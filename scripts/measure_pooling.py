#!/usr/bin/env python3
"""Measure send throughput of the core seam and the proxy's upstream sender (BUG-0549).

A loopback HTTP/1.1 keep-alive server, started here, answers every request with a
2-byte body. Both senders are measured against it, in plain HTTP and over TLS (a leaf of
a throw-away `LocalCA`, verified against that CA), each ``--repeat`` times:

- ``HttpClient(...).send`` (the core seam, its default transport);
- ``SocketSender(...)(host, port, use_tls, raw)`` (the proxy's upstream sender);

first ``--sends`` sequential sends (``--tls-sends`` over TLS), then the same number split
over ``--threads`` threads. Reported per path: sends per second (median and each run)
and the connections the server accepted per run. Then the phases of one fresh TLS send
(context with the test CA, context with the system CA store, connect, handshake, first
exchange) against an exchange on a kept connection.

To compare a commit with another, extract that commit's package and point ``--tree`` at
it::

    mkdir /tmp/base && git archive <ref> fuzzlab | tar -x -C /tmp/base
    python scripts/measure_pooling.py --tree /tmp/base

Prints one JSON document; nothing is asserted (the numbers are the result). Loopback
only: it never contacts a target.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

ANSWER = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
RAW = b"GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"


class _Server:
    """Keep-alive HTTP/1.1 on 127.0.0.1, a thread per connection; counts connections."""

    def __init__(self, tls: ssl.SSLContext | None):
        self.tls = tls
        self.connections = 0
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(256)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn) -> None:
        try:
            if self.tls is not None:
                conn = self.tls.wrap_socket(conn, server_side=True)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    data = conn.recv(65536)
                    if not data:
                        return
                    buf += data
                _head, buf = buf.split(b"\r\n\r\n", 1)
                conn.sendall(ANSWER)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._srv.close()


def _rate(fn, sends: int, threads: int) -> tuple[float, float]:
    start = time.perf_counter()
    for _ in range(sends):
        fn()
    seq = sends / (time.perf_counter() - start)
    per = sends // threads

    def work() -> None:
        for _ in range(per):
            fn()
    pool = [threading.Thread(target=work) for _ in range(threads)]
    start = time.perf_counter()
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return seq, per * threads / (time.perf_counter() - start)


def _one_round(tls: ssl.SSLContext | None, sends: int, threads: int) -> dict:
    from fuzzlab.core.budget import RequestBudget
    from fuzzlab.core.http import HttpClient, Request
    from fuzzlab.proxy.socketsender import SocketSender
    out = {}
    server = _Server(tls)
    scheme = "https" if tls else "http"
    client = HttpClient(RequestBudget(10 ** 9), ["127.0.0.1"], timeout=10)

    def seam() -> None:
        r = client.send(Request("GET", f"{scheme}://127.0.0.1:{server.port}/x"))
        assert r.status == 200 and r.body == b"ok"
    before = server.connections
    seq, conc = _rate(seam, sends, threads)
    out["seam"] = (seq, conc, server.connections - before)
    getattr(client, "close", lambda: None)()

    sender = SocketSender(timeout=10)

    def upstream() -> None:
        assert sender("127.0.0.1", server.port, tls is not None, RAW) == ANSWER
    before = server.connections
    seq, conc = _rate(upstream, sends, threads)
    out["socketsender"] = (seq, conc, server.connections - before)
    getattr(sender, "close", lambda: None)()
    server.close()
    return out


def _tls_phases(ca_file: str, server_ctx: ssl.SSLContext, real_default) -> dict:
    server = _Server(server_ctx)
    phases: dict[str, list[float]] = {"context_test_ca": [], "connect": [],
                                      "handshake": [], "first_exchange": []}

    def exchange(s) -> None:
        s.sendall(RAW)
        got = b""
        while len(got) < len(ANSWER):
            got += s.recv(65536)
    for _ in range(40):
        t0 = time.perf_counter()
        ctx = real_default(cafile=ca_file)
        t1 = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        t2 = time.perf_counter()
        s = ctx.wrap_socket(s, server_hostname="127.0.0.1")
        t3 = time.perf_counter()
        exchange(s)
        t4 = time.perf_counter()
        s.close()
        for key, v in zip(phases, (t1 - t0, t2 - t1, t3 - t2, t4 - t3)):
            phases[key].append(v * 1000)
    s = real_default(cafile=ca_file).wrap_socket(
        socket.create_connection(("127.0.0.1", server.port), timeout=10),
        server_hostname="127.0.0.1")
    kept = []
    for _ in range(200):
        t0 = time.perf_counter()
        exchange(s)
        kept.append((time.perf_counter() - t0) * 1000)
    s.close()
    system = []
    for _ in range(20):
        t0 = time.perf_counter()
        real_default()
        system.append((time.perf_counter() - t0) * 1000)
    server.close()
    out = {k: round(statistics.median(v), 2) for k, v in phases.items()}
    out["context_system_ca"] = round(statistics.median(system), 2)
    out["kept_exchange"] = round(statistics.median(kept), 2)
    return {"ms_median": out}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--tree", default=str(Path(__file__).resolve().parent.parent),
                   help="the directory whose fuzzlab package is measured")
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--sends", type=int, default=1000)
    p.add_argument("--tls-sends", type=int, default=296)
    p.add_argument("--threads", type=int, default=8)
    args = p.parse_args(argv)
    sys.path.insert(0, args.tree)
    from fuzzlab.proxy.ca import LocalCA

    result: dict = {"tree": args.tree, "load_average": os.getloadavg()}
    with tempfile.TemporaryDirectory() as d:
        ca = LocalCA(os.path.join(d, "ca"))
        cert, key = ca.leaf_cert_files("127.0.0.1")
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert), str(key))
        ca_file = str(ca.ca_cert_path)
        os.environ["REQUESTS_CA_BUNDLE"] = ca_file          # the seam verifies against it
        real_default = ssl.create_default_context
        ssl.create_default_context = lambda *a, **k: real_default(cafile=ca_file)
        try:
            rounds = {"plain": [], "tls": []}
            for _ in range(args.repeat):
                rounds["plain"].append(_one_round(None, args.sends, args.threads))
                rounds["tls"].append(_one_round(server_ctx, args.tls_sends, args.threads))
            for kind, runs in rounds.items():
                sends = args.sends if kind == "plain" else args.tls_sends
                for who in ("seam", "socketsender"):
                    seq = [r[who][0] for r in runs]
                    conc = [r[who][1] for r in runs]
                    result[f"{kind}/{who}"] = {
                        "sends_per_run": sends + sends // args.threads * args.threads,
                        "seq_per_s_median": round(statistics.median(seq)),
                        f"threads{args.threads}_per_s_median": round(statistics.median(conc)),
                        "seq_per_s_runs": [round(x) for x in seq],
                        f"threads{args.threads}_per_s_runs": [round(x) for x in conc],
                        "connections_per_run": [r[who][2] for r in runs]}
            result["tls_phases"] = _tls_phases(ca_file, server_ctx, real_default)
        finally:
            ssl.create_default_context = real_default
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
