"""`fuzzlab proxy` — run the intercepting proxy against the lab (Phase 6, on-host).

Forwards through the real upstream `SocketSender` (byte-exact), records flows to the
store when `--store` is given, and — with a local CA — terminates CONNECT/TLS so HTTPS
targets can be intercepted. Lab-only: requires `--authorized` to run (it sends traffic
to upstreams). `--export-ca` just writes/prints the CA cert to import into your browser
and sends nothing, so it needs no `--authorized`.

Recording stays opt-in: ``--store PATH`` records there (as before), and ``--record`` records
into the resolved default store (`core.storepath`: ``$FUZZLAB_STORE``,
``$FUZZLAB_STORE_PATH``, else ``./fuzzlab.db`` -- the store the web UI shows; FR-PROXY-400).

Ctrl-C and SIGTERM (``kill``, the web UI's Stop through `procutil`'s supervisor, a service
manager) both stop it the same way: the listener closes, then the flow history still
queued on its writer thread is written and the run's end recorded (FR-PROXY-404). Only a
hard kill (SIGKILL, a crash) loses what is still queued.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal

from fuzzlab.core import storepath
from fuzzlab.proxy.ca import LocalCA
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import AsyncProxyServer, InboundLimits, ProxyEngine
from fuzzlab.proxy.socketsender import SocketSender


def _build_scope(hosts: list[str] | None) -> Scope:
    scope = Scope()
    for h in (hosts or ["127.0.0.1"]):
        scope.include(h)
    return scope


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fuzzlab proxy")
    p.add_argument("--host", default="127.0.0.1", help="Proxy listen host (loopback)")
    p.add_argument("--port", type=int, default=8888, help="Proxy listen port")
    p.add_argument("--scope", action="append",
                   help="Host to intercept (repeatable; default 127.0.0.1). "
                        "Out-of-scope hosts are forwarded transparently, unrecorded.")
    p.add_argument("--ca-dir", default=os.path.expanduser("~/.fuzzlab/ca"),
                   help="Local CA directory (holds fuzzlab-ca.crt / .key)")
    p.add_argument("--store", default=None, help="Store (SQLite) to record flow history")
    p.add_argument("--record", action="store_true",
                   help=f"Record flow history into the default store "
                        f"({storepath.DEFAULT_RULE}); --store PATH records there "
                        f"instead. Off by default: nothing is recorded unless asked.")
    p.add_argument("--identity", default=None, help="Tag recorded flows with this identity")
    p.add_argument("--max-response-bytes", type=int, default=None,
                   help="Cap on one upstream response body (default 64 MiB; FR-PROXY-12)")
    p.add_argument("--response-deadline", type=float, default=None,
                   help="Overall seconds for one upstream response (default 4x the idle "
                        "timeout; long-lived streams are cut off by design)")
    bounds = InboundLimits()
    p.add_argument("--max-connections", type=int, default=None,
                   help=f"Client connections at once; more are answered 503 (default "
                        f"{bounds.max_connections}; FR-PROXY-403)")
    p.add_argument("--max-request-bytes", type=int, default=None,
                   help=f"Cap on one request body as it arrives; more is answered 413 "
                        f"(default {bounds.max_body_bytes})")
    p.add_argument("--max-header-bytes", type=int, default=None,
                   help=f"Cap on one request head; more is answered 431 (default "
                        f"{bounds.max_header_bytes})")
    p.add_argument("--request-deadline", type=float, default=None,
                   help=f"Seconds for one whole request to arrive; later is answered 408 "
                        f"(default {bounds.request_deadline:g})")
    p.add_argument("--raw-framing", action="store_true",
                   help="Raw mode (D4, malformed-traffic study): a request with "
                        "conflicting Content-Length values is framed by the first and "
                        "forwarded byte-exact instead of answered 400")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="Do not verify upstream TLS certs (self-signed lab origins)")
    p.add_argument("--export-ca", action="store_true",
                   help="Ensure the local CA exists, print its cert path, and exit")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable CONNECT/TLS interception (plain-HTTP proxy only)")
    p.add_argument("--authorized", action="store_true",
                   help="Required to run the proxy (it forwards traffic to upstreams)")
    from fuzzlab.cli_dryrun import add_dry_run_flag
    add_dry_run_flag(p)
    return p


def main(argv: list[str]) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.dry_run:
        recording = _recording(p, args)      # a bad --store fails before any plan prints
        from fuzzlab.cli_dryrun import report
        report("proxy", args)
        if recording is not None:
            print(f"  {storepath.describe(recording)}")
        return 0

    ca = LocalCA(args.ca_dir)

    if args.export_ca:
        try:
            ca.ensure_ca()
        except Exception as exc:  # noqa: BLE001 - cryptography missing/broken
            p.error(f"could not create the local CA (needs a working 'cryptography'): {exc}")
        print(f"CA certificate: {ca.ca_cert_path}")
        print("Import this file into your browser/OS trust store to intercept HTTPS.")
        print(f"The CA private key stays on this host (0600): {ca.ca_key_path}")
        return 0

    recording = _recording(p, args)          # after --export-ca, which records nothing
    if not args.authorized:
        p.error("refusing to run the proxy without --authorized (lab-only)")
    from fuzzlab.core.net import require_loopback
    try:
        require_loopback(args.host, "the proxy")      # D11 (BUG-0080)
    except ValueError as exc:
        p.error(str(exc))

    if recording is not None:
        try:
            storepath.check_writable(recording)
        except storepath.StorePathError as exc:
            p.error(str(exc))

    try:
        limits = inbound_limits(args)
    except ValueError as exc:
        p.error(str(exc))

    from fuzzlab.proxy.socketsender import MAX_BODY_BYTES
    sender = SocketSender(verify_tls=not args.no_verify_tls,
                          max_body=args.max_response_bytes or MAX_BODY_BYTES,
                          deadline=args.response_deadline)
    scope = _build_scope(args.scope)

    store = None
    history = None
    if recording is not None:
        from fuzzlab.core.store import Store
        from fuzzlab.proxy.history import HistoryWriter
        store = Store(recording.path)
        run_id = store.start_run("proxy", args.host)
        # batch_size=1: each flow is written as soon as the writer thread takes it (WAL),
        # so a reader sees flows while the proxy runs. A requested stop (Ctrl-C,
        # SIGTERM) drains what is queued in `close` below; a hard kill loses it.
        history = HistoryWriter(store, run_id, batch_size=1)

    engine = ProxyEngine(scope=scope, sender=sender, history=history,
                         identity=args.identity)
    server = AsyncProxyServer(engine, host=args.host, port=args.port,
                              ca=None if args.no_tls else ca, limits=limits,
                              raw_framing=args.raw_framing)

    async def _serve() -> None:
        stop = asyncio.Event()
        _stop_on_sigterm(stop)
        await server.start()
        print(f"proxy listening on {args.host}:{server.port}  "
              f"(scope: {sorted(scope_hosts(scope))})")
        print(f"  configure your browser to use HTTP proxy {args.host}:{server.port}")
        if not args.no_tls:
            print(f"  HTTPS interception on: import {ca.ca_cert_path} "
                  f"(run `fuzzlab proxy --export-ca` first if it doesn't exist)")
        if recording is not None:
            print(f"  recording flows to {recording.path} ({recording.source})")
        print("  Ctrl-C to stop.")
        try:
            await stop.wait()                     # run until interrupted or terminated
        finally:
            await server.stop()
            refused = {k: v for k, v in server.counts.items() if v}
            if refused:
                print(f"  refused by the listener's bounds: {refused}")

    ended = "complete"                    # Ctrl-C or SIGTERM: a requested stop
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass
    except BaseException as exc:
        ended = f"aborted: {type(exc).__name__}"
        raise
    finally:
        if history is not None:
            history.close(run_end=ended)  # flush, the run's end, the trace counters
        if store is not None:
            store.close()
    return 0


def inbound_limits(args) -> InboundLimits:
    """The listener's bounds from the flags; a flag left out keeps its default
    (`InboundLimits`). Raises ``ValueError`` for a bound that is not positive."""
    given = {"max_connections": args.max_connections,
             "max_body_bytes": args.max_request_bytes,
             "max_header_bytes": args.max_header_bytes,
             "request_deadline": args.request_deadline}
    return InboundLimits(**{k: v for k, v in given.items() if v is not None})


def _stop_on_sigterm(stop: asyncio.Event) -> None:
    """Make SIGTERM end the running loop as Ctrl-C does, so the server stops and `main`
    closes the history writer, which writes every flow still queued (BUG-0550). Its
    default action would end the process at once: no `finally`, no ``atexit``, the
    queued flows neither written nor counted. Only possible on the main thread of a
    platform with signals; elsewhere SIGTERM keeps its default."""
    try:
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    except (NotImplementedError, RuntimeError, ValueError):
        pass


def _recording(p, args):
    """The store flow history goes to, or None when nothing is recorded (opt-in:
    ``--store PATH`` or ``--record``; FR-PROXY-400)."""
    if args.store is None and not args.record:
        return None
    try:
        return storepath.resolve(args.store)
    except storepath.StorePathError as exc:
        p.error(str(exc))


def scope_hosts(scope: Scope) -> set[str]:
    """Best-effort list of included hosts, for the startup banner."""
    return {r.host for r in getattr(scope, "rules", []) if not r.exclude}


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
