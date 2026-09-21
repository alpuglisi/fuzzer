"""`fuzzlab proxy` — run the intercepting proxy against the lab (Phase 6, on-host).

Forwards through the real upstream `SocketSender` (byte-exact), records flows to the
store when `--store` is given, and — with a local CA — terminates CONNECT/TLS so HTTPS
targets can be intercepted. Lab-only: requires `--authorized` to run (it sends traffic
to upstreams). `--export-ca` just writes/prints the CA cert to import into your browser
and sends nothing, so it needs no `--authorized`.
"""

from __future__ import annotations

import argparse
import asyncio
import os

from fuzzlab.proxy.ca import LocalCA
from fuzzlab.proxy.scope import Scope
from fuzzlab.proxy.server import AsyncProxyServer, ProxyEngine
from fuzzlab.proxy.socketsender import SocketSender


def _build_scope(hosts: list[str] | None) -> Scope:
    scope = Scope()
    for h in (hosts or ["127.0.0.1"]):
        scope.include(h)
    return scope


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="fuzzlab proxy")
    p.add_argument("--host", default="127.0.0.1", help="Proxy listen host (loopback)")
    p.add_argument("--port", type=int, default=8888, help="Proxy listen port")
    p.add_argument("--scope", action="append",
                   help="Host to intercept (repeatable; default 127.0.0.1). "
                        "Out-of-scope hosts are forwarded transparently, unrecorded.")
    p.add_argument("--ca-dir", default=os.path.expanduser("~/.fuzzlab/ca"),
                   help="Local CA directory (holds fuzzlab-ca.crt / .key)")
    p.add_argument("--store", default=None, help="Store (SQLite) to record flow history")
    p.add_argument("--identity", default=None, help="Tag recorded flows with this identity")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="Do not verify upstream TLS certs (self-signed lab origins)")
    p.add_argument("--export-ca", action="store_true",
                   help="Ensure the local CA exists, print its cert path, and exit")
    p.add_argument("--no-tls", action="store_true",
                   help="Disable CONNECT/TLS interception (plain-HTTP proxy only)")
    p.add_argument("--authorized", action="store_true",
                   help="Required to run the proxy (it forwards traffic to upstreams)")
    args = p.parse_args(argv)

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

    if not args.authorized:
        p.error("refusing to run the proxy without --authorized (lab-only)")

    sender = SocketSender(verify_tls=not args.no_verify_tls)
    scope = _build_scope(args.scope)

    store = None
    history = None
    if args.store:
        from fuzzlab.core.store import Store
        from fuzzlab.proxy.history import HistoryWriter
        store = Store(args.store)
        run_id = store.start_run("proxy", args.host)
        history = HistoryWriter(store, run_id)

    engine = ProxyEngine(scope=scope, sender=sender, history=history,
                         identity=args.identity)
    server = AsyncProxyServer(engine, host=args.host, port=args.port,
                              ca=None if args.no_tls else ca)

    async def _serve() -> None:
        await server.start()
        print(f"proxy listening on {args.host}:{server.port}  "
              f"(scope: {sorted(scope_hosts(scope))})")
        print(f"  configure your browser to use HTTP proxy {args.host}:{server.port}")
        if not args.no_tls:
            print(f"  HTTPS interception on: import {ca.ca_cert_path} "
                  f"(run `fuzzlab proxy --export-ca` first if it doesn't exist)")
        if args.store:
            print(f"  recording flows to {args.store}")
        print("  Ctrl-C to stop.")
        try:
            await asyncio.Event().wait()          # run until interrupted
        finally:
            await server.stop()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass
    finally:
        if history is not None:
            history.flush()
        if store is not None:
            store.close()
    return 0


def scope_hosts(scope: Scope) -> set[str]:
    """Best-effort list of included hosts, for the startup banner."""
    return {r.host for r in getattr(scope, "rules", []) if not r.exclude}


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
