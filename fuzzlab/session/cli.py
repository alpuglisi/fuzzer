"""`fuzzlab session` — provision per-host credentials and print a session header.

Subcommands:
  set-credential --host H --identity I [--username U]   store creds (password prompted)
  print --host H --identity I --base-url URL            detect-login and print a header

Credentials are saved per host in the credential store (D12); nothing is sent to a
target except by `print`, which performs the login for that one host.

A session is sent only to its own origins (FR-SESS-20): two apps on one host (two
ports) share the host's credential entry under one identity name, so give each app its
own identity name (`--identity shop-user`, `--identity bwapp-user`).
"""

from __future__ import annotations

import argparse
import getpass

from fuzzlab.core.config import load_config
from fuzzlab.core.credentials import CredentialStore
from fuzzlab.session.manager import SessionAuthError, SessionManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzlab session")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("set-credential", help="save credentials for a host+identity")
    sc.add_argument("--host", required=True)
    sc.add_argument("--identity", required=True,
                    help="identity name; credentials are keyed per host, so use a "
                         "distinct identity name per app when two apps share a host "
                         "(another port is another app, FR-SESS-20)")
    sc.add_argument("--username", help="login username (prompted if omitted)")

    pr = sub.add_parser("print", help="log in and print a ready-to-use session header")
    pr.add_argument("--host", required=True)
    pr.add_argument("--identity", required=True,
                    help="identity name (a distinct one per app on a shared host)")
    pr.add_argument("--base-url", required=True,
                    help="the app's URL; the session is printed only for one of its own "
                         "origins (FR-SESS-20)")
    from fuzzlab.session.manager import AUTH_ORIGIN_HELP
    pr.add_argument("--auth-origin", action="append", default=[], metavar="ORIGIN",
                    help=AUTH_ORIGIN_HELP)
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config()
    store = CredentialStore.open(cfg)

    if args.cmd == "set-credential":
        username = args.username or input("username: ")
        password = getpass.getpass("password: ")
        store.set(args.host, args.identity, username, password)
        print(f"stored credentials for {args.identity}@{args.host}")
        return 0

    if args.cmd == "print":
        scope = list(cfg.get("scope_hosts", []))
        if args.host not in scope:
            scope.append(args.host)
        from fuzzlab.session.manager import parse_auth_origins
        try:
            auth_origins = parse_auth_origins(args.auth_origin, scope)
        except ValueError as exc:
            print(f"usage error: {exc}")
            return 2
        mgr = SessionManager(store, scope_hosts=scope, auth_origins=auth_origins)
        try:
            # every header the session sends: a browser login has a bearer AND the
            # cookie its app set (BUG-0132), and a server-rendered page reads the cookie
            headers = mgr.session_headers(args.host, args.identity, args.base_url,
                                          operator=True)
        except SessionAuthError as exc:
            print(f"login failed: {exc}")
            return 1
        for name, value in headers.items():
            print(f"{name}: {value}")
        if not headers:
            print("(no session header detected)")
        return 0

    return 2
