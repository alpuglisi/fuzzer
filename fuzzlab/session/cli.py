"""`fuzzlab session` — provision per-host credentials and print a session header.

Subcommands:
  set-credential --host H --identity I [--username U]   store creds (password prompted)
  print --host H --identity I --base-url URL            detect-login and print a header

Credentials are saved per host in the credential store (D12); nothing is sent to a
target except by `print`, which performs the login for that one host.
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
    sc.add_argument("--identity", required=True)
    sc.add_argument("--username", help="login username (prompted if omitted)")

    pr = sub.add_parser("print", help="log in and print a ready-to-use session header")
    pr.add_argument("--host", required=True)
    pr.add_argument("--identity", required=True)
    pr.add_argument("--base-url", required=True)
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
        mgr = SessionManager(store, scope_hosts=scope)
        try:
            header = mgr.session_header(args.host, args.identity, args.base_url)
        except SessionAuthError as exc:
            print(f"login failed: {exc}")
            return 1
        print(header or "(no session header detected)")
        return 0

    return 2
