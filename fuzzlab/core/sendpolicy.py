"""Which send rules are enforced in this process: the one switch for three lab rules (D71).

Three rules keep the tool away from parts of a lab:
- **destructive** — a URL, route, button, option or entry with a destructive or
  session-ending word (``core.urls.destructive_reason`` / ``text_destructive_reason``) is
  never visited, submitted or fuzzed;
- **transactions** — a route, label or request that names a transaction
  (``core.urls.transaction_reason``) is never submitted or fuzzed;
- **credential changes** — a form or body that changes a credential or manages an
  account (``store_adapter.credential_change_rule``) is never submitted or fuzzed.

All three are enforced by default. The owner's decision D71 keeps them and adds a
lab-only flag per rule to turn it off for one run (``--allow-destructive-routes``,
``--allow-transactions``, ``--allow-credential-changes``). Turning one off costs lab
state: a run may log itself out, delete or change lab data, or change the lab user's
password. Reset the lab between such runs.

The rule functions stay pure classifiers: they always answer "is this destructive?".
This module decides whether a **refusal** uses the answer. Every refusal site passes
its reason through `destructive`, `transaction` or `credential_change`. The login flow
(``session/browserlogin.py``, ``SessionManager._navigation_ok``) is not a refusal site:
it uses the rules to tell a login form from a password-change form and to keep itself
logged in, and it calls them directly, so the flags never change how a login is found.

The state lives in one environment variable, ``FUZZLAB_SEND_POLICY_OFF`` (a comma list
of rule names), so a browser worker or any subprocess sees the same policy. A command
sets it only from its own flags (`apply`); a stray value in the shell is cleared, never
inherited.
"""

from __future__ import annotations

import argparse
import logging
import os

ENV = "FUZZLAB_SEND_POLICY_OFF"

DESTRUCTIVE = "destructive"
TRANSACTIONS = "transactions"
CREDENTIAL_CHANGES = "credential-changes"
RULES = (DESTRUCTIVE, TRANSACTIONS, CREDENTIAL_CHANGES)

#: (flag, rule, help) for each rule a command may turn off.
FLAGS = (
    ("--allow-destructive-routes", DESTRUCTIVE,
     "lab-only: visit, submit and fuzz URLs, routes, buttons and entries with "
     "destructive words (logout, reset, delete, erase, ...); the run may log itself out "
     "or delete lab data"),
    ("--allow-transactions", TRANSACTIONS,
     "lab-only: submit and fuzz forms and requests that name a transaction "
     "(checkout, payment, order, transfer, ...)"),
    ("--allow-credential-changes", CREDENTIAL_CHANGES,
     "lab-only: submit and fuzz forms and bodies that change a credential or manage an "
     "account; the run may change the lab user's password"),
)


def _dest(flag: str) -> str:
    return flag.lstrip("-").replace("-", "_")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the three off-switches to a command's parser."""
    for flag, _rule, text in FLAGS:
        parser.add_argument(flag, action="store_true", help=text)


def disabled_by(args: argparse.Namespace) -> tuple[str, ...]:
    return tuple(rule for flag, rule, _t in FLAGS if getattr(args, _dest(flag), False))


def apply(args: argparse.Namespace) -> tuple[str, ...]:
    """Set this process's policy from a command's flags, and return the rules turned off.
    Any inherited value is replaced: only the command's own flags count."""
    off = disabled_by(args)
    set_disabled(off)
    if off:
        logging.warning("send rules turned off for this run (D71, lab-only): %s",
                        ", ".join(off))
    return off


def set_disabled(rules) -> None:
    rules = tuple(rules)
    unknown = [r for r in rules if r not in RULES]
    if unknown:
        raise ValueError(f"unknown send rule(s): {', '.join(unknown)}")
    if rules:
        os.environ[ENV] = ",".join(rules)
    else:
        os.environ.pop(ENV, None)


def disabled() -> frozenset[str]:
    raw = os.environ.get(ENV, "")
    return frozenset(r.strip() for r in raw.split(",") if r.strip() in RULES)


def enforced(rule: str) -> bool:
    return rule not in disabled()


def destructive(reason: str | None) -> str | None:
    """``reason`` if the destructive rule is enforced, else None."""
    return reason if enforced(DESTRUCTIVE) else None


def transaction(reason: str | None) -> str | None:
    """``reason`` if the transaction rule is enforced, else None."""
    return reason if enforced(TRANSACTIONS) else None


def credential_change(reason: str | None) -> str | None:
    """``reason`` if the credential-change rule is enforced, else None."""
    return reason if enforced(CREDENTIAL_CHANGES) else None
