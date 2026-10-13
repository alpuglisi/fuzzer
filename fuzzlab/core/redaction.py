"""Which field names hold secrets — one predicate for logs and persisted traffic
(BUG-0084, PA-0003, PA-0085).

Names are matched by **token**, not by substring. A name is split on ``_ - . [ ]``,
whitespace, camelCase and letter/digit boundaries, then lower-cased, and each token is
compared with the set. Substring matching redacted ``author`` (``auth``), ``sidebar``
(``sid``) and ``tokenizer``. A name that merely contains a sensitive word inside a
longer token is not redacted, so benign fields stay readable. A sensitive token anywhere
in the name redacts it, so ``session_count`` is redacted: harmless, and stated.
"""

from __future__ import annotations

import re

#: Whole tokens that mark a secret on their own.
SENSITIVE_TOKENS = frozenset({
    "password", "passwd", "pwd", "pw", "pass", "passcode", "passphrase", "secret",
    "token", "tokens", "jwt", "cookie", "cookies", "credential", "credentials",
    "session", "sessid", "sessionid", "sid", "apikey", "auth", "authorization",
    "otp", "csrf", "xsrf", "csrftoken", "xsrftoken", "accesstoken", "refreshtoken",
    "authtoken", "bearer", "signature", "sig", "pin",
})
#: ``key`` is a secret with one of these beside it (``api_key``, ``privateKey``), or alone.
_KEY_QUALIFIERS = frozenset({"api", "private", "secret", "access", "signing", "client",
                             "auth", "encryption", "master"})

_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
                    r"|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")


def name_tokens(name: str) -> list[str]:
    """``name`` split into lower-case tokens (see the module docstring)."""
    return [t.lower() for t in _SPLIT.split(name or "") if t]


def is_sensitive_name(name: str) -> bool:
    """True when the field or parameter ``name`` holds a secret."""
    tokens = name_tokens(name)
    if not tokens:
        return False
    if any(t in SENSITIVE_TOKENS or t.endswith(("sessid", "sessionid")) for t in tokens):
        return True                               # incl. PHPSESSID / JSESSIONID
    if "key" in tokens:
        return len(tokens) == 1 or any(t in _KEY_QUALIFIERS for t in tokens)
    return tokens == ["code"]                     # an OAuth code, only as the whole name
