"""Target fingerprinting: DBMS / framework / WAF / server (Phase 2 T2.5).

Fingerprint-before-fuzz lets the scheduler and oracle scope payloads to the target
(e.g. MySQL SLEEP vs Postgres pg_sleep) instead of trying everything. Pure and
accumulative: build a fingerprint over one or more responses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# framework hints by cookie name
_COOKIE_FRAMEWORK = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "connect.sid": "Node/Express",
    "_rails_session": "Rails",
    "sessionid": "Django",           # with csrftoken; weak on its own
}

# WAF hints by response header name (lowercased)
_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "x-iinfo": "Imperva/Incapsula",
}

# DBMS hints from error text (fingerprinting, distinct from the oracle's confirm set)
_DBMS_ERRORS = [
    (re.compile(r"you have an error in your sql syntax|warning:\s*mysqli?_", re.I), "MySQL"),
    (re.compile(r"mariadb", re.I), "MariaDB"),
    (re.compile(r"postgresql|pg_query|syntax error at or near", re.I), "PostgreSQL"),
    (re.compile(r"sqlite_error|sqlite3?::|unrecognized token", re.I), "SQLite"),
    (re.compile(r"microsoft sql server|unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}|quoted string not properly terminated", re.I), "Oracle"),
]


@dataclass
class Fingerprint:
    server: str | None = None
    framework: str | None = None
    dbms: str | None = None
    waf: str | None = None

    def merge(self, other: "Fingerprint") -> "Fingerprint":
        """Fill any unknown field from ``other`` (first observation wins)."""
        return Fingerprint(
            server=self.server or other.server,
            framework=self.framework or other.framework,
            dbms=self.dbms or other.dbms,
            waf=self.waf or other.waf,
        )

    def as_dict(self) -> dict[str, str | None]:
        return {"server": self.server, "framework": self.framework,
                "dbms": self.dbms, "waf": self.waf}


def _cookie_names(headers_low: dict[str, str], cookies: dict[str, str] | None) -> set[str]:
    names = {c.lower() for c in (cookies or {})}
    setc = headers_low.get("set-cookie", "")
    for part in setc.split(","):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            names.add(name)
    return names


def fingerprint(headers: dict[str, str], body: str = "",
                cookies: dict[str, str] | None = None) -> Fingerprint:
    low = {k.lower(): v for k, v in (headers or {}).items()}
    fp = Fingerprint()

    fp.server = low.get("server")

    powered = low.get("x-powered-by", "")
    if powered:
        fp.framework = powered
    else:
        for name in _cookie_names(low, cookies):
            if name in _COOKIE_FRAMEWORK:
                fp.framework = _COOKIE_FRAMEWORK[name]
                break

    for rx, dbms in _DBMS_ERRORS:
        if rx.search(body or ""):
            fp.dbms = dbms
            break

    for header, waf in _WAF_HEADERS.items():
        if header in low:
            fp.waf = waf
            break
    if fp.waf is None and "cloudflare" in (fp.server or "").lower():
        fp.waf = "Cloudflare"

    return fp
