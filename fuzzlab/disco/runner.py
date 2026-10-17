"""The contract runner (Phase 3): execute every test case of a contract and write its
``results`` ledger.

For each case, in contract order: its setup steps run first, in order, each one's
``extract`` JSONPaths filling ``{{variables}}`` for the steps after it and the case's own
request; then the request is sent; then the oracle judges the answer. A verdict is one
of ``pass`` / ``finding`` / ``error`` / ``skipped``, with what matched and why.

**Every send is gated at the send** (PA-0083(1)), whoever wrote the contract:
- the URL must be in the contract's scope (`core.urls.in_origin_scope`, SP-06), checked on
  the final URL, never on a template;
- the destructive-URL and method gate (`core.urls.check_send_url`, SP-09). A case the
  contract marks ``safety.destructive`` is ``skipped`` unless the operator passed
  ``allow_destructive``, which is then the explicit allowance for that case's own URL;
- redirects are never followed (PA-0046): the oracle judges what the server said;
- each response is read up to ``limits.max_body_bytes`` and within ``limits.timeout_ms``
  (PA-0102(1)); sends are spaced to ``limits.rps``.

**A send that gets no complete response is no verdict** (PA-0153): classified by the
one owner (`tools.probesender._unobserved`, SP-34) it is an ``error`` for that case and
the run goes on; a timeout is an ``error`` too, or a ``finding`` when the oracle names a
latency bound; a target that cannot be reached at all (refused, DNS, TLS) stops the
run loudly (`TargetUnreachable`) with the results so far written.

**Credentials** come from the auth profile's ``ref`` (`keyring:<identity>` through
`core.credentials`, ``env:<NAME>``, or a Playwright storage-state file), are sent only to
the base URL's own origin (PA-0134: an artefact with a secret carries the origin it
belongs to), and are never written: evidence goes through `core.redaction`.

**The oracle.** A case's ``findings_if`` rules, plus the built-in rules every case gets:
a 5xx, and a response matching `LEAK_PATTERNS` (a stack trace, a database error) that the
same endpoint's baseline did not already show (the PA-0117 noise guard: the first
non-error answer the endpoint gave in this run is its baseline). An answer outside the
case's ``expect_status_class`` is matched as ``expect_status_class``.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlencode, urljoin, urlsplit

from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
from fuzzlab.core.redaction import redact_body, redact_url
from fuzzlab.core.urls import (DestructiveUrlRefused, check_send_url, in_origin_scope,
                               origin_scope, url_key)
from fuzzlab.disco.capture import redact_headers
from fuzzlab.disco.contract import VAR, Contract

#: Stack traces and database errors across stacks (specific enough that a benign page
#: rarely shows one; the baseline check removes those that do).
LEAK_PATTERNS = (
    r"Traceback \(most recent call last\)", r"SQLSTATE\[", r"\bORA-\d{5}\b",
    r"\bat [a-z][\w$]*(\.[\w$]+)+\([\w$]+\.java:\d+\)", r"PHP (Fatal|Parse) error",
    r"\bpsycopg2?\.errors\.", r"\bSequelize\w*Error\b", r"\bActiveRecord::\w+",
    r"System\.Data\.SqlClient", r"\bMySqlException\b", r"You have an error in your SQL syntax",
    r"\bsqlite3\.OperationalError\b", r"\bunterminated quoted string\b",
    r"\bgoroutine \d+ \[running\]", r"\bat Object\.<anonymous> \(", r"\bnode_modules/",
    r"\bNullPointerException\b", r"Whitelabel Error Page", r"\bwerkzeug\.exceptions\b",
    r"\bDjango Version:", r"\bpanic: ",
)
_LEAK = [re.compile(p) for p in LEAK_PATTERNS]
#: How much of a body the patterns are matched on.
MATCH_BYTES = 256 * 1024
_ASSERT = re.compile(r"^\s*(\$[^\s<>=!]*)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s*$")


class TargetUnreachable(RuntimeError):
    """The target refused the connection, or its name, TLS or a proxy failed."""


# --- JSONPath (the subset extraction and assertions use) -----------------------------

_JP_TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_\-]*)|\[(\d+)\]|\[\"((?:[^\"\\]|\\.)*)\"\]"
                       r"|\['([^']*)'\]")


def jsonpath(doc, path: str):
    """The value at ``path`` (``$``, ``.key``, ``["key"]``, ``[n]``), or KeyError."""
    if not path.startswith("$"):
        raise KeyError(path)
    rest, cur = path[1:], doc
    while rest:
        m = _JP_TOKEN.match(rest)
        if not m:
            raise KeyError(path)
        if m.group(2) is not None:
            if not isinstance(cur, list) or int(m.group(2)) >= len(cur):
                raise KeyError(path)
            cur = cur[int(m.group(2))]
        else:
            key = m.group(1) or (json.loads(f'"{m.group(3)}"') if m.group(3) is not None
                                 else m.group(4))
            if not isinstance(cur, dict) or key not in cur:
                raise KeyError(path)
            cur = cur[key]
        rest = rest[m.end():]
    return cur


def assertion_holds(doc, text: str) -> bool | None:
    """``"$.total >= 0"`` against ``doc``: True / False, None when it cannot be judged."""
    m = _ASSERT.match(text or "")
    if not m:
        return None
    try:
        left = jsonpath(doc, m.group(1))
        right = json.loads(m.group(3))
    except (KeyError, ValueError):
        return None
    op = m.group(2)
    try:
        return {"==": left == right, "!=": left != right}[op] if op in ("==", "!=") else \
            {">=": left >= right, "<=": left <= right, ">": left > right,
             "<": left < right}[op]
    except TypeError:
        return False


def fill(value, variables: dict):
    """``value`` with every ``{{var}}`` replaced (a whole-string reference keeps the
    variable's JSON type)."""
    if isinstance(value, str):
        whole = VAR.fullmatch(value.strip())
        if whole and whole.group(1) in variables:
            return variables[whole.group(1)]
        return VAR.sub(lambda m: str(variables.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: fill(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, variables) for v in value]
    return value


# --- sending -----------------------------------------------------------------------

@dataclass
class Exchange:
    url: str
    method: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    latency_ms: int | None = None
    error: str | None = None
    timed_out: bool = False
    truncated: bool = False

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return None


@dataclass
class Prepared:
    method: str
    url: str
    headers: dict
    body: bytes | None


class Runner:
    """``Runner(contract, authorized=True).run()`` -> the results list. ``session`` is
    a ``requests.Session``-like object (tests pass a fake); ``credentials`` resolves a
    ``keyring:`` ref (default `core.credentials.CredentialStore`)."""

    def __init__(self, contract: Contract, *, authorized: bool, allow_destructive: bool = False,
                 allow_reset_hook: bool = False, evidence_dir: Path | None = None,
                 session=None, credentials=None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if not authorized:
            raise PermissionError("the contract runner sends traffic: pass --authorized "
                                  "(lab-only, D11)")
        self.c = contract
        self.allow_destructive = allow_destructive
        self.allow_reset_hook = allow_reset_hook
        self.evidence_dir = evidence_dir
        self.session = session or self._session()
        self.credentials = credentials
        self.clock, self.sleep = clock, sleep
        self._last_send: float | None = None
        self._baselines: dict[str, Exchange] = {}
        self._session_origins = origin_scope(contract.base_url)
        self.results: list[dict] = []

    @staticmethod
    def _session():
        import requests
        s = requests.Session()
        s.trust_env = False            # the contract's scope decides; no ambient proxy
        return s

    # --- auth ------------------------------------------------------------------------
    def _secret(self, ref: str):
        if ref.startswith("env:"):
            val = os.environ.get(ref[4:])
            if val is None:
                raise PermissionError(f"auth ref {ref!r}: the variable is not set")
            return val
        if ref.startswith("keyring:"):
            from fuzzlab.core.credentials import CredentialStore
            store = self.credentials or CredentialStore()
            host = urlsplit(self.c.base_url).hostname or ""
            cred = store.get(host, ref[len("keyring:"):])
            if cred is None:
                raise PermissionError(f"auth ref {ref!r}: no stored credential")
            return cred
        raise PermissionError(f"auth ref {ref!r} is not keyring:/env:")

    def auth_headers(self, profile_id: str | None) -> dict[str, str]:
        """The headers a profile adds (never logged)."""
        if not profile_id:
            return {}
        prof = self.c.profile(profile_id)
        kind, ref = prof["kind"], prof.get("ref") or ""
        if kind == "none":
            return {}
        if kind == "storage_state":
            doc = json.loads(Path(ref).read_text(encoding="utf-8"))
            host = urlsplit(self.c.base_url).hostname or ""
            jar = [f"{c['name']}={c['value']}" for c in doc.get("cookies") or []
                   if host == str(c.get("domain", "")).lstrip(".")
                   or host.endswith("." + str(c.get("domain", "")).lstrip("."))]
            return {"Cookie": "; ".join(jar)} if jar else {}
        secret = self._secret(ref)
        text = secret.password if hasattr(secret, "password") else str(secret)
        if kind == "bearer":
            return {"Authorization": f"Bearer {text}"}
        if kind == "basic":
            import base64
            user = getattr(secret, "username", "")
            token = base64.b64encode(f"{user}:{text}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        if kind == "cookie":
            return {"Cookie": text}
        name, _sep, value = text.partition(":")
        return {name.strip(): value.strip()} if _sep else {}

    # --- building and sending --------------------------------------------------------
    def prepare(self, endpoint_id: str, *, path_params=None, query=None, headers=None,
                body=None, raw_body=None, content_type_override=None,
                auth_profile=None) -> Prepared:
        ep = self.c.endpoint(endpoint_id)
        path = ep["path"]
        for name, val in (path_params or {}).items():
            path = path.replace("{" + name + "}", quote(str(val), safe=""))
        if re.search(r"\{p\d+\}|\{[A-Za-z_]\w*\}", path):
            raise ValueError(f"{endpoint_id}: a path parameter has no value")
        # an endpoint path is absolute from its origin (it is the captured path), so a
        # base URL's own sub-path is never prefixed again (the PA-0300 class)
        url = urljoin(ep.get("origin") or self.c.base_url, path)
        if query:
            url += ("&" if "?" in url else "?") + urlencode({k: str(v) for k, v in query.items()})
        hdrs = dict(ep.get("headers") or {}) or dict(DEFAULT_BROWSER_HEADERS)
        data: bytes | None = None
        if raw_body is not None:
            data = raw_body.encode("utf-8")
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = ep.get("content_type") or "application/json"
        if content_type_override:
            hdrs = {k: v for k, v in hdrs.items() if k.lower() != "content-type"}
            hdrs["Content-Type"] = content_type_override
        if in_origin_scope(url, self._session_origins):
            hdrs.update(self.auth_headers(auth_profile))
        for k, v in (headers or {}).items():          # the case's own headers win (D69)
            hdrs = {h: x for h, x in hdrs.items() if h.lower() != str(k).lower()}
            hdrs[str(k)] = str(v)
        return Prepared(ep["method"], url, hdrs, data)

    def _pace(self) -> None:
        gap = 1.0 / float(self.c.limits["rps"])
        if self._last_send is not None:
            wait = self._last_send + gap - self.clock()
            if wait > 0:
                self.sleep(wait)
        self._last_send = self.clock()

    def send(self, req: Prepared, *, explicit: frozenset[str] = frozenset()) -> Exchange:
        """One gated send (see the module docstring)."""
        if not in_origin_scope(req.url, self.c.allowed_origins):
            raise PermissionError(f"refusing an out-of-scope send to "
                                  f"{urlsplit(req.url).hostname!r}")
        check_send_url(req.url, explicit, req.method)
        from fuzzlab.tools.probesender import _is_timeout, _unobserved
        import requests
        limits = self.c.limits
        self._pace()
        ex = Exchange(req.url, req.method)
        start = self.clock()
        deadline = start + limits["timeout_ms"] / 1000
        try:
            resp = self.session.request(req.method, req.url, headers=req.headers,
                                        data=req.body, allow_redirects=False,
                                        timeout=limits["timeout_ms"] / 1000, stream=True)
            ex.status, ex.headers = resp.status_code, dict(resp.headers)
            chunks, size = [], 0
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size >= limits["max_body_bytes"]:
                    ex.truncated = True
                    break
                if self.clock() > deadline:
                    ex.timed_out = True
                    break
            ex.body = b"".join(chunks)[:limits["max_body_bytes"]]
            resp.close()
        except requests.RequestException as exc:
            if _is_timeout(exc):
                ex.timed_out, ex.error = True, "timeout"
            else:
                unobserved = _unobserved(exc)
                if unobserved is None:
                    raise TargetUnreachable(f"{urlsplit(req.url).hostname}: "
                                            f"{type(exc).__name__}") from None
                ex.error = str(unobserved)
        ex.latency_ms = int((self.clock() - start) * 1000)
        return ex

    # --- one case --------------------------------------------------------------------
    def _evidence(self, case_id: str, req: Prepared, ex: Exchange) -> dict | None:
        if self.evidence_dir is None:
            return None
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        ctype = {k.lower(): v for k, v in req.headers.items()}.get("content-type", "")
        rq = {"method": req.method, "url": redact_url(req.url),
              "headers": redact_headers(req.headers),
              "body": redact_body(req.body or b"", ctype).decode("utf-8", "replace")}
        rctype = {k.lower(): v for k, v in ex.headers.items()}.get("content-type", "")
        rs = {"status": ex.status, "headers": redact_headers(ex.headers),
              "body": redact_body(ex.body, rctype).decode("utf-8", "replace")[:MATCH_BYTES],
              "error": ex.error, "latency_ms": ex.latency_ms}
        refs = {}
        for kind, doc in (("req", rq), ("res", rs)):
            p = self.evidence_dir / f"{case_id}.{kind}.json"
            p.write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
            refs[f"{'request' if kind == 'req' else 'response'}_ref"] = str(p)
        return refs

    def _reset(self) -> None:
        hook = self.c.doc["run"].get("reset_hook")
        if not hook:
            return
        if not self.allow_reset_hook:
            raise PermissionError("the contract has a reset_hook; pass --allow-reset-hook "
                                  "to let it run")
        from fuzzlab import procutil
        procutil.run_bounded(shlex.split(hook), timeout=300)

    def run_case(self, case: dict) -> dict:
        cid = case["id"]
        res: dict = {"test_case": cid, "endpoint": case["endpoint"], "class": case["class"]}
        destructive = bool(case["safety"].get("destructive"))
        if destructive and not self.allow_destructive:
            return {**res, "verdict": "skipped", "reason": "destructive (pass "
                    "--allow-destructive to run it)", "matched": []}
        variables: dict = {}
        if destructive:
            self._reset()
        try:
            for i, step in enumerate(case.get("setup") or []):
                req = self.prepare(step["call"], path_params=fill(step.get("path_params"),
                                                                  variables),
                                   query=fill(step.get("query"), variables),
                                   headers=fill(step.get("headers"), variables),
                                   body=fill(step.get("body"), variables),
                                   auth_profile=step.get("auth_profile",
                                                         case.get("auth_profile")))
                ex = self.send(req)
                if ex.status is None or ex.status >= 400:
                    return {**res, "verdict": "error", "matched": [],
                            "reason": f"setup step {i + 1} ({step['call']}) got "
                                      f"{ex.status or ex.error}"}
                doc = ex.json()
                for var, jp in (step.get("extract") or {}).items():
                    try:
                        variables[var] = jsonpath(doc, jp)
                    except KeyError:
                        return {**res, "verdict": "error", "matched": [],
                                "reason": f"setup step {i + 1}: {jp} not in the answer"}
            rq = fill(case["request"], variables)
            req = self.prepare(case["endpoint"], path_params=rq.get("path_params"),
                               query=rq.get("query"), headers=rq.get("headers"),
                               body=rq.get("body"), raw_body=rq.get("raw_body"),
                               content_type_override=rq.get("content_type_override"),
                               auth_profile=case.get("auth_profile"))
            explicit = frozenset({url_key(req.url)}) if destructive else frozenset()
            ex = self.send(req, explicit=explicit)
        except DestructiveUrlRefused as exc:
            return {**res, "verdict": "skipped", "matched": [], "reason": str(exc)[:200]}
        except (ValueError, PermissionError) as exc:
            return {**res, "verdict": "error", "matched": [], "reason": str(exc)[:200]}
        finally:
            if destructive:
                self._reset()
        verdict, matched, reason = self.judge(case, ex, variables)
        out = {**res, "status": ex.status, "latency_ms": ex.latency_ms, "verdict": verdict,
               "matched": matched}
        if reason:
            out["reason"] = reason
        ev = self._evidence(cid, req, ex)
        if ev:
            out["evidence"] = ev
        return out

    # --- the oracle --------------------------------------------------------------------
    def _baseline(self, eid: str) -> Exchange | None:
        return self._baselines.get(eid)

    def judge(self, case: dict, ex: Exchange, variables: dict) -> tuple[str, list[str], str | None]:
        oracle = case.get("oracle") or {}
        rules = oracle.get("findings_if") or []
        latency_rule = next((r["latency_ms_gt"] for r in rules if "latency_ms_gt" in r), None)
        if ex.status is None:
            if ex.timed_out and latency_rule is not None:
                return "finding", ["latency_ms_gt"], "timed out"
            return "error", [], ex.error or "no response"
        matched: list[str] = []
        text = ex.body[:MATCH_BYTES].decode("utf-8", "replace")
        base = self._baseline(case["endpoint"])
        base_text = base.body[:MATCH_BYTES].decode("utf-8", "replace") if base else ""
        cls = f"{ex.status // 100}xx"
        if cls == "5xx":
            matched.append("status_class:5xx")
        leaks = [p.pattern for p in _LEAK if p.search(text) and not p.search(base_text)]
        if leaks:
            matched.append("leak:" + leaks[0])
        expect = oracle.get("expect_status_class") or []
        if expect and cls not in expect:
            matched.append("expect_status_class")
        for rule in rules:
            if "status_class" in rule and cls == rule["status_class"] and \
                    f"status_class:{cls}" not in matched:
                matched.append(f"status_class:{cls}")
            if "status_in" in rule and ex.status in rule["status_in"]:
                matched.append("status_in")
            for rx in rule.get("body_matches") or []:
                if re.search(rx, text) and not (base_text and re.search(rx, base_text)):
                    matched.append("body_matches")
                    break
            if "latency_ms_gt" in rule and (ex.latency_ms or 0) > rule["latency_ms_gt"]:
                matched.append("latency_ms_gt")
            if rule.get("response_schema_drift") and self._drift(case["endpoint"], ex):
                matched.append("response_schema_drift")
            if "state_check" in rule:
                held = self._state_check(rule["state_check"], variables, case)
                if held is False:
                    matched.append("state_check")
        if not matched and ex.status < 500 and case["endpoint"] not in self._baselines \
                and ex.status < 400:
            self._baselines[case["endpoint"]] = ex
        return ("finding" if matched else "pass"), matched, None

    def _drift(self, eid: str, ex: Exchange) -> bool:
        schema = self.c.endpoint(eid).get("response_schema")
        doc = ex.json()
        if not schema or doc is None or not 200 <= (ex.status or 0) < 300:
            return False
        from jsonschema import Draft202012Validator
        clean = _strip_extensions(schema)
        return any(True for _ in Draft202012Validator(clean).iter_errors(doc))

    def _state_check(self, sc: dict, variables: dict, case: dict) -> bool | None:
        try:
            req = self.prepare(sc["call"], path_params=fill(sc.get("path_params"), variables),
                               query=fill(sc.get("query"), variables),
                               auth_profile=sc.get("auth_profile", case.get("auth_profile")))
            ex = self.send(req)
        except (ValueError, PermissionError, DestructiveUrlRefused):
            return None
        doc = ex.json()
        return None if doc is None else assertion_holds(doc, sc["assert_jsonpath"])

    # --- the run -----------------------------------------------------------------------
    def run(self, on_result: Callable[[dict], None] | None = None) -> list[dict]:
        for case in self.c.doc["test_cases"]:
            result = self.run_case(case)
            self.results.append(result)
            if on_result is not None:
                on_result(result)
        return self.results


def _strip_extensions(schema, depth: int = 0):
    """A schema without ``x-*`` keys, ``enum`` and ``examples`` (observations, not
    constraints): drift is a type or required-field change, never a new value."""
    if depth > 32 or not isinstance(schema, dict):
        return {}
    out = {}
    for key, val in schema.items():
        if str(key).startswith("x-") or key in ("enum", "examples", "format"):
            continue
        if key == "properties" and isinstance(val, dict):      # names, not keywords
            out[key] = {name: _strip_extensions(sub, depth + 1) for name, sub in val.items()}
        elif key == "items":
            out[key] = _strip_extensions(val, depth + 1)
        else:
            out[key] = val
    return out


def summary(results: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return counts
