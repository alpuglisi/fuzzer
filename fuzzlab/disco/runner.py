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
- each response is read up to ``limits.max_body_bytes`` (on the wire and decoded) and
  within ``limits.timeout_ms``, checked at every receive, by the one bounded reader
  (`core.bodyread.read`, SP-57, BUG-0536; PA-0102(1)); sends are spaced to
  ``limits.rps``.

**A send that gets no complete response is no verdict** (PA-0153, BUG-0528): no
response, a body cut off or over ``max_body_bytes``, or a ``timeout_ms`` that passed
before the whole answer arrived (`Exchange.incomplete`) is an ``error`` for that case and
the run goes on -- never a pass, a match on what was read, a baseline or evidence bytes
(the response is closed on every exit). A read or deadline timeout is a ``finding`` only
under a ``latency_ms_gt`` bound that ``timeout_ms`` proves; a connect timeout proves
nothing. SP-34 classifies the exceptions (`tools.probesender`). A target that cannot be
reached at all (refused, DNS, TLS) stops the run loudly (`TargetUnreachable`) with the
results so far written.

**Only the application's own answer is judged** (SP-56, `core.comparability`;
BUG-0529): a throttled or unavailable answer (429, 503) and a credentialed request's
refused credential (401, 407, a redirect to a login page -- not a credential submission's
own refusal, SP-16 `session.detect.login_facts`) are judged only where ``status_in``
names the status; a policy block (403, 451) only where ``expect_status_class`` holds
``4xx`` or ``status_in`` names it. Otherwise each is an ``error``. A gateway answer
(502, 504) is judged under the 5xx rule. A state check is satisfied, violated or
**unobserved**; a pass needs every one satisfied, and the unobserved ones are listed on
the result (``unobserved``).

**Credentials** come from the auth profile's ``ref`` (`keyring:<identity>` through
`core.credentials`, ``env:<NAME>``, or a Playwright storage-state file), are sent only to
the base URL's own origin (PA-0134: an artefact with a secret carries the origin it
belongs to), and are never written: evidence goes through `core.redaction`.

**The oracle.** A case's ``findings_if`` rules, plus the built-in rules every case gets:
a 5xx, and a response matching `LEAK_PATTERNS` (a stack trace, a database error) that the
same endpoint's baseline did not already show (the PA-0117 noise guard: the first
complete application answer below 400 that passed is its baseline). An answer outside the
case's ``expect_status_class`` is matched as ``expect_status_class``. A case's
``body_matches`` patterns (contract-supplied) run in a worker process killed after
`MATCH_SECONDS` (`search_bounded`, BUG-0536): patterns that could not be evaluated make
the case an ``error`` unless other evidence matched -- never a no-match.
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
from urllib.parse import quote, urljoin, urlsplit

from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
from fuzzlab.core.redaction import redact_body, redact_url
from fuzzlab.core.urls import (DestructiveUrlRefused, check_send_url, in_origin_scope,
                               origin_scope, place_query_param, url_key)
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
#: Seconds one case's ``body_matches`` patterns may take, together, on its answer and its
#: baseline (BUG-0536). A backtracking pattern's CPU is unbounded on target text and a
#: thread cannot stop it, so they run in a worker process killed at this limit.
MATCH_SECONDS = 5.0
_MATCH_WORKER = ("import json, re, sys\n"
                 "d = json.load(sys.stdin)\n"
                 "json.dump([[re.search(p, t) is not None for t in d['texts']]\n"
                 "           for p in d['patterns']], sys.stdout)\n")


def search_bounded(patterns: list[str], texts: list[str]) -> list[list[bool]] | None:
    """Whether each pattern matches (``re.search``) each text: one row per pattern, one
    boolean per text. Computed in a worker process (`procutil.run_bounded`: its own
    session, killed with its tree at the limit) given `MATCH_SECONDS`; None when it did
    not answer in time, could not start, or answered anything but that shape -- never a
    match and never a miss."""
    if not patterns:
        return []
    import subprocess
    import sys

    from fuzzlab import procutil
    payload = json.dumps({"patterns": list(patterns), "texts": list(texts)})
    try:
        done = procutil.run_bounded([sys.executable, "-I", "-S", "-c", _MATCH_WORKER],
                                    timeout=MATCH_SECONDS, input=payload)
    except (subprocess.TimeoutExpired, procutil.ProcUtilError, OSError):
        return None
    try:
        rows = json.loads(done.stdout) if done.returncode == 0 else None
    except (TypeError, ValueError):
        return None
    if not (isinstance(rows, list) and len(rows) == len(patterns) and all(
            isinstance(row, list) and len(row) == len(texts)
            and all(isinstance(v, bool) for v in row) for row in rows)):
        return None
    return rows


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
    #: What was read. For an incomplete exchange only its length is ever used: it is
    #: never judged, a baseline or written as evidence (FR-FUZZ-52, BUG-0528).
    body: bytes = b""
    latency_ms: int | None = None
    error: str | None = None
    timed_out: bool = False
    truncated: bool = False
    #: Reading the body failed after the headers (cut off, reset): SP-34's reason.
    cut: str | None = None
    #: On a timeout: ``"connect"`` (nothing was sent, M7), ``"read"`` (the transport's
    #: read timeout) or ``"deadline"`` (the runner's own ``timeout_ms`` passed while the
    #: answer was read).
    timeout_kind: str | None = None

    @property
    def incomplete(self) -> str | None:
        """Why this exchange is not a whole answer (status line, headers and the whole
        body within ``timeout_ms`` and ``max_body_bytes``), or None."""
        if self.status is None:
            if self.timeout_kind == "connect":
                return "timed out before connecting"
            return "timed out before the headers" if self.timed_out else \
                (self.error or "no response")
        if self.timed_out:
            return f"timed out after the headers ({self.status})"
        if self.cut:
            return f"body cut off ({self.status})"
        if self.truncated:
            return f"body over max_body_bytes ({self.status})"
        return None

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
    #: The profile's credential is in the final headers -- added on the base origin and
    #: not replaced by the case's own header (D69): a forged or empty token is not the
    #: profile's credential (SP-56's ``credentialed``).
    credentialed: bool = False
    #: The request's own names (query keys, JSON body keys at every depth): SP-16 reads
    #: a credential name among them (`session.detect.login_facts`).
    entry_names: tuple[str, ...] = ()


@dataclass
class Judgement:
    """`Runner.judge`'s answer: the verdict, what matched, why, and the state checks
    that observed nothing (``{"check": n, "reason": ...}``, numbered among the case's
    state checks)."""
    verdict: str
    matched: list[str]
    reason: str | None = None
    unobserved: list[dict] = field(default_factory=list)
    response_class: str | None = None


def _json_keys(doc, depth: int = 0) -> list[str]:
    """Every key of a JSON document, at every depth (bounded)."""
    if depth > 32:
        return []
    if isinstance(doc, dict):
        out = [str(k) for k in doc]
        for v in doc.values():
            out += _json_keys(v, depth + 1)
        return out
    if isinstance(doc, list):
        return [k for v in doc for k in _json_keys(v, depth + 1)]
    return []


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
        for k, v in (query or {}).items():
            # SP-42 (FR-FUZZ-64, BUG-0531's sweep): a name the endpoint's own query already
            # has is set in place (its first occurrence), never appended as a second one;
            # a new name is appended, encoded as before
            url = place_query_param(url, str(k), str(v))
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
        auth = self.auth_headers(auth_profile) if in_origin_scope(
            url, self._session_origins) else {}
        hdrs.update(auth)
        for k, v in (headers or {}).items():          # the case's own headers win (D69)
            hdrs = {h: x for h, x in hdrs.items() if h.lower() != str(k).lower()}
            hdrs[str(k)] = str(v)
        final = {str(h).lower(): x for h, x in hdrs.items()}
        credentialed = bool(auth) and all(final.get(str(h).lower()) == x
                                          for h, x in auth.items())
        names = [str(k) for k in (query or {})] + (_json_keys(body) if raw_body is None
                                                   else [])
        return Prepared(ep["method"], url, hdrs, data, credentialed=credentialed,
                        entry_names=tuple(names))

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
        from fuzzlab.core import bodyread
        from fuzzlab.tools.probesender import _is_connect_timeout, _is_timeout, _unobserved
        import requests
        limits = self.c.limits
        self._pace()
        ex = Exchange(req.url, req.method)
        start = self.clock()
        deadline = start + limits["timeout_ms"] / 1000
        resp = None
        try:
            resp = self.session.request(req.method, req.url, headers=req.headers,
                                        data=req.body, allow_redirects=False,
                                        timeout=limits["timeout_ms"] / 1000, stream=True)
            ex.status, ex.headers = resp.status_code, dict(resp.headers)
            # the one bounded reader (SP-57, BUG-0536): max_body_bytes on the wire and
            # decoded, timeout_ms checked at every receive
            cap = limits["max_body_bytes"]
            body = bodyread.read(resp, deadline=deadline, clock=self.clock,
                                 limits=bodyread.Limits(wire=cap, decoded=cap))
            ex.body = body.data
            if body.reason == "deadline":
                ex.timed_out, ex.timeout_kind = True, "deadline"
            elif body.reason in ("wire", "decoded"):
                ex.truncated = True
            elif body.reason is not None:                 # a coding it cannot bound
                ex.error = ex.cut = f"no complete response: incomplete body ({body.reason})"
        except requests.RequestException as exc:
            if _is_timeout(exc):
                ex.timed_out, ex.error = True, "timeout"
                ex.timeout_kind = "connect" if _is_connect_timeout(exc) else "read"
            else:
                unobserved = _unobserved(exc)
                if unobserved is None:
                    raise TargetUnreachable(f"{urlsplit(req.url).hostname}: "
                                            f"{type(exc).__name__}") from None
                ex.error = str(unobserved)
                if ex.status is not None:
                    ex.cut = ex.error                     # after the headers (BUG-0528)
        finally:
            if resp is not None:                          # every exit (BUG-0528)
                resp.close()
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
              "error": ex.error, "latency_ms": ex.latency_ms}
        if ex.incomplete is not None:
            # M3: a partial body is never written -- the redactor may only be able to
            # sniff it (a cut JSON document served as text/plain), so its bytes stay out
            rs.update(body="omitted (incomplete)", body_bytes=len(ex.body),
                      incomplete=ex.incomplete)
        else:
            rs["body"] = redact_body(ex.body, rctype).decode("utf-8", "replace")[:MATCH_BYTES]
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
                failed = self._setup_failed(req, ex)
                if failed:
                    return {**res, "verdict": "error", "matched": [],
                            "reason": f"setup step {i + 1} ({step['call']}) got {failed}"}
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
        j = self.judge(case, ex, variables, req)
        out = {**res, "status": ex.status, "latency_ms": ex.latency_ms, "verdict": j.verdict,
               "matched": j.matched, "response_class": j.response_class}
        if j.reason:
            out["reason"] = j.reason
        if j.unobserved:
            out["unobserved"] = j.unobserved
        ev = self._evidence(cid, req, ex)
        if ev:
            out["evidence"] = ev
        return out

    # --- the oracle --------------------------------------------------------------------
    def _baseline(self, eid: str) -> Exchange | None:
        return self._baselines.get(eid)

    @staticmethod
    def classify(req: Prepared | None, ex: Exchange) -> tuple[str, str, object]:
        """SP-56's class of a complete exchange, with SP-16's facts (`login_facts`) on the
        request's URL and own names: ``(class, reason, facts)``."""
        from fuzzlab.core.comparability import response_class
        from fuzzlab.session.detect import login_facts
        facts = login_facts(ex.url, ex.headers,
                            entry_names=req.entry_names if req is not None else ())
        cls, why = response_class(ex.status, ex.headers, complete=ex.incomplete is None,
                                  credentialed=bool(req is not None and req.credentialed),
                                  credential_submission=facts.credential_submission,
                                  redirect_to_login=facts.redirect_to_login)
        return cls, why, facts

    def _setup_failed(self, req: Prepared, ex: Exchange) -> str | None:
        """Why a setup step's answer set nothing up, or None: it must be a complete
        application answer below 400 and not a redirect to a login page (a failed form
        login, A8) -- unless the step itself creates or resets an account, whose
        redirect to the login page is its success (ADOPT 5)."""
        from fuzzlab.core.comparability import APPLICATION
        why = ex.incomplete
        if why is not None:
            return f"an incomplete response ({why})"
        if ex.status >= 400:
            return str(ex.status)
        cls, reason, facts = self.classify(req, ex)
        if cls != APPLICATION:
            return reason
        if facts.redirect_to_login and not facts.account_submission:
            return f"a {ex.status} redirect to a login page (not logged in)"
        return None

    def judge(self, case: dict, ex: Exchange, variables: dict,
              req: Prepared | None = None) -> Judgement:
        """FR-FUZZ-52: only a complete answer that is the application's own is judged.
        An incomplete exchange is an ``error`` (a read or deadline timeout matches a
        ``latency_ms_gt`` bound it proves, M7). A throttled or unavailable answer, or a
        credentialed request's refused credential, is judged only where ``status_in``
        names its status; a policy block where ``expect_status_class`` holds 4xx or
        ``status_in`` names it; otherwise each is an ``error`` (SP-56, BUG-0529). Every
        state check must be observed and satisfied for a pass (BUG-0528)."""
        from fuzzlab.core.comparability import (APPLICATION, AUTH_FAILURE, INCOMPLETE,
                                                POLICY_BLOCK, THROTTLE_OR_UNAVAILABLE)
        oracle = case.get("oracle") or {}
        rules = oracle.get("findings_if") or []
        latency_rule = next((r["latency_ms_gt"] for r in rules if "latency_ms_gt" in r), None)
        why = ex.incomplete
        if why is not None:
            if ex.timeout_kind in ("read", "deadline") and latency_rule is not None \
                    and latency_rule <= self.c.limits["timeout_ms"]:
                return Judgement("finding", ["latency_ms_gt"], "timed out", [], INCOMPLETE)
            return Judgement("error", [], f"incomplete response: {why}", [], INCOMPLETE)
        named = any(ex.status in (r.get("status_in") or ()) for r in rules)
        expect = oracle.get("expect_status_class") or []
        cls, reason, _facts = self.classify(req, ex)
        if cls == THROTTLE_OR_UNAVAILABLE and not named:
            return Judgement("error", [], f"not judged: {reason}", [], cls)
        if cls == AUTH_FAILURE and req is not None and req.credentialed and not named:
            return Judgement("error", [], f"credentials not accepted ({reason})", [], cls)
        if cls == POLICY_BLOCK and not named and "4xx" not in expect:
            return Judgement("error", [], f"not judged: {reason}, which the case does not "
                                          f"expect", [], cls)
        matched: list[str] = []
        unobserved: list[dict] = []
        text = ex.body[:MATCH_BYTES].decode("utf-8", "replace")
        base = self._baseline(case["endpoint"])
        base_text = base.body[:MATCH_BYTES].decode("utf-8", "replace") if base else ""
        # the case's patterns, matched on its answer and its baseline in one bounded
        # worker (BUG-0536): None when they could not be evaluated in time
        patterns = [rx for rule in rules for rx in rule.get("body_matches") or []]
        hits = search_bounded(patterns, [text, base_text]) if patterns else []
        pattern_at = 0
        status_class = f"{ex.status // 100}xx"
        if status_class == "5xx":
            matched.append("status_class:5xx")
        leaks = [p.pattern for p in _LEAK if p.search(text) and not p.search(base_text)]
        if leaks:
            matched.append("leak:" + leaks[0])
        if expect and status_class not in expect:
            matched.append("expect_status_class")
        checks = 0
        for rule in rules:
            if "status_class" in rule and status_class == rule["status_class"] and \
                    f"status_class:{status_class}" not in matched:
                matched.append(f"status_class:{status_class}")
            if "status_in" in rule and ex.status in rule["status_in"]:
                matched.append("status_in")
            body_hit = False
            for _rx in rule.get("body_matches") or []:
                if hits is not None and hits[pattern_at][0] \
                        and not (base_text and hits[pattern_at][1]):
                    body_hit = True
                pattern_at += 1
            if body_hit:
                matched.append("body_matches")
            if "latency_ms_gt" in rule and (ex.latency_ms or 0) > rule["latency_ms_gt"]:
                matched.append("latency_ms_gt")
            if rule.get("response_schema_drift") and self._drift(case["endpoint"], ex):
                matched.append("response_schema_drift")
            if "state_check" in rule:
                checks += 1
                held, why_not = self._state_check(rule["state_check"], variables, case)
                if held is False:
                    matched.append("state_check")
                elif held is None:
                    unobserved.append({"check": checks, "reason": why_not})
        if matched:
            # evidence already observed stands (PA-0137(1)); the unobserved checks are
            # recorded beside it
            return Judgement("finding", matched, None, unobserved, cls)
        if hits is None:                    # never a no-match (BUG-0536)
            return Judgement("error", [], f"body_matches not evaluated within "
                                          f"{MATCH_SECONDS:g} s (inconclusive)",
                             unobserved, cls)
        if unobserved:
            first = unobserved[0]
            return Judgement("error", [], f"state check {first['check']} not observed: "
                                         f"{first['reason']}", unobserved, cls)
        if cls == APPLICATION and ex.status < 400 \
                and case["endpoint"] not in self._baselines:
            self._baselines[case["endpoint"]] = ex     # a complete application answer
        return Judgement("pass", [], None, [], cls)

    def _drift(self, eid: str, ex: Exchange) -> bool:
        schema = self.c.endpoint(eid).get("response_schema")
        doc = ex.json()
        if not schema or doc is None or not 200 <= (ex.status or 0) < 300:
            return False
        from jsonschema import Draft202012Validator
        clean = _strip_extensions(schema)
        return any(True for _ in Draft202012Validator(clean).iter_errors(doc))

    def _state_check(self, sc: dict, variables: dict, case: dict
                     ) -> tuple[bool | None, str | None]:
        """``(True, None)`` satisfied, ``(False, None)`` violated, or ``(None, why)``
        unobserved (BUG-0528): it could not be prepared or sent, its answer was not a
        complete application 2xx (every other SP-56 class is not a 2xx), not JSON, or
        the assertion could not be evaluated on it. The reason names no URL or value."""
        from fuzzlab.core.comparability import APPLICATION
        try:
            req = self.prepare(sc["call"], path_params=fill(sc.get("path_params"), variables),
                               query=fill(sc.get("query"), variables),
                               auth_profile=sc.get("auth_profile", case.get("auth_profile")))
        except (ValueError, PermissionError) as exc:
            return None, f"could not be prepared ({type(exc).__name__})"
        try:
            ex = self.send(req)
        except (PermissionError, DestructiveUrlRefused) as exc:
            return None, f"refused at the send ({type(exc).__name__})"
        why = ex.incomplete
        if why is not None:
            return None, f"incomplete response ({why})"
        cls, reason, _facts = self.classify(req, ex)
        if cls != APPLICATION or not 200 <= ex.status < 300:
            return None, f"not the application's 2xx answer ({reason or ex.status})"
        doc = ex.json()
        if doc is None:
            return None, "the answer is not JSON"
        held = assertion_holds(doc, sc["assert_jsonpath"])
        if held is None:
            return None, "the assertion could not be evaluated on the answer"
        return held, None

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
