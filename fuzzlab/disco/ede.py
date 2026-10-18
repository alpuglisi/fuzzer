"""Excessive data exposure by response mutation (``fuzzlab disco ede``; FR-CRAWL-25).

After EDEFuzz (Pan, Cohney, Murray, Pham, ICSE 2024): a field of an API response is
*excessive* when removing it leaves the page the user sees unchanged -- the server sent
data the client never shows. The test mutates the **response**, not the request, so it
needs a server it controls: the page's JSON API answers are served from a disco run's
own capture (`capture.jsonl`), changed one field at a time, while the page itself and
its static assets load through the guarded browser as usual. Those API calls never
reach the target during the test.

Per page of the run (each in-scope HTML document it loaded):

1. **Baseline.** The page is loaded `BASELINE_LOADS` times with the recorded answers.
   Nodes whose text or attributes differ between those loads (a clock, a random id)
   are ignored from then on; a page whose *structure* differs between them is
   non-deterministic and skipped (the paper's pre-processing step).
2. **Fields.** Every scalar field of every recorded JSON answer the page requested,
   named by its shape: ``$[*].deletedAt`` is the ``deletedAt`` of every element of the
   top-level list, removed from all of them at once. One load per field, not one per
   element (EDEFuzz mutated each leaf; repeated structures dominated its cost).
3. **Verdict.** A field whose removal leaves every non-ignored node unchanged is
   reported *unused at load*. It may still be used after an interaction the load does
   not perform (the paper's one false-positive class); it is a candidate for a person
   to inspect, never a confirmed finding. Its value is never written: only its type,
   and whether its name reads as sensitive (`core.redaction.is_sensitive_name`).

Only GET answers are replayed (matched by method and redacted URL; the request body is
not part of the key). Everything else goes to the guard (`navguard.guard_page`): scope,
destructive URLs, the abort code, as in every guarded browser.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urldefrag

from fuzzlab.core.redaction import is_sensitive_name, redact_url
from fuzzlab.core.urls import in_origin_scope, origin_scope
from fuzzlab.disco.capture import CaptureRecord
from fuzzlab.disco.synth import content_family, parse_body
from fuzzlab.tools import navguard
from fuzzlab.tools.netquiet import Inflight

#: Loads of each page with the recorded answers, to find what varies by itself.
BASELINE_LOADS = 3
#: How long a load is let settle (requests quiet for `QUIET_MS`, at most this).
SETTLE_MS = 5000
QUIET_MS = 300
#: Never more than this many fields of one answer (one load each).
MAX_FIELDS = 200
MAX_DEPTH = 12

#: One entry per element of the rendered body: ``depth|tag|attributes|own text``.
_SNAPSHOT_JS = r"""() => {
  const out = [];
  const walk = (el, depth) => {
    const attrs = Array.from(el.attributes || [])
      .filter(a => a.name !== 'style')
      .map(a => a.name + '=' + a.value).sort().join(' ');
    let text = '';
    for (const n of el.childNodes) if (n.nodeType === 3) text += n.textContent;
    let value = '';
    if ('value' in el && typeof el.value === 'string') value = el.value;
    out.push(depth + '|' + el.tagName + '|' + attrs + '|' + text.trim() + '|' + value);
    for (const c of el.children) walk(c, depth + 1);
  };
  if (document.body) walk(document.body, 0);
  return out;
}"""


# --- the pure half ----------------------------------------------------------------------
def replay_key(method: str, url: str) -> tuple[str, str]:
    """What a live request is matched on: its method and its URL as the capture stores
    it (redacted, no fragment)."""
    return str(method).upper(), urldefrag(redact_url(url))[0]


def replayable(records: list[CaptureRecord]) -> dict[tuple[str, str], CaptureRecord]:
    """The capture's JSON GET answers that can be served again: answered 2xx, a JSON
    body that is whole (not truncated, not omitted). The last one per key wins."""
    out: dict[tuple[str, str], CaptureRecord] = {}
    for rec in records:
        if rec.kind != "http" or rec.method != "GET" or rec.status is None \
                or not 200 <= rec.status < 300 or rec.res_truncated:
            continue
        if content_family(rec.res_ctype) != "json" or \
                parse_body(rec.res_body, rec.res_ctype) is None:
            continue
        out[replay_key(rec.method, rec.url)] = rec
    return out


_HTML = frozenset({"text/html", "application/xhtml+xml"})


def _media(ctype: str | None) -> str:
    return (ctype or "").split(";", 1)[0].strip().lower()


def page_urls(records: list[CaptureRecord], in_scope) -> list[str]:
    """The in-scope HTML documents the run loaded, in first-seen order."""
    seen: dict[str, None] = {}
    for rec in records:
        if rec.kind == "http" and rec.method == "GET" and rec.status is not None \
                and 200 <= rec.status < 300 and _media(rec.res_ctype) in _HTML \
                and in_scope(rec.url):
            seen.setdefault(urldefrag(rec.url)[0], None)
    return list(seen)


Path_ = tuple  # a field's shape: dict keys, "*" for every element of a list


def field_paths(value, path: Path_ = (), depth: int = 0) -> list[Path_]:
    """Every scalar field's shape, each once (``("*", "id")`` for a list of objects)."""
    out: dict[Path_, None] = {}
    if depth > MAX_DEPTH:
        return []
    if isinstance(value, dict):
        for k, v in value.items():
            for p in field_paths(v, path + (str(k),), depth + 1):
                out.setdefault(p, None)
    elif isinstance(value, list):
        for v in value:
            for p in field_paths(v, path + ("*",), depth + 1):
                out.setdefault(p, None)
    elif path:
        out.setdefault(path, None)
    return list(out)


def without(value, path: Path_):
    """A copy of ``value`` with the field at ``path`` removed everywhere it occurs."""
    if not path:
        return value
    head, rest = path[0], path[1:]
    if isinstance(value, list):
        if head != "*":
            return value
        return [without(v, rest) for v in value] if rest else []
    if isinstance(value, dict):
        if head not in value:
            return value
        out = dict(value)
        if rest:
            out[head] = without(value[head], rest)
        else:
            del out[head]
        return out
    return value


def path_text(path: Path_) -> str:
    return "$" + "".join("[*]" if p == "*" else f".{p}" for p in path)


def value_type(value, path: Path_) -> str:
    """The JSON type at ``path`` (the first occurrence), never the value."""
    for p in path:
        if isinstance(value, list):
            value = value[0] if value else None
        if p != "*":
            value = value.get(p) if isinstance(value, dict) else None
    if isinstance(value, list):
        value = value[0] if value else None
    return {bool: "boolean", int: "number", float: "number", str: "string",
            type(None): "null"}.get(type(value), "object")


def noise_mask(snapshots: list[list[str]]) -> set[int] | None:
    """The node indices whose content varied across the baseline loads, or None when
    the page's structure varied (its node count, or a node's depth and tag)."""
    first = snapshots[0]
    shape = [s.split("|", 2)[:2] for s in first]
    ignored: set[int] = set()
    for snap in snapshots[1:]:
        if len(snap) != len(first) or [s.split("|", 2)[:2] for s in snap] != shape:
            return None
        ignored |= {i for i, (a, b) in enumerate(zip(first, snap)) if a != b}
    return ignored


def same_page(base: list[str], other: list[str], ignored: set[int]) -> bool:
    return len(base) == len(other) and all(
        a == b for i, (a, b) in enumerate(zip(base, other)) if i not in ignored)


# --- the browser half -------------------------------------------------------------------
@dataclass
class EdeReport:
    pages: int = 0
    pages_skipped_nondeterministic: int = 0
    pages_failed: int = 0
    answers: int = 0
    fields_tested: int = 0
    fields_unused: int = 0
    loads: int = 0
    budget_hit: str | None = None
    findings: list[dict] = field(default_factory=list)


class EdeRunner:
    """Runs the test over one disco run's capture (see the module doc)."""

    def __init__(self, records: list[CaptureRecord], *, scope_urls: list[str],
                 headless: bool = True, max_pages: int = 20, deadline_s: float = 900.0,
                 clock=time.monotonic):
        self.scope_urls = list(scope_urls)
        self.origins = origin_scope(*self.scope_urls)
        self.replay = replayable(records)
        self.pages = page_urls(records, self._in_scope)[:max_pages]
        self.headless = headless
        self.deadline = clock() + deadline_s
        self.clock = clock
        self.report = EdeReport()
        self._mutation: tuple[tuple[str, str], Path_] | None = None
        self._served: dict[tuple[str, str], None] = {}

    def _in_scope(self, url: str) -> bool:
        return in_origin_scope(url, self.origins)

    # the replaying route: added after the guard, so it answers first; anything it does
    # not replay falls back to the guard
    def _route(self, route, request=None) -> None:
        req = route.request
        key = replay_key(req.method, req.url)
        rec = self.replay.get(key) if self._in_scope(req.url) else None
        if rec is None:
            route.fallback()
            return
        self._served.setdefault(key, None)
        body = rec.res_body
        if self._mutation is not None and self._mutation[0] == key:
            body = json.dumps(without(parse_body(rec.res_body, rec.res_ctype),
                                      self._mutation[1]))
        route.fulfill(status=rec.status,
                      headers={"content-type": rec.res_ctype or "application/json"},
                      body=body)

    def _load(self, page, url: str, net: Inflight) -> list[str]:
        self.report.loads += 1
        navguard.navigate(page, url, timeout_ms=SETTLE_MS, wait_until="load")
        end = self.clock() + SETTLE_MS / 1000
        while self.clock() < end:
            if net.n == 0 and self.clock() - net.last_change >= QUIET_MS / 1000:
                break
            page.wait_for_timeout(50)
        return page.evaluate(_SNAPSHOT_JS)

    def run(self) -> EdeReport:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
        args = navguard.browser_launch_args(self.scope_urls)
        launch = navguard.chromium_launch_kwargs(args, headless=self.headless)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**launch)
            try:
                for url in self.pages:
                    if self.clock() >= self.deadline:
                        self.report.budget_hit = "deadline"
                        break
                    ctx = browser.new_context(service_workers="block")
                    navguard.guard_page(ctx, in_scope=self._in_scope)
                    ctx.route("**/*", self._route)
                    page = ctx.new_page()
                    net = Inflight(page)
                    try:
                        self._page(page, url, net)
                    except PlaywrightError:
                        self.report.pages_failed += 1
                    finally:
                        navguard.release(ctx)
                        ctx.close()
            finally:
                browser.close()
        return self.report

    def _page(self, page, url: str, net: Inflight) -> None:
        self._mutation, self._served = None, {}
        baselines = [self._load(page, url, net) for _ in range(BASELINE_LOADS)]
        self.report.pages += 1
        ignored = noise_mask(baselines)
        if ignored is None:
            self.report.pages_skipped_nondeterministic += 1
            return
        for key in list(self._served):
            rec = self.replay[key]
            value = parse_body(rec.res_body, rec.res_ctype)
            self.report.answers += 1
            for path in field_paths(value)[:MAX_FIELDS]:
                if self.clock() >= self.deadline:
                    self.report.budget_hit = "deadline"
                    return
                self._mutation = (key, path)
                try:
                    snap = self._load(page, url, net)
                finally:
                    self._mutation = None
                self.report.fields_tested += 1
                if same_page(baselines[0], snap, ignored):
                    self.report.fields_unused += 1
                    name = next((p for p in reversed(path) if p != "*"), "")
                    self.report.findings.append({
                        "page": redact_url(url), "endpoint": key[1], "field": path_text(path),
                        "type": value_type(value, path),
                        "sensitive_name": is_sensitive_name(name)})


def write_report(report: EdeReport, out: Path) -> None:
    """``ede.json``: the counts and the unused fields (no values)."""
    doc = {k: v for k, v in report.__dict__.items()}
    out.write_text(json.dumps(doc, indent=1), encoding="utf-8")
