"""Data-flow and sequence views over the trace model (FR-UI-511, `core.trace`).

Every view is built from the persisted model -- ``dg_entity`` / ``dg_flow`` /
``dg_evidence`` and the ``trace_event`` rows they cite -- never from free text, so the
web page, the JSON export and the Mermaid export show the same thing and can be rebuilt
after a restart. Nothing here sends a request or widens a scope.

**Data flow** (`dataflow`): actors (the browser, the automated explorer, the testing
tool), the target application, its origins and their interfaces (method + path, id-shaped
segments grouped -- the grouping basis is recorded), external hosts the browser asked
for, and flows with direction, protocol, statuses, data categories by parameter name,
auth context by safe name, the evidence count and first/last seen. The application view
and the testing overlay are separate (``view``): tool traffic never draws the target's
architecture. Each origin says its internals are unknown; no server-side component is
ever drawn. Each interface carries its coverage (`COVERAGE`): what was discovered,
captured, scheduled, executed, evaluated and found -- "no finding" is shown as what was
tested, never as "secure".

**Sequences** (`sequence`): a test (its exchanges, strategy outcomes and finding), a
captured workflow (an explorer action and the exchanges tagged with it, through the
capture proxy), the spider's trace (crawl order), the traffic through the intercepting
proxy (``proxy``, FR-UI-512), one exchange, or a finding. Steps are
ordered by the producer's sequence, and correlated by explicit ids (test, strategy
scope, action id, parent exchange), never by time windows; a step with no response is
drawn lost, never as a reply; repeated exchanges of one role are collapsed with their
evidence keys kept.

Exports: `export_json` (the whole model with its evidence keys and completeness),
`mermaid_flow`, `mermaid_sequence`. Mermaid cannot carry every attribute, so the JSON is
the full record; every Mermaid label is reduced to a safe alphabet with numeric entity
codes (`mermaid_text`), so captured text can never become diagram syntax.
"""

from __future__ import annotations

import json
import re

from fuzzlab.core import trace

SCHEMA = "fuzzlab.diagram/1"
COVERAGE = ("discovered", "captured", "scheduled", "executed", "evaluated", "finding")
#: The units: *discovered* and *captured* count observations (captured: browser traffic
#: that was answered); *scheduled* counts tests; *executed* counts a test's own sends,
#: answered or not (a follow-up, a restore and a retry are part of a send, not one);
#: *evaluated* counts strategy runs that reached a verdict; *finding* counts findings.
_NOT_A_TEST_SEND = frozenset({"follow-up", "restore", "retry"})
#: Exchanges of one role in a row above this many are collapsed in a sequence.
COLLAPSE_AFTER = 3
#: Steps a sequence returns at most (the rest is reported as truncated).
MAX_STEPS = 400


def _attrs(row) -> dict:
    try:
        return json.loads(row["attrs"] or "{}")
    except ValueError:
        return {}


def _evidence_counts(conn, run_id: int) -> dict[str, int]:
    return {r["ref"]: r["n"] for r in conn.execute(
        "SELECT ref, COUNT(*) n FROM dg_evidence WHERE run_id=? GROUP BY ref", (run_id,))}


def status(conn, run_id: int) -> dict:
    """How complete the model is: event counts, whether the run ended and how, the
    recorder's dropped events, queue pressure and lag, and the sources not modelled."""
    kinds = {r["kind"]: r["n"] for r in conn.execute(
        "SELECT kind, COUNT(*) n FROM trace_event WHERE run_id=? GROUP BY kind",
        (run_id,))}
    last = conn.execute("SELECT MAX(id) m FROM trace_event WHERE run_id=?",
                        (run_id,)).fetchone()["m"]
    end = conn.execute("SELECT body FROM trace_event WHERE run_id=? AND kind='run.end'",
                       (run_id,)).fetchone()
    metrics = {r["key"][6:]: r["value"] for r in conn.execute(
        "SELECT key, value FROM run_metrics WHERE run_id=? AND key LIKE 'trace\\_%' "
        "ESCAPE '\\'", (run_id,))}
    run_end = json.loads(end["body"]).get("status") if end else None
    warnings = []
    if not kinds:
        state = "empty"
        warnings.append("no trace events for this run (recorded before FR-CORE-505, "
                        "or nothing ran)")
    elif run_end is None:
        state = "partial"
        warnings.append("no run end recorded: the run is still writing, or stopped "
                        "without recording its end")
    elif run_end != "complete":
        state = "partial"
        warnings.append(f"the run ended {run_end}: results are partial")
    else:
        state = "complete"
    if metrics.get("dropped"):
        state = "partial"
        warnings.append(f"{int(metrics['dropped'])} trace event(s) could not be written")
    return {"run_id": run_id, "state": state, "events": sum(kinds.values()),
            "by_kind": kinds, "last_event_id": last, "run_end": run_end,
            "recorder": metrics, "warnings": warnings,
            "unsupported": [
                "server-side components, stores and internal calls: never observable "
                "from traffic, never drawn",
                "browser-only (M6) and out-of-band (M8) confirmations record their HTTP "
                "sends only; the browser's own steps inside them are not traced"]}


# --- data flow ---------------------------------------------------------------------------
def dataflow(conn, run_id: int, *, overlay: bool = False, origin: str | None = None,
             knowledge: str | None = None, finding: int | None = None) -> dict:
    """The data-flow model (module docstring). Filters: ``origin`` (canonical),
    ``knowledge`` (observed / inferred / unknown), ``finding`` (the interface the
    finding's own event names, its origin and the application, and every flow into it
    with that flow's source: the flows `finding_links` lists); ``overlay`` adds the
    testing view's flows."""
    counts = _evidence_counts(conn, run_id)
    entities = {}
    for r in conn.execute("SELECT * FROM dg_entity WHERE run_id=? ORDER BY eid",
                          (run_id,)):
        entities[r["eid"]] = {"id": r["eid"], "kind": r["kind"], "label": r["label"],
                              "parent": r["parent"], "knowledge": r["knowledge"],
                              "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                              "attrs": _attrs(r), "observations": counts.get(r["eid"], 0)}
    flows = []
    for r in conn.execute("SELECT * FROM dg_flow WHERE run_id=? ORDER BY fid", (run_id,)):
        if r["view"] == "test" and not overlay:
            continue
        flows.append({"id": r["fid"], "src": r["src"], "dst": r["dst"], "view": r["view"],
                      "protocol": r["protocol"], "direction": "request/response"
                      if r["protocol"] == "http" else "never sent"
                      if r["protocol"] == "blocked" else "bidirectional messages",
                      "knowledge": r["knowledge"], "first_seen": r["first_seen"],
                      "last_seen": r["last_seen"], "attrs": _attrs(r),
                      "observations": counts.get(r["fid"], 0)})
    coverage = interface_coverage(conn, run_id)
    for eid, cov in coverage.items():
        if eid in entities:
            entities[eid]["coverage"] = cov
    keep = set(entities)
    if origin:
        oid = trace.origin_id(origin)
        keep = {e for e, n in entities.items()
                if e == oid or n["parent"] == oid or n["kind"] in ("actor", "tool",
                                                                   "application")}
    if knowledge:
        keep = {e for e in keep if entities[e]["knowledge"] == knowledge
                or entities[e]["kind"] in ("application", "origin")}
    if finding is not None:
        # the finding's own relation (its event names its interface), as `finding_links`
        # and the finding's sequence read it -- never the capped ``attrs.finding`` and
        # never a list of actor ids (BUG-0519): the interface, its parent chain, and the
        # source of every flow into it. Intersected with ``keep``, so only the run's own
        # entities are drawn.
        links = finding_links(conn, run_id, finding)
        iface = links["interface"] if links else None
        chain: set[str] = set()
        e = iface
        while e in entities and e not in chain:
            chain.add(e)
            e = entities[e]["parent"]
        keep &= chain | {f["src"] for f in flows if f["dst"] == iface}
    nodes = [entities[e] for e in sorted(keep)]
    flows = [f for f in flows if f["src"] in keep and f["dst"] in keep]
    boundaries = [{
        "id": "boundary:client-server",
        "label": "client / server (network)",
        "inside": [trace.BROWSER, trace.EXPLORER, trace.SPIDER],
        "basis": "observed: every application flow crosses a network connection from "
                 "the browser; how origins group into trust zones is unknown (a shared "
                 "or different host name is not evidence of either)"}, {
        "id": "boundary:testing",
        "label": "testing infrastructure (not part of the application)",
        "inside": [trace.TOOL, trace.EXPLORER, trace.SPIDER],
        "basis": "explicit configuration: fuzzlab's own processes"}]
    # every origin of the run, whatever the filters: the page's origin list
    origins = sorted(n["label"] for n in entities.values() if n["kind"] == "origin")
    return {"schema": SCHEMA, "run_id": run_id, "overlay": overlay, "nodes": nodes,
            "flows": flows, "boundaries": boundaries, "origins": origins,
            "status": status(conn, run_id)}


def interface_coverage(conn, run_id: int) -> dict[str, dict]:
    """Per interface, what happened to it, each state counted separately (`COVERAGE`).
    The fields are read in SQL (``json_extract``), never by parsing whole bodies."""
    out: dict[str, dict] = {}

    def bump(eid, state, n=1):
        out.setdefault(eid, dict.fromkeys(COVERAGE, 0))[state] += n

    rows = conn.execute(
        "SELECT kind, json_extract(body,'$.origin') o, json_extract(body,'$.method') m, "
        "json_extract(body,'$.url') u, json_extract(body,'$.test') test, "
        "json_extract(body,'$.src') src, json_extract(body,'$.status') status, "
        "json_extract(body,'$.outcome') outcome, json_extract(body,'$.role') role, "
        "COUNT(*) n FROM trace_event "
        "WHERE run_id=? AND kind IN ('observe.exchange','observe.page','test.start',"
        "'exchange','test.strategy','finding') GROUP BY kind, o, m, u, test, src, "
        "status IS NULL, outcome, role", (run_id,)).fetchall()
    tests: dict[str, str] = {}
    for r in rows:
        if r["kind"] == "test.start" and r["o"]:
            tests[r["test"]] = trace.interface_id(r["o"], r["m"], r["u"] or "")
    for r in rows:
        kind, n = r["kind"], r["n"]
        if kind in ("observe.exchange", "observe.page") and r["o"]:
            eid = trace.interface_id(r["o"], r["m"], r["u"] or "")
            bump(eid, "discovered", n)
            # browser traffic answered: disco's capture or the intercepting proxy
            if r["src"] in ("capture", "proxy") and r["status"] is not None:
                bump(eid, "captured", n)
        elif kind == "test.start" and r["test"] in tests:
            bump(tests[r["test"]], "scheduled", n)
        elif kind == "exchange" and r["test"] in tests and \
                r["role"] not in _NOT_A_TEST_SEND and r["outcome"] != "not_sent":
            # a test's own sends, answered or not, on the test's interface (BUG-0515)
            bump(tests[r["test"]], "executed", n)
        elif kind == "test.strategy" and r["test"] in tests and \
                r["outcome"] in ("confirmed", "not_confirmed", "inconclusive"):
            bump(tests[r["test"]], "evaluated", n)
        elif kind == "finding" and r["o"]:
            bump(trace.interface_id(r["o"], r["m"], r["u"] or ""), "finding", n)
    return out


# --- evidence ------------------------------------------------------------------------------
def evidence(conn, run_id: int, ref: str, *, limit: int = 100, after: int = 0) -> dict:
    """The events supporting a diagram entity or flow (``ref``), or one event by key."""
    rows = conn.execute(
        "SELECT e.id, e.key, e.kind, e.scope, e.seq, e.t, e.body FROM trace_event e "
        "JOIN dg_evidence d ON d.run_id=e.run_id AND d.event_key=e.key "
        "WHERE e.run_id=? AND d.ref=? AND e.id>? ORDER BY e.id LIMIT ?",
        (run_id, ref, after, limit + 1)).fetchall()
    if not rows:
        rows = conn.execute("SELECT id, key, kind, scope, seq, t, body FROM trace_event "
                            "WHERE run_id=? AND key=?", (run_id, ref)).fetchall()
    items = [{"id": r["id"], "key": r["key"], "kind": r["kind"], "scope": r["scope"],
              "seq": r["seq"], "t": r["t"], "body": json.loads(r["body"])}
             for r in rows[:limit]]
    return {"ref": ref, "items": items,
            "next": items[-1]["id"] if len(rows) > limit else None}


def finding_links(conn, run_id: int, finding_id: int) -> dict | None:
    """A finding's test, strategy, the exact exchanges it cites, its interface and the
    flows touching it."""
    row = conn.execute("SELECT body FROM trace_event WHERE run_id=? AND key=?",
                       (run_id, f"finding:{finding_id}")).fetchone()
    if row is None:
        return None
    b = json.loads(row["body"])
    iface = trace.interface_id(b.get("origin") or "", b.get("method"), b.get("url") or "")
    flows = [r["fid"] for r in conn.execute(
        "SELECT fid FROM dg_flow WHERE run_id=? AND dst=?", (run_id, iface))]
    return {"finding_id": finding_id, "test": b.get("test"), "strategy": b.get("strategy"),
            "mechanism": b.get("mechanism"), "vuln_class": b.get("vuln_class"),
            "exchanges": b.get("exchanges") or [], "interface": iface, "flows": flows,
            "sequence_scope": f"finding:{finding_id}"}


# --- a finding's diagrams: can they be opened, and the link to them (FR-UI-513) ----------
#: The largest run or finding id a diagram link carries: the largest integer a browser's
#: script holds exactly (2^53-1), one bound for the builder, the parser and the page.
MAX_LINK_ID = 2 ** 53 - 1
_LINK_ID = re.compile(r"[1-9][0-9]{0,15}")
_DIAGRAM_STATES = """
SELECT f.id, f.run_id,
       EXISTS (SELECT 1 FROM trace_event t WHERE t.run_id = f.run_id) AS run_traced,
       e.id IS NOT NULL AS has_event,
       COALESCE(json_extract(e.body, '$.test'), '') <> '' AS has_test,
       COALESCE(json_extract(e.body, '$.origin'), '') <> '' AS has_origin
FROM finding f
LEFT JOIN trace_event e ON e.run_id = f.run_id AND e.key = 'finding:' || f.id
WHERE f.id IN (SELECT value FROM json_each(?))"""


def finding_diagram_states(conn, finding_ids) -> dict[int, dict]:
    """Whether each finding's sequence and data flow can be opened, by the relations those
    views read: the finding's run, the run's trace, and the finding's own event
    (``finding:<id>``) with its test (the sequence) and its origin (the interface).

    Returns ``{finding_id: {"run_id", "available", "reason"}}`` for the ids that exist;
    ``reason`` is None when available, else ``no-trace`` (the run has no trace events:
    recorded before FR-CORE-505, or with ``--no-trace``), ``not-recorded`` (no event for
    the finding: its batch was dropped) or ``incomplete`` (the event names no test or no
    origin). One read-only query."""
    ids = [int(i) for i in finding_ids]
    if not ids:
        return {}
    out = {}
    for r in conn.execute(_DIAGRAM_STATES, (json.dumps(ids),)):
        reason = (None if r["has_event"] and r["has_test"] and r["has_origin"] else
                  "no-trace" if not r["run_traced"] else
                  "not-recorded" if not r["has_event"] else "incomplete")
        out[r["id"]] = {"run_id": r["run_id"], "available": reason is None,
                        "reason": reason}
    return out


def finding_deep_link(run_id: int, finding_id: int) -> str:
    """The Diagrams page's link to one finding's sequence and data flow (FR-UI-513). The
    one builder; `parse_deep_link` is the one parser. Both values are checked ``int``s in
    range, so their decimal form needs no encoding."""
    for value in (run_id, finding_id):
        if type(value) is not int or not 1 <= value <= MAX_LINK_ID:
            raise ValueError("a diagram link carries ids from 1 to 2^53-1")
    return f"/diagrams?run={run_id}&finding={finding_id}"


class DeepLinkError(ValueError):
    """A malformed diagram link; ``param`` names the parameter (never its value)."""

    def __init__(self, param: str) -> None:
        super().__init__(f"bad diagram link: {param}")
        self.param = param


def parse_deep_link(items) -> tuple[int, int] | None:
    """The Diagrams page's query (``(key, value)`` pairs) as ``(run, finding)``, or None
    when it carries neither. Both are required, each exactly once, each a decimal integer
    from 1 to `MAX_LINK_ID` with no sign, space or leading zero; anything else raises
    `DeepLinkError`. Other keys are not read."""
    items = list(items)
    runs = [v for k, v in items if k == "run"]
    finds = [v for k, v in items if k == "finding"]
    if not runs and not finds:
        return None
    for name, values in (("run", runs), ("finding", finds)):
        if (len(values) != 1 or not _LINK_ID.fullmatch(values[0])
                or int(values[0]) > MAX_LINK_ID):
            raise DeepLinkError(name)
    return int(runs[0]), int(finds[0])


# --- sequences ------------------------------------------------------------------------------
def scopes(conn, run_id: int) -> list[dict]:
    """The sequence scopes the run has: tests, captured workflows, the spider trace,
    findings."""
    out = []
    for r in conn.execute("SELECT body FROM trace_event WHERE run_id=? AND "
                          "kind='test.start' ORDER BY seq", (run_id,)):
        b = json.loads(r["body"])
        out.append({"scope": f"test:{b['test']}", "kind": "test",
                    "label": f"{b['test']}: {b.get('method')} "
                             f"{_short(b.get('url'))} {b.get('param')} "
                             f"({b.get('category') or '-'})"})
    for r in conn.execute("SELECT scope, COUNT(*) n FROM trace_event WHERE run_id=? AND "
                          "scope LIKE 'workflow:%' GROUP BY scope ORDER BY MIN(seq)",
                          (run_id,)):
        out.append({"scope": r["scope"], "kind": "workflow",
                    "label": f"{r['scope'][9:]} ({r['n']} event(s))"})
    for scope, label in (("capture", "capture records with no action (uncorrelated)"),
                         ("spider", "spider exploration (crawl order)"),
                         ("proxy", "proxied traffic (intercepting proxy)")):
        n = conn.execute("SELECT COUNT(*) n FROM trace_event WHERE run_id=? AND scope=?",
                         (run_id, scope)).fetchone()["n"]
        if n:
            out.append({"scope": scope, "kind": scope, "label": f"{label}: {n}"})
    for r in conn.execute("SELECT key, body FROM trace_event WHERE run_id=? AND "
                          "kind='finding' ORDER BY seq", (run_id,)):
        b = json.loads(r["body"])
        out.append({"scope": r["key"], "kind": "finding",
                    "label": f"finding {b.get('finding_id')}: {b.get('vuln_class')} "
                             f"{_short(b.get('url'))} {b.get('param')}"})
    return out


def _short(url) -> str:
    from urllib.parse import urlsplit
    p = urlsplit(url or "")
    return (p.path or "/") + (f"#{p.fragment}" if p.fragment else "")


def _rows(conn, run_id, where, args):
    return [dict(r) | {"body": json.loads(r["body"])} for r in conn.execute(
        f"SELECT id, key, kind, scope, seq, t, body FROM trace_event WHERE run_id=? AND "
        f"{where} ORDER BY seq, id", (run_id, *args))]


def sequence(conn, run_id: int, scope: str) -> dict:
    """The sequence for one scope (module docstring)."""
    kind, _sep, ident = scope.partition(":")
    if kind == "test":
        return _test_sequence(conn, run_id, ident, scope)
    if kind == "finding":
        if not ident.isdigit():
            return {"scope": scope, "error": "bad scope: a finding is a number"}
        return _finding_sequence(conn, run_id, int(ident), scope)
    if kind == "workflow":
        return _capture_sequence(conn, run_id, _rows(conn, run_id, "scope=?", [scope]),
                                 scope, correlated=True)
    if kind == "capture":
        return _capture_sequence(conn, run_id, _rows(conn, run_id, "scope=?", ["capture"]),
                                 scope, correlated=False)
    if kind == "spider":
        return _spider_sequence(_rows(conn, run_id, "scope=?", ["spider"]), scope)
    if kind == "proxy":
        return _proxy_sequence(_rows(conn, run_id, "scope=?", ["proxy"]), scope)
    if kind == "exchange":
        # the exchange, its follow-up and retries, and the follow-up's retries
        rows = _rows(conn, run_id, "(key=? OR json_extract(body,'$.parent')=? OR "
                     "json_extract(body,'$.parent') IN (SELECT key FROM trace_event "
                     "WHERE run_id=? AND json_extract(body,'$.parent')=?))",
                     [scope, scope, run_id, scope])
        return _exchange_steps(rows, scope,
                               "a single exchange, its retries and its follow-ups")
    return {"scope": scope, "error": "unknown scope"}


class _Seq:
    def __init__(self, scope, basis):
        self.scope = scope
        self.participants: dict[str, dict] = {}
        self.steps: list[dict] = []
        self.notes: list[str] = [basis]
        self.truncated = 0

    def party(self, pid, label, kind):
        self.participants.setdefault(pid, {"id": pid, "label": label, "kind": kind})
        return pid

    def step(self, **step):
        if len(self.steps) >= MAX_STEPS:
            self.truncated += 1
            return
        self.steps.append(step)

    def out(self):
        doc = {"scope": self.scope, "participants": list(self.participants.values()),
               "steps": self.steps, "notes": self.notes}
        if self.truncated:
            doc["truncated"] = self.truncated
            doc["notes"].append(f"{self.truncated} step(s) beyond {MAX_STEPS} not shown")
        return doc


def _origin_party(seq: _Seq, origin) -> str:
    return seq.party(f"origin:{origin}", origin or "(unknown origin)", "target")


def _redirect(b: dict) -> str | None:
    """A response's redirect target: ``redirect`` (BUG-0517), or, in an event written
    before it, a ``location`` holding a path (an injection location is one word)."""
    if b.get("redirect"):
        return b["redirect"]
    loc = b.get("location")
    return loc if isinstance(loc, str) and "/" in loc else None


def _exchange_pair(seq: _Seq, row: dict, src: str) -> None:
    """One tool exchange: the request, then what came back -- or a lost arrow."""
    b = row["body"]
    dst = _origin_party(seq, b.get("origin"))
    value = b.get("value_preview")
    shown = f" {b.get('param')}={value!r}" if value is not None and b.get("param") \
        else (f" {b.get('param')}=(withheld)" if b.get("param") else "")
    role = b.get("role")
    if role == "retry" and b.get("attempt"):
        role = f"retry, try {b['attempt']}"            # an earlier try (FR-FUZZ-61)
    seq.step(type="message", src=src, dst=dst, kind="request", role=b.get("role"),
             label=f"[{role}] {b.get('method')} {_short(b.get('url'))}{shown}",
             evidence=[row["key"]])
    outcome = b.get("outcome")
    if outcome == "response":
        extra = f" → {_short(_redirect(b))}" if _redirect(b) else ""
        seq.step(type="message", src=dst, dst=src, kind="response",
                 label=f"{b.get('status')} ({b.get('elapsed_ms')} ms){extra}",
                 evidence=[row["key"]])
    elif outcome == "not_sent":
        seq.step(type="note", over=[src], kind="tool",
                 label="not sent: the tool refused to place it", evidence=[row["key"]])
    else:
        seq.step(type="lost", src=dst, dst=src, kind="no-response",
                 label=f"{outcome or 'no response'}"
                       f"{(' (' + b['error'] + ')') if b.get('error') else ''}",
                 evidence=[row["key"]])


def _exchange_steps(rows, scope, basis) -> dict:
    seq = _Seq(scope, basis)
    tool = seq.party("tool", "Fuzzer (tool)", "tool")
    for row in rows:
        if row["kind"] == "exchange":
            _exchange_pair(seq, row, tool)
    return seq.out()


def _test_sequence(conn, run_id, test_id, scope, only_strategy=None) -> dict:
    rows = _rows(conn, run_id, "scope=?", [f"test:{test_id}"])
    seq = _Seq(scope, "correlation: explicit test and strategy scopes recorded at the "
                      "execution point; order: the recorder's sequence")
    tool = seq.party("tool", "Fuzzer (tool)", "tool")
    ev = seq.party("evaluator", "Evaluator (tool)", "annotation")
    run = []                                    # a run of same-role exchanges to collapse

    def flush_run():
        if len(run) > COLLAPSE_AFTER:
            first = run[0]
            statuses = sorted({str(r["body"].get("status") or r["body"].get("outcome"))
                               for r in run})
            seq.step(type="group", kind="collapsed", count=len(run),
                     label=f"{len(run)} × [{first['body'].get('role')}] exchanges "
                           f"({first['body'].get('strategy')}); outcomes: "
                           f"{', '.join(statuses)}",
                     evidence=[r["key"] for r in run])
            _exchange_pair(seq, first, tool)
        else:
            for r in run:
                _exchange_pair(seq, r, tool)
        run.clear()

    for row in rows:
        b = row["body"]
        if only_strategy and b.get("strategy") not in (None, only_strategy) and \
                row["kind"] in ("exchange", "test.strategy"):
            continue
        if row["kind"] == "exchange":
            key = (b.get("strategy"), b.get("role"))
            if run and (run[-1]["body"].get("strategy"), run[-1]["body"].get("role")) \
                    != key:
                flush_run()
            run.append(row)
            continue
        flush_run()
        if row["kind"] == "test.start":
            seq.step(type="note", over=[tool], kind="tool",
                     label=f"test {test_id}: {b.get('method')} {_short(b.get('url'))} "
                           f"{b.get('param')} ({b.get('location')}), "
                           f"{b.get('category') or '-'}", evidence=[row["key"]])
        elif row["kind"] == "test.strategy":
            seq.step(type="note", over=[ev], kind="evaluation",
                     label=f"{b.get('strategy')}: {b.get('outcome')}"
                           f"{(' — ' + b['detail']) if b.get('detail') else ''}",
                     evidence=[row["key"]] + list(b.get("exchanges") or []))
        elif row["kind"] == "finding":
            seq.step(type="note", over=[ev], kind="finding",
                     label=f"finding {b.get('finding_id')} created: {b.get('vuln_class')} "
                           f"({b.get('mechanism')}) — a tool record, not a target "
                           f"response", evidence=[row["key"]] + list(b.get("exchanges")
                                                                       or []))
        elif row["kind"] == "test.end":
            seq.step(type="note", over=[ev], kind="evaluation",
                     label=f"test {test_id} ended: {b.get('outcome')}",
                     evidence=[row["key"]])
    flush_run()
    if not rows:
        seq.notes.append("no events for this test")
    return seq.out()


def _finding_sequence(conn, run_id, finding_id, scope) -> dict:
    links = finding_links(conn, run_id, finding_id)
    if links is None or not links["test"]:
        return {"scope": scope, "error": "no trace for this finding"}
    doc = _test_sequence(conn, run_id, links["test"], scope,
                         only_strategy=links["strategy"])
    doc["notes"].append(f"filtered to strategy {links['strategy']}; the finding cites "
                        f"{len(links['exchanges'])} exchange(s)")
    doc["finding"] = links
    return doc


def _capture_sequence(conn, run_id, rows, scope, *, correlated: bool) -> dict:
    seq = _Seq(scope, "correlation: the explorer's action id tagged on each request "
                      "(x-disco-action); order within the action: capture time"
               if correlated else
               "uncorrelated: these records carry no action id; ordered by capture time "
               "only, which does not establish causality")
    actor = seq.party("explorer", "Explorer (automated browser user)", "tool") \
        if correlated else None
    browser = seq.party("browser", "Browser", "actor")
    proxy = seq.party("proxy", "Capture proxy (tool)", "tool")
    # the action first: every record here carries its tag, i.e. it was made by it
    rows = sorted(rows, key=lambda r: (r["kind"] != "observe.action", r["t"] is None,
                                       r["t"] or 0, r["seq"]))
    for row in rows:
        b = row["body"]
        if row["kind"] == "observe.action" and actor:
            seq.step(type="message", src=actor, dst=browser, kind="action",
                     label=f"{b.get('kind')}: {b.get('label') or ''} "
                           f"{_short(b.get('url') or b.get('route'))}",
                     evidence=[row["key"]])
        elif row["kind"] == "observe.exchange":
            dst = _origin_party(seq, b.get("origin"))
            if b.get("ws"):
                src, to = (browser, dst) if b["ws"] == "client" else (dst, browser)
                seq.step(type="message", src=src, dst=to, kind="ws",
                         label=f"WebSocket message ({b['ws']})", evidence=[row["key"]])
                continue
            seq.step(type="message", src=browser, dst=proxy, kind="request",
                     label=f"{b.get('method')} {_short(b.get('url'))}",
                     evidence=[row["key"]])
            seq.step(type="message", src=proxy, dst=dst, kind="forward",
                     label="forwarded", evidence=[row["key"]])
            if b.get("status") is not None:
                extra = f" → {_short(_redirect(b))}" if _redirect(b) else ""
                seq.step(type="message", src=dst, dst=proxy, kind="response",
                         label=f"{b.get('status')}{extra}", evidence=[row["key"]])
                seq.step(type="message", src=proxy, dst=browser, kind="response",
                         label=f"{b.get('status')}", evidence=[row["key"]])
            else:
                seq.step(type="lost", src=dst, dst=proxy, kind="no-response",
                         label=f"no response ({b.get('error') or 'unknown'})",
                         evidence=[row["key"]])
    return seq.out()


def _spider_sequence(rows, scope) -> dict:
    seq = _Seq(scope, "order: the spider's row order (crawl order: pages, then captured "
                      "requests); 'from' names the page whose load queued a page "
                      "(FR-CRAWL-29); a step's time, when recorded, is when the page's "
                      "load began or the request was captured. Both are unknown in a "
                      "spider DB from before FR-CRAWL-29")
    spider = seq.party("spider", "Spider (tool)", "tool")
    for row in rows:
        b = row["body"]
        dst = _origin_party(seq, b.get("origin"))
        label = f"{b.get('method')} {_short(b.get('url'))} [{b.get('via')}]"
        if b.get("referer"):
            label += f" from {b['referer']}"
        if b.get("delivery") and b["delivery"] != "sent":
            seq.step(type="lost", src=spider, dst=dst, kind="blocked",
                     label=label + " — blocked in the browser, never sent",
                     evidence=[row["key"]])
            continue
        seq.step(type="message", src=spider, dst=dst, kind="request", label=label,
                 evidence=[row["key"]])
        status = b.get("status") or None            # 0 in an older event: no reply
        if status is not None:
            seq.step(type="message", src=dst, dst=spider, kind="response",
                     label=str(status), evidence=[row["key"]])
        elif b.get("by") == "crawler" or "discovered_pages" in str(b.get("ref")):
            seq.step(type="lost", src=dst, dst=spider, kind="no-response",
                     label=b.get("outcome") or "no response recorded",
                     evidence=[row["key"]])
    return seq.out()


def _proxy_sequence(rows, scope) -> dict:
    """Traffic through the intercepting proxy (FR-UI-512): per recorded flow, the
    browser's request, the proxy's forward (or the operator's drop), the origin's reply
    or a lost arrow, and the proxy's reply to the browser. The interception decisions
    shown are only those the proxy recorded (``intercept``)."""
    seq = _Seq(scope, "order: the time the intercepting proxy received each request, "
                      "then the recorder's sequence; each flow is one exchange, and no "
                      "causality between flows is implied")
    browser = seq.party("browser", "Browser / client", "actor")
    proxy = seq.party("proxy", "Intercepting proxy (tool)", "tool")
    rows = sorted((r for r in rows if r["kind"] == "observe.exchange"),
                  key=lambda r: (r["t"] is None, r["t"] or 0, r["seq"]))
    untimed = sum(1 for r in rows if r["t"] is None)
    if untimed:
        seq.notes.append(f"{untimed} flow(s) with no recorded time are shown last, in "
                         f"the recorder's sequence")
    for row in rows:
        b, ev = row["body"], [row["key"]]
        intercept = str(b.get("intercept") or "")
        label = f"{b.get('method')} {_short(b.get('url'))}"
        if b.get("profile"):
            label += f" [{b['profile']}]"
        seq.step(type="message", src=browser, dst=proxy, kind="request", label=label,
                 evidence=ev)
        if "request dropped" in intercept or intercept.strip() == "dropped":
            seq.step(type="note", over=[proxy], kind="intercept",
                     label="dropped by the operator: never forwarded", evidence=ev)
            continue
        dst = _origin_party(seq, b.get("origin"))
        edited = "request edited" in intercept or intercept.strip() == "edited"
        seq.step(type="message", src=proxy, dst=dst, kind="forward",
                 label="forwarded" + (" (edited by the operator)" if edited else ""),
                 evidence=ev)
        if b.get("status") is None and not str(b.get("outcome") or "").startswith(
                "response"):
            seq.step(type="lost", src=dst, dst=proxy, kind="no-response",
                     label=f"no response ({b.get('error') or 'connection closed'})",
                     evidence=ev)
            continue
        shown = str(b["status"]) if b.get("status") is not None else "no status line"
        extra = f" → {_short(_redirect(b))}" if _redirect(b) else ""
        resp_edited = "response edited" in intercept
        # the proxy records the response it sent on: after an edit, not the origin's
        seq.step(type="message", src=dst, dst=proxy, kind="response",
                 label="response (the origin's original is not recorded)" if resp_edited
                 else f"{shown}{extra}", evidence=ev)
        if "response dropped" in intercept:
            seq.step(type="note", over=[proxy], kind="intercept",
                     label="response dropped by the operator: not sent to the browser",
                     evidence=ev)
            continue
        if resp_edited:
            seq.step(type="note", over=[proxy], kind="intercept",
                     label="response edited by the operator", evidence=ev)
        seq.step(type="message", src=proxy, dst=browser, kind="response",
                 label=f"{shown}{extra}" if resp_edited else shown, evidence=ev)
    return seq.out()


# --- exports ------------------------------------------------------------------------------
_SAFE = re.compile(r"[A-Za-z0-9 ./_\-{}()?=,+@]")


def mermaid_text(text, limit: int = 120) -> str:
    """``text`` as a Mermaid label: newlines folded, cut at ``limit``, every character
    outside a safe alphabet written as a numeric entity (``#NN;``), so no captured
    string can close a label, open a link or start a directive."""
    raw = " ".join(str(text if text is not None else "").split())
    if len(raw) > limit:
        raw = raw[:limit] + "…"
    return "".join(ch if _SAFE.fullmatch(ch) else f"#{ord(ch)};" for ch in raw)


def mermaid_flow(model: dict) -> str:
    """The data-flow model as a Mermaid ``flowchart``: origins as subgraphs inside the
    application, interfaces inside their origin, flows labelled with protocol and
    observation count; inferred nodes and flows dashed."""
    ids: dict[str, str] = {}

    def nid(eid):
        return ids.setdefault(eid, f"n{len(ids) + 1}")

    lines = ["flowchart LR"]
    nodes = {n["id"]: n for n in model["nodes"]}
    children: dict[str | None, list] = {}
    for n in model["nodes"]:
        children.setdefault(n["parent"] if n["parent"] in nodes else None, []).append(n)

    def emit(node, depth):
        pad = "  " * depth
        label = mermaid_text(f"{node['label']} [{node['knowledge']}]")
        if children.get(node["id"]):
            lines.append(f'{pad}subgraph {nid(node["id"])}["{label}"]')
            for child in children[node["id"]]:
                emit(child, depth + 1)
            lines.append(f"{pad}end")
        else:
            shape = ('(["{}"])' if node["kind"] in ("actor", "tool") else
                     '[/"{}"/]' if node["kind"] == "external" else '["{}"]')
            lines.append(f"{pad}{nid(node['id'])}{shape.format(label)}")

    for top in children.get(None, []):
        emit(top, 1)
    for f in model["flows"]:
        # a request refused or blocked before sending is never drawn as traffic
        refused = bool(f["attrs"].get("refused"))
        arrow = "-.->" if refused or f["knowledge"] != "observed" or f["view"] == "test" \
            else "-->"
        if refused:
            text = (f"{'blocked' if f['protocol'] == 'blocked' else 'refused'}, never "
                    f"sent ×{f['observations']}")
        else:
            text = (f"{f['protocol']} ×{f['observations']}"
                    f"{' (test)' if f['view'] == 'test' else ''}")
        label = mermaid_text(text)
        lines.append(f"  {nid(f['src'])} {arrow}|\"{label}\"| {nid(f['dst'])}")
    return "\n".join(lines) + "\n"


def mermaid_sequence(seq: dict) -> str:
    """A sequence as a Mermaid ``sequenceDiagram``: lost responses use the cross arrow,
    collapsed exchanges a ``loop`` around their representative, notes stay notes."""
    if seq.get("error"):
        return f"%% {mermaid_text(seq['error'])}\n"
    pid = {p["id"]: f"p{i + 1}" for i, p in enumerate(seq["participants"])}
    lines = ["sequenceDiagram"]
    for p in seq["participants"]:
        lines.append(f"  participant {pid[p['id']]} as {mermaid_text(p['label'], 60)}")
    pending_loop = 0
    for s in seq["steps"]:
        if s["type"] == "group":
            lines.append(f"  loop {mermaid_text(s['label'])}")
            pending_loop = 2                   # its representative request + reply
            continue
        if s["type"] == "note":
            over = ",".join(pid[o] for o in s["over"])
            lines.append(f"  Note over {over}: {mermaid_text(s['label'])}")
        else:
            arrow = {"message": "->>", "lost": "-x"}[s["type"]]
            if s.get("kind") == "response":
                arrow = "-->>"
            lines.append(f"  {pid[s['src']]}{arrow}{pid[s['dst']]}: "
                         f"{mermaid_text(s['label'])}")
        if pending_loop:
            pending_loop -= 1
            if pending_loop == 0:
                lines.append("  end")
    if pending_loop:
        lines.append("  end")
    return "\n".join(lines) + "\n"


def export_json(conn, run_id: int) -> dict:
    """The full model: the data flow (with the testing overlay), every sequence scope's
    index, each entity's and flow's evidence keys, and the completeness status."""
    model = dataflow(conn, run_id, overlay=True)
    refs: dict[str, list[str]] = {}
    for r in conn.execute("SELECT ref, event_key FROM dg_evidence WHERE run_id=? "
                          "ORDER BY ref, event_key", (run_id,)):
        refs.setdefault(r["ref"], []).append(r["event_key"])
    for item in model["nodes"] + model["flows"]:
        item["evidence"] = refs.get(item["id"], [])
    model["sequences"] = scopes(conn, run_id)
    return model
