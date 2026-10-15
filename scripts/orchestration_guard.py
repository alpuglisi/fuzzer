#!/usr/bin/env python3
"""Progress governance for autonomous, multi-agent work on this repository (BUG-0141, BUG-0156).

An orchestrating session once ran for about 15 hours, dispatching review round
after review round and follow-up after follow-up, while the goal metric
(confirmed Juice Shop findings) moved by one. It never measured progress against
the goal. When the stall was visible it did not investigate or fix it, and it
never told the user until they intervened. PA-0020's lesson applies: a rule
addressed to the same process that failed is not prevention. This script is the mechanical
half of PA-0141..PA-0147 and of ``docs/QUALITY_POLICY.md`` L11/R1; Claude Code hooks call
it (``.claude/settings.json``).

The **ledger** (``.claude/orchestration/ledger.json`` in the main checkout,
git-ignored) holds one goal with a measurable metric, its checkpoints, the work
items dispatched for it, the decisions that lifted holds and the history of earlier
goals. The hooks read the ledger plus the session transcript, which holds the user's
real messages and the session's own PushNotification calls.

**Contact is not a decision (BUG-0156).** The first version let any later user
message (a status question included) clear every hold and restart every clock. Now a
hold is lifted only by a **decision** recorded with ``decide``, which names the hold
(and item) and quotes the user's own words. A decision counts only while a real user
message after the hold began contains that quote; the report shows each decision and
whether it is verified. A decision lifts only the hold it names, and an extension
adds to the budget without erasing the spend.

Triggers (defaults in ``DEFAULT_CONFIG``):

* **checkpoint due**: more than ``checkpoint_hours`` of unattended work since the
  last checkpoint or user message. The Stop hook blocks until ``checkpoint`` is run.
* **stall**: the metric has not improved for ``stall_hours`` since the goal opened
  or its last improvement. User contact does not restart this clock. Only a process
  or measurement item opened after the stall (to find out why the metric is not
  moving and fix that) may be dispatched; the Stop hook requires a PushNotification.
  A verified ``decide --hold stall --hours H`` suspends the gate for H hours.
* **review-round cap**: ``review_round_cap`` review rounds for one item. A round is
  the set of review requests sent between two work dispatches for the item (two
  reviewers in parallel are one round, at most ``round_request_cap`` requests). A
  verified ``decide --hold review --rounds N`` allows N more rounds.
* **item budget**: cumulative active time on an item (across close/reopen and
  ``--continues`` renames) beyond ``--budget-hours`` plus verified ``decide --hold
  budget --hours H`` extensions. An item with a ``--hypothesis`` that overruns its
  base budget also needs an ``item disposition`` (R1).
* **self-originated scope**: an item the session opened itself (``--origin self``)
  that is not a defect blocking an active item. Dispatchable only after a verified
  ``decide --hold scope``.
* **bug chain** (R1, the systemic-diagnosis trigger): ``bug_chain_limit`` bugs
  spawned by one item's fixes since its last disposition. Dispatch for that item and
  its bugs is denied until ``item disposition`` records the class (isolated-defect,
  missing-shared-contract, capability-gap, unresolved-hypothesis), the evidence and
  the next action. This is the delivery owner's decision, not the user's.
* **WIP limit / file overlap**: ``item add`` refuses more than ``wip_limit``
  active items, or declared files overlapping another active item's without
  ``--after``. ``audit`` (also run by the Stop hook) compares the active items'
  real branch diffs.

Usage::

    scripts/orchestration_guard.py goal open --text "..." --metric "confirmed findings" \\
        --baseline 6 --evidence run.out [--reviewer <agent-id> ...]
    scripts/orchestration_guard.py goal close|reopen
    scripts/orchestration_guard.py checkpoint --value 7 --evidence run.out --note "..."
    scripts/orchestration_guard.py item add FR-X-1 --title "..." --kind feature \\
        --origin user --hypothesis "<prediction; effort ceiling; exit decision>" \\
        [--files a.py,b/] [--branch b --base ref] [--spawned-by ID] [--continues OLD]
    scripts/orchestration_guard.py item done|drop|reopen FR-X-1
    scripts/orchestration_guard.py item disposition FR-X-1 --class capability-gap \\
        --evidence "<store rows / log / reproduction>" --next "<action; prediction; budget>"
    scripts/orchestration_guard.py decide --hold budget --item FR-X-1 --hours 2 \\
        --quote "<the user's words>"
    scripts/orchestration_guard.py report
    scripts/orchestration_guard.py check [--transcript PATH]
    scripts/orchestration_guard.py hook stop|pretooluse|sessionstart   (stdin: hook JSON)

Every dispatch (Agent, SendMessage, Workflow, remote create_session/send_message)
must carry ``[item: <ID>]`` while a goal is open. A review request also carries
``[review]``, or goes to a reviewer registered with ``--reviewer``. Messages that
start with ``STOP`` and read-only agent types are exempt.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_CONFIG = {
    "checkpoint_hours": 3.0,
    "stall_hours": 6.0,
    "review_round_cap": 3,
    "round_request_cap": 4,
    "item_budget_hours": 4.0,
    "wip_limit": 3,
    "bug_chain_limit": 2,
    "push_required": True,
    "unledgered_dispatch_limit": 2,
    "unledgered_window_hours": 2.0,
}

DISPATCH_TOOLS = {
    "Agent",
    "Task",
    "SendMessage",
    "Workflow",
    "mcp__claude-code-remote__create_session",
    "mcp__claude-code-remote__send_message",
}
READ_ONLY_AGENT_TYPES = {"Explore", "Plan", "claude-code-guide", "statusline-setup"}
ITEM_TAG = re.compile(r"\[item:\s*([A-Za-z0-9_.\-/]+)\s*\]")
REVIEW_TAG = "[review]"
ITEM_KINDS = ("feature", "bug", "safety", "process", "measurement")
HYPOTHESIS_KINDS = ("feature",)
STALL_RESPONSE_KINDS = ("process", "measurement")
DISPOSITION_CLASSES = ("isolated-defect", "missing-shared-contract", "capability-gap",
                       "unresolved-hypothesis")
HOLDS = ("stall", "budget", "review", "scope")
ACTIVE = "active"
CLOSED_STATES = {"done", "dropped", "renamed"}

# Text a "user" transcript line can carry that the user did not type.
NOT_USER_PREFIXES = (
    "<task-notification",
    "<system-reminder",
    "<command-",
    "<local-command",
    "Caveat:",
    "This session is being continued",
    "Stop hook feedback",
    "[Request interrupted",
)


class GuardError(Exception):
    """A refused CLI action; the message says why and what to do."""


# --------------------------------------------------------------------------- time


def utcnow() -> datetime:
    forced = os.environ.get("FUZZLAB_ORCH_NOW")
    if forced:
        return parse_ts(forced)
    return datetime.now(timezone.utc)


def parse_ts(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hours(delta: timedelta) -> float:
    return delta.total_seconds() / 3600.0


# ------------------------------------------------------------------------- ledger


def main_checkout(start: Path | None = None) -> Path:
    """The main checkout, also from inside a linked worktree (one ledger per repo)."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    cwd = start or (Path(env) if env else Path(__file__).resolve().parent.parent)
    try:
        common = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True, text=True, check=True, timeout=20,
        ).stdout.strip()
        return Path(common).parent
    except (OSError, subprocess.SubprocessError):
        return cwd


def ledger_path() -> Path:
    env = os.environ.get("FUZZLAB_ORCH_LEDGER")
    if env:
        return Path(env)
    return main_checkout() / ".claude" / "orchestration" / "ledger.json"


def empty_ledger() -> dict:
    return {"version": 2, "config": dict(DEFAULT_CONFIG), "goal": None,
            "checkpoints": [], "items": {}, "decisions": [], "events": [], "history": []}


def load_ledger(path: Path | None = None) -> dict:
    path = path or ledger_path()
    if not path.exists():
        return empty_ledger()
    data = json.loads(path.read_text(encoding="utf-8"))
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(data.get("config") or {})
    data["config"] = cfg
    for key in ("checkpoints", "decisions", "events", "history"):
        data.setdefault(key, [])
    data.setdefault("items", {})
    return data


def save_ledger(data: dict, path: Path | None = None) -> None:
    path = path or ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def goal_active(data: dict) -> bool:
    goal = data.get("goal")
    return bool(goal) and goal.get("status") == ACTIVE


def log_event(data: dict, kind: str, detail: str, now: datetime) -> None:
    data["events"].append({"ts": fmt_ts(now), "kind": kind, "detail": detail})


# --------------------------------------------------------------------- transcript


def _norm(text: str) -> str:
    return " ".join(text.lower().split())


@dataclass
class TranscriptFacts:
    user_messages: list[datetime]
    pushes: list[datetime]
    dispatches: list[datetime]
    user_texts: list[tuple[datetime, str]] = field(default_factory=list)

    def last_user(self) -> datetime | None:
        return max(self.user_messages) if self.user_messages else None

    def user_after(self, when: datetime) -> bool:
        return any(t > when for t in self.user_messages)

    def push_after(self, when: datetime) -> bool:
        return any(t > when for t in self.pushes)

    def quoted_after(self, quote: str, when: datetime) -> datetime | None:
        """The first real user message after ``when`` that contains ``quote``."""
        needle = _norm(quote)
        if not needle:
            return None
        hits = [t for t, text in self.user_texts if t > when and needle in _norm(text)]
        return min(hits) if hits else None


# An AskUserQuestion answer is a tool result the harness writes; the session cannot.
ANSWER_PREFIXES = ("Your questions have been answered", "The user answered")


def _answer_text(content) -> str | None:
    if not isinstance(content, list):
        return None
    for part in content:
        if isinstance(part, dict) and part.get("type") == "tool_result":
            body = part.get("content")
            if isinstance(body, list):
                body = " ".join(b.get("text", "") for b in body if isinstance(b, dict))
            if isinstance(body, str) and body.lstrip().startswith(ANSWER_PREFIXES):
                return body
    return None


def _text_of(content) -> tuple[str, bool]:
    """(text, is_tool_result) for a message's content."""
    if isinstance(content, str):
        return content, False
    if isinstance(content, list):
        if any(isinstance(p, dict) and p.get("type") == "tool_result" for p in content):
            return "", True
        return " ".join(p.get("text", "") for p in content
                        if isinstance(p, dict) and p.get("type") == "text"), False
    return "", False


def real_user_text(entry: dict) -> str | None:
    """The text of a line the user really wrote (or an answer they gave), else None."""
    if entry.get("type") != "user" or entry.get("isSidechain") or entry.get("isMeta"):
        return None
    content = (entry.get("message") or {}).get("content")
    answer = _answer_text(content)
    if answer is not None:
        return answer
    text, tool_result = _text_of(content)
    text = text.strip()
    if tool_result or not text or text.startswith(NOT_USER_PREFIXES):
        return None
    return text


def is_real_user_line(entry: dict) -> bool:
    return real_user_text(entry) is not None


def read_transcript(path: str | os.PathLike | None) -> TranscriptFacts:
    facts = TranscriptFacts([], [], [])
    if not path or not Path(path).exists():
        return facts
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            # Cheap prefilters: transcripts reach tens of MB; tool results dominate.
            if '"isSidechain":true' in line or '"isSidechain": true' in line:
                continue
            is_user = '"type":"user"' in line or '"type": "user"' in line
            is_tool_use = '"tool_use"' in line
            if not (is_user or is_tool_use):
                continue
            if is_user and '"tool_use_id"' in line and not any(a in line for a in ANSWER_PREFIXES):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            ts = entry.get("timestamp")
            if not ts:
                continue
            when = parse_ts(ts)
            if entry.get("type") == "user":
                text = real_user_text(entry)
                if text is not None:
                    facts.user_messages.append(when)
                    facts.user_texts.append((when, text))
                continue
            content = (entry.get("message") or {}).get("content")
            if entry.get("type") != "assistant" or not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, dict) or part.get("type") != "tool_use":
                    continue
                name = part.get("name", "")
                if name == "PushNotification":
                    facts.pushes.append(when)
                elif name in DISPATCH_TOOLS and not _exempt(name, part.get("input") or {}):
                    facts.dispatches.append(when)
    return facts


# ---------------------------------------------------------------------- decisions


def lineage(data: dict, item_id: str) -> set[str]:
    """The item and every item it continues (``--continues``), transitively."""
    seen: set[str] = set()
    cur: str | None = item_id
    while cur and cur not in seen:
        seen.add(cur)
        cur = (data["items"].get(cur) or {}).get("continues")
    return seen


def verified_decisions(data: dict, facts: TranscriptFacts, hold: str, item_id: str | None,
                       after: datetime) -> list[tuple[dict, datetime]]:
    """Decisions for ``hold`` (and the item's lineage) whose quote a real user message
    after ``after`` contains, with that message's time, oldest first."""
    ids = lineage(data, item_id) if item_id else {None}
    out = []
    for d in data.get("decisions", []):
        if d.get("hold") != hold or d.get("item") not in ids:
            continue
        said = facts.quoted_after(d.get("quote", ""), after)
        if said is not None:
            out.append((d, said))
    return sorted(out, key=lambda pair: parse_ts(pair[0]["ts"]))


def decision_state(data: dict, facts: TranscriptFacts, d: dict) -> str:
    said = facts.quoted_after(d.get("quote", ""), parse_ts("1970-01-01T00:00:00Z"))
    return (f"quote found in a user message at {fmt_ts(said)}" if said
            else "UNVERIFIED: no user message contains this quote")


# ----------------------------------------------------------------------- triggers


@dataclass
class Trigger:
    code: str
    since: datetime
    message: str
    items: tuple[str, ...] = ()
    blocks_stop: bool = False      # the Stop hook refuses to end the turn
    holds: bool = True             # dispatch for ``items`` (all, for a stall) is denied


def _better(direction: str, a: float, b: float) -> bool:
    return a > b if direction == "up" else a < b


def last_improvement(data: dict) -> datetime:
    goal = data["goal"]
    direction = goal.get("direction", "up")
    best = goal.get("baseline")
    when = parse_ts(goal["opened"])
    for cp in data["checkpoints"]:
        value = cp["value"]
        if best is None or _better(direction, value, best):
            best = value
            when = parse_ts(cp["ts"])
    return when


def current_value(data: dict):
    return data["checkpoints"][-1]["value"] if data["checkpoints"] else data["goal"].get("baseline")


def spent_hours(item: dict, now: datetime) -> float:
    """Cumulative active hours: closed segments plus the open one."""
    spent = float(item.get("spent_hours") or 0.0)
    if item.get("status") == ACTIVE and item.get("started"):
        spent += max(0.0, hours(now - parse_ts(item["started"])))
    return spent


def base_budget(data: dict, item: dict) -> float:
    return float(item.get("budget_hours") or data["config"]["item_budget_hours"])


def spawned_bugs(data: dict, item_id: str, after: datetime | None = None) -> list[tuple[str, dict]]:
    ids = lineage(data, item_id)
    found = [(i, it) for i, it in data["items"].items()
             if it.get("spawned_by") in ids and it.get("kind") == "bug"
             and (after is None or parse_ts(it["opened"]) > after)]
    return sorted(found, key=lambda pair: pair[1]["opened"])


def last_disposition(data: dict, item_id: str) -> datetime | None:
    stamps = [parse_ts(d["ts"]) for i in lineage(data, item_id)
              for d in (data["items"].get(i) or {}).get("dispositions", [])]
    return max(stamps) if stamps else None


def review_allowance(data: dict, facts: TranscriptFacts, item_id: str,
                     item: dict) -> tuple[int, int]:
    """(rounds counted, rounds allowed) since the latest verified review decision."""
    cap = int(data["config"]["review_round_cap"])
    rounds = [parse_ts(r) for i in lineage(data, item_id)
              for r in (data["items"].get(i) or {}).get("rounds", [])]
    decisions = verified_decisions(data, facts, "review", item_id, parse_ts(item["opened"]))
    if decisions:
        d, _ = decisions[-1]
        since = parse_ts(d["ts"])
        return len([r for r in rounds if r >= since]), int(d.get("rounds") or cap)
    return len(rounds), cap


def evaluate(data: dict, facts: TranscriptFacts, now: datetime) -> list[Trigger]:
    """Every trigger currently in force. Empty when no goal is open."""
    if not goal_active(data):
        return []
    cfg = data["config"]
    goal = data["goal"]
    last_user = facts.last_user()
    out: list[Trigger] = []

    # Checkpoint due: a reporting cadence for unattended work.
    anchors = [parse_ts(goal["opened"])]
    if data["checkpoints"]:
        anchors.append(parse_ts(data["checkpoints"][-1]["ts"]))
    if last_user:
        anchors.append(last_user)
    due = max(anchors) + timedelta(hours=cfg["checkpoint_hours"])
    if now > due:
        out.append(Trigger(
            "checkpoint-due", due,
            f"No progress checkpoint for {cfg['checkpoint_hours']:g} h of unattended work. "
            "Measure the goal metric (a real run, not an estimate), record it with "
            "`scripts/orchestration_guard.py checkpoint --value N --evidence <run output>`, "
            "and send the user the `report` summary with PushNotification.",
            blocks_stop=True, holds=False))

    # Stall: measured from the last improvement only; contact does not restart it.
    base = last_improvement(data)
    stall_at = base + timedelta(hours=cfg["stall_hours"])
    if now > stall_at:
        live = [(d, said) for d, said in verified_decisions(data, facts, "stall", None, stall_at)
                if now < parse_ts(d["ts"]) + timedelta(hours=float(d.get("hours") or 0))]
        if live:
            d, _ = live[-1]
            until = parse_ts(d["ts"]) + timedelta(hours=float(d["hours"]))
            out.append(Trigger(
                "stall", stall_at,
                f"Stall acknowledged by the user: the metric ({goal['metric']}) is unchanged "
                f"for {hours(now - base):.1f} h; dispatch is allowed until {fmt_ts(until)} "
                "under the decision. The clock has not restarted.",
                holds=False))
        else:
            out.append(Trigger(
                "stall", stall_at,
                f"STALL: the goal metric ({goal['metric']}) has not improved for "
                f"{hours(now - base):.1f} h (limit {cfg['stall_hours']:g} h). Busy is not "
                "building: stop feeding the stalled work. Treat the stall as a defect: open a "
                "process or measurement item (`item add <ID> --kind process|measurement`) to "
                "find out why the metric is not moving and fix that cause. Only such an item "
                "may be dispatched until the metric improves or the user decides (`decide "
                "--hold stall --hours H --quote \"<their words>\"`). Send the user the "
                "`report` with PushNotification (PA-0141).",
                blocks_stop=cfg["push_required"] and not facts.push_after(stall_at)))

    for item_id, item in sorted(data["items"].items()):
        if item.get("status") in CLOSED_STATES:
            continue
        opened = parse_ts(item["opened"])
        # Review-round cap.
        count, allowed = review_allowance(data, facts, item_id, item)
        if count >= allowed and not item.get("round_open"):
            out.append(Trigger(
                "review-cap", now,
                f"{item_id}: {count} review rounds (allowed {allowed}). Do not start another "
                "round. Tell the user what the rounds keep finding and propose: ship as is "
                "with stated residuals, narrow the scope, or redesign. Their decision is "
                "recorded with `decide --hold review --item ... --rounds N --quote ...` "
                "(PA-0142).", items=(item_id,)))
        # Budget: cumulative spend against base budget plus verified extensions. Checked
        # for an open item too: a reopened item carries its spend (BUG-0156).
        spent = spent_hours(item, now)
        budget0 = base_budget(data, item)
        extra = sum(float(d.get("hours") or 0)
                    for d, _ in verified_decisions(data, facts, "budget", item_id, opened))
        if spent > budget0 + extra:
            over_at = now - timedelta(hours=spent - (budget0 + extra))
            out.append(Trigger(
                "budget", over_at,
                f"{item_id}: {spent:.1f} h spent, over its {budget0 + extra:g} h budget "
                f"({budget0:g} h + {extra:g} h granted). Report the overrun and ask whether "
                "to continue, cut scope, or drop it. An extension is the user's decision: "
                "`decide --hold budget --item ... --hours H --quote ...`; it adds hours "
                "and does not reset the spend (PA-0145).", items=(item_id,)))
        if item.get("hypothesis") and spent > budget0:
            over0 = now - timedelta(hours=spent - budget0)
            done = last_disposition(data, item_id)
            if done is None or done < over0:
                out.append(Trigger(
                    "disposition-due", over0,
                    f"{item_id}: its experiment exhausted its {budget0:g} h budget "
                    f"(hypothesis: {item['hypothesis']}). Before another equivalent patch, "
                    "disposition the approach: `item disposition ... --class "
                    "isolated-defect|missing-shared-contract|capability-gap|"
                    "unresolved-hypothesis --evidence ... --next ...` (QUALITY_POLICY R1).",
                    items=(item_id,)))
        # Self-originated scope.
        if item.get("origin") == "self" and not item.get("blocks") \
                and not item.get("stall_response"):
            if not verified_decisions(data, facts, "scope", item_id, opened):
                out.append(Trigger(
                    "self-scope", opened,
                    f"{item_id}: opened by this session, not by the user, and it is not a "
                    "defect blocking an active item. It waits in the backlog until the user "
                    "approves it (`decide --hold scope --item ... --quote ...`); list it in "
                    "your next report. Contact alone is not approval (PA-0143).",
                    items=(item_id,)))
        # Bug chain: the systemic-diagnosis trigger (R1).
        chain = spawned_bugs(data, item_id, last_disposition(data, item_id))
        limit = int(cfg["bug_chain_limit"])
        if len(chain) >= limit:
            since = parse_ts(chain[limit - 1][1]["opened"])
            ids = (item_id,) + tuple(i for i, _ in chain)
            out.append(Trigger(
                "bug-chain", since,
                f"{item_id}: its fixes have spawned {len(chain)} bugs "
                f"({', '.join(i for i, _ in chain)}). Stop fixing forward. Check the evidence "
                "(or run the smallest discriminating experiment) and record a disposition: "
                "`item disposition <ID> --class isolated-defect|missing-shared-contract|"
                "capability-gap|unresolved-hypothesis --evidence ... --next \"<action; "
                "prediction; budget>\"` (PA-0144, QUALITY_POLICY R1).", items=ids))
    return out


def unledgered_dispatch(data: dict, facts: TranscriptFacts, now: datetime) -> Trigger | None:
    """Orchestration without a goal ledger: several dispatches in a short window."""
    if goal_active(data):
        return None
    cfg = data["config"]
    window = now - timedelta(hours=cfg["unledgered_window_hours"])
    recent = [t for t in facts.dispatches if t > window]
    if len(recent) < int(cfg["unledgered_dispatch_limit"]):
        return None
    return Trigger(
        "no-goal", recent[0],
        f"{len(recent)} agent dispatches in the last {cfg['unledgered_window_hours']:g} h "
        "with no goal ledger. Before dispatching more, open one: "
        "`scripts/orchestration_guard.py goal open --text ... --metric ... --baseline N "
        "--evidence ...` (PA-0141).", blocks_stop=True, holds=False)


# -------------------------------------------------------------------------- audit


def _paths_overlap(a: str, b: str) -> bool:
    a, b = a.rstrip("/"), b.rstrip("/")
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def declared_overlap(data: dict, files: list[str], exclude: str,
                     after: str | None) -> list[str]:
    clashes = []
    for other_id, other in data["items"].items():
        if other_id == exclude or other.get("status") != ACTIVE or other_id == after:
            continue
        if other.get("after") == exclude:
            continue
        for f in files:
            for g in other.get("files", []):
                if _paths_overlap(f, g):
                    clashes.append(f"{other_id}: {g}")
    return clashes


def branch_files(repo: Path, base: str, branch: str) -> set[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only", f"{base}...{branch}"],
            capture_output=True, text=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    return {line for line in out.splitlines() if line}


def audit_overlaps(data: dict, repo: Path) -> list[str]:
    """Files changed on two active items' branches with no declared merge order."""
    active = [(i, it) for i, it in sorted(data["items"].items())
              if it.get("status") == ACTIVE and it.get("branch") and it.get("base")]
    changed = {i: branch_files(repo, it["base"], it["branch"]) for i, it in active}
    problems = []
    for n, (a, ita) in enumerate(active):
        for b, itb in active[n + 1:]:
            if ita.get("after") == b or itb.get("after") == a:
                continue
            both = sorted(changed[a] & changed[b])
            if both:
                problems.append(f"{a} and {b} both change {', '.join(both[:5])}"
                                + (" ..." if len(both) > 5 else ""))
    return problems


# --------------------------------------------------------------------------- hooks


def _exempt(tool: str, tool_input: dict) -> bool:
    if tool in ("Agent", "Task") and tool_input.get("subagent_type") in READ_ONLY_AGENT_TYPES:
        return True
    text = _dispatch_text(tool_input)
    return text.lstrip().upper().startswith("STOP")


def _dispatch_text(tool_input: dict) -> str:
    return " ".join(str(tool_input.get(k, "")) for k in
                    ("prompt", "message", "description", "script", "args"))


def gate_dispatch(data: dict, facts: TranscriptFacts, tool: str, tool_input: dict,
                  now: datetime) -> str | None:
    """The reason to deny this dispatch, or None to allow it. Records review rounds."""
    if not goal_active(data) or tool not in DISPATCH_TOOLS or _exempt(tool, tool_input):
        return None
    text = _dispatch_text(tool_input)
    match = ITEM_TAG.search(text)
    if not match:
        return ("Every dispatch carries `[item: <ID>]` naming a ledger item while a goal is "
                "open (`scripts/orchestration_guard.py report` lists them; `item add` opens "
                "one). Messages starting with STOP are exempt.")
    item_id = match.group(1)
    item = data["items"].get(item_id)
    if item is None:
        return f"[item: {item_id}] is not in the ledger. Add it with `item add` first."
    if item.get("status") in CLOSED_STATES:
        extra = f" It continues as {item['renamed_to']}." if item.get("renamed_to") else ""
        return f"{item_id} is {item['status']}.{extra} Reopen it or add a new item."
    triggers = evaluate(data, facts, now)
    stall = next((t for t in triggers if t.code == "stall" and t.holds), None)
    responding = bool(item.get("stall_response")) or (
        stall is not None and item.get("kind") in STALL_RESPONSE_KINDS
        and parse_ts(item["opened"]) >= stall.since)
    if stall is not None and not responding:
        return stall.message
    for trig in triggers:
        if not trig.holds or item_id not in trig.items or trig.code == "review-cap":
            continue  # the review cap only stops further review (below)
        if trig.code == "self-scope" and responding:
            continue
        return trig.message
    if responding and not item.get("stall_response"):
        item["stall_response"] = True
        log_event(data, "stall-response", item_id, now)
    reviewers = set(data["goal"].get("reviewers", []))
    is_review = REVIEW_TAG in text.lower() or (
        tool in ("SendMessage", "mcp__claude-code-remote__send_message")
        and (tool_input.get("to") in reviewers or tool_input.get("session_id") in reviewers))
    if is_review:
        if item.get("round_open"):
            cap = int(data["config"]["round_request_cap"])
            if int(item.get("round_requests") or 0) >= cap:
                return (f"{item_id}: {cap} review requests already in this round. Apply the "
                        "consolidated must-fix list before the next round (PA-0142).")
            item["round_requests"] = int(item.get("round_requests") or 0) + 1
        else:
            count, allowed = review_allowance(data, facts, item_id, item)
            if count >= allowed:
                return next(t.message for t in triggers
                            if t.code == "review-cap" and item_id in t.items)
            item.setdefault("rounds", []).append(fmt_ts(now))
            item["round_open"] = True
            item["round_requests"] = 1
            log_event(data, "review-round", item_id, now)
    else:
        item["round_open"] = False
    if item.get("status") != ACTIVE:
        item["status"] = ACTIVE
        item["started"] = fmt_ts(now)
        log_event(data, "item-started", item_id, now)
    return None


def hook_main(event: str, payload: dict, ledger_file: Path | None = None) -> tuple[int, str]:
    """(exit code, stderr/stdout text) for a hook event. Exit 2 blocks or denies."""
    now = utcnow()
    data = load_ledger(ledger_file)
    facts = read_transcript(payload.get("transcript_path"))

    if event == "pretooluse":
        tool = payload.get("tool_name", "")
        reason = gate_dispatch(data, facts, tool, payload.get("tool_input") or {}, now)
        if reason:
            return 2, f"orchestration_guard: dispatch denied. {reason}"
        if goal_active(data) and tool in DISPATCH_TOOLS:
            save_ledger(data, ledger_file)
        return 0, ""

    if event == "stop":
        if payload.get("stop_hook_active"):
            return 0, ""
        triggers = [t for t in evaluate(data, facts, now) if t.blocks_stop]
        missing = unledgered_dispatch(data, facts, now)
        if missing:
            triggers.append(missing)
        if goal_active(data):
            overlaps = audit_overlaps(data, main_checkout())
            if overlaps:
                triggers.append(Trigger(
                    "overlap", now, "Concurrent items change the same files with no merge "
                    "order (PA-0146): " + "; ".join(overlaps) + ". Serialise them "
                    "(`item add ... --after`) or merge one first.", blocks_stop=True,
                    holds=False))
        if triggers:
            return 2, "orchestration_guard: " + " | ".join(t.message for t in triggers)
        return 0, ""

    if event == "sessionstart":
        if not goal_active(data):
            return 0, ""
        return 0, ("ORCHESTRATION GOAL IS OPEN. Before dispatching anything, read this report "
                   "and compare progress with the goal. A summary's 'pending tasks' and 'next "
                   "step' are not authorization (PA-0147).\n" + render_report(data, facts, now))
    return 0, ""


# -------------------------------------------------------------------------- report


def render_report(data: dict, facts: TranscriptFacts, now: datetime) -> str:
    goal = data.get("goal")
    if not goal:
        return "No goal ledger."
    better = "higher" if goal.get("direction", "up") == "up" else "lower"
    improved = last_improvement(data)
    lines = [
        f"Metric: {goal['metric']} = {current_value(data)} (baseline {goal.get('baseline')}, "
        f"{better} is better); unchanged since {fmt_ts(improved)} "
        f"({hours(now - improved):.1f} h)",
        f"Goal ({goal['status']}): {goal['text']}",
    ]
    trig = evaluate(data, facts, now)
    lines.append("Holds and triggers:" if trig else "Holds and triggers: none")
    for t in trig:
        lines.append(f"  - {t.code}{'' if t.holds else ' (not holding)'}: {t.message}")
    last_user = facts.last_user()
    lines.append(f"Last user message: {fmt_ts(last_user) if last_user else 'none seen'}; "
                 f"now {fmt_ts(now)}")
    lines.append("Checkpoints:")
    for cp in data["checkpoints"] or []:
        lines.append(f"  {cp['ts']}  {cp['value']}  {cp.get('note', '')}")
    if not data["checkpoints"]:
        lines.append("  (none)")
    lines.append("Items:")
    for item_id, item in sorted(data["items"].items()):
        bugs = len(spawned_bugs(data, item_id))
        lines.append(
            f"  {item_id} [{item.get('status')}] {item.get('kind')}/{item.get('origin')}: "
            f"{item.get('title', '')} | spent {spent_hours(item, now):.1f} h of "
            f"{base_budget(data, item):g} h | rounds {len(item.get('rounds', []))}"
            f" | bugs spawned {bugs} | dispositions {len(item.get('dispositions', []))}"
            f" | opened {item['opened']}"
            + (f" | continues {item['continues']}" if item.get("continues") else ""))
        if item.get("hypothesis"):
            lines.append(f"      hypothesis: {item['hypothesis']}")
    if data.get("decisions"):
        lines.append("Decisions:")
        for d in data["decisions"]:
            scope = f" {d['item']}" if d.get("item") else ""
            grant = "".join(f" +{d[k]} {k}" for k in ("hours", "rounds") if d.get(k))
            lines.append(f"  {d['ts']} {d['hold']}{scope}{grant}: \"{d['quote']}\" — "
                         f"{decision_state(data, facts, d)}")
    if data.get("history"):
        lines.append(f"Earlier goals kept in history: {len(data['history'])}")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- CLI


def _check_evidence(path: str | None, after: datetime | None) -> None:
    if not path:
        raise GuardError("--evidence is required: the output of the run that measured it.")
    p = Path(path)
    if not p.is_file():
        raise GuardError(f"evidence file not found: {path}")
    if after is not None:
        mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
        if mtime <= after:
            raise GuardError(f"evidence {path} is older than the previous checkpoint "
                             f"({fmt_ts(after)}); a changed value needs a new measurement.")


def _close_segment(item: dict, now: datetime) -> None:
    item["spent_hours"] = spent_hours(item, now)
    item["started"] = None


def cmd_goal(args, data: dict, now: datetime) -> str:
    if args.action == "open":
        if goal_active(data):
            raise GuardError("a goal is already open; close it first (`goal close --reason`).")
        _check_evidence(args.evidence, None)
        if data.get("goal"):  # keep the closed goal's whole record (L11: history survives)
            data["history"].append({"goal": data["goal"], "checkpoints": data["checkpoints"],
                                    "items": data["items"], "decisions": data["decisions"]})
        data["goal"] = {"text": args.text, "metric": args.metric, "direction": args.direction,
                        "baseline": args.baseline, "opened": fmt_ts(now), "status": ACTIVE,
                        "reviewers": list(args.reviewer or []), "evidence": args.evidence}
        data["checkpoints"] = []
        data["items"] = {}
        data["decisions"] = []
        log_event(data, "goal-open", args.text, now)
        return "goal opened"
    if args.action == "close":
        if not data.get("goal"):
            raise GuardError("no goal to close")
        for item in data["items"].values():
            if item.get("status") == ACTIVE:
                _close_segment(item, now)
                item["status"] = "open"
        data["goal"]["status"] = "closed"
        data["goal"]["closed"] = fmt_ts(now)
        log_event(data, "goal-close", args.reason or "", now)
        return "goal closed"
    if args.action == "reopen":
        if not data.get("goal") or goal_active(data):
            raise GuardError("no closed goal to reopen")
        data["goal"]["status"] = ACTIVE
        log_event(data, "goal-reopen", args.reason or "", now)
        return "goal reopened; its clocks, spend and items continue"
    if args.action == "reviewers":
        if not goal_active(data):
            raise GuardError("no open goal")
        data["goal"]["reviewers"] = sorted(set(data["goal"].get("reviewers", []))
                                           | set(args.reviewer or []))
        return "reviewers: " + ", ".join(data["goal"]["reviewers"])
    raise GuardError(f"unknown goal action {args.action}")


def cmd_checkpoint(args, data: dict, now: datetime) -> str:
    if not goal_active(data):
        raise GuardError("no open goal")
    prev = data["checkpoints"][-1] if data["checkpoints"] else None
    prev_value = prev["value"] if prev else data["goal"].get("baseline")
    if args.value != prev_value:
        _check_evidence(args.evidence,
                        parse_ts(prev["ts"]) if prev else parse_ts(data["goal"]["opened"]))
    data["checkpoints"].append({"ts": fmt_ts(now), "value": args.value,
                                "evidence": args.evidence, "note": args.note or ""})
    log_event(data, "checkpoint", f"{args.value} {args.note or ''}", now)
    return f"checkpoint {args.value} recorded"


def cmd_decide(args, data: dict, now: datetime) -> str:
    if not goal_active(data):
        raise GuardError("no open goal")
    if not (args.quote or "").strip():
        raise GuardError("--quote is required: the user's own words that decide this hold. "
                         "It counts only while a real user message contains it.")
    if args.hold != "stall" and not args.item:
        raise GuardError(f"--hold {args.hold} needs --item")
    if args.item and args.item not in data["items"]:
        raise GuardError(f"{args.item} is not in the ledger")
    if args.hold in ("stall", "budget") and not (args.hours and args.hours > 0):
        raise GuardError(f"--hold {args.hold} needs --hours > 0: an extension adds time; "
                         "it never resets the clock")
    if args.hold == "review" and not (args.rounds and args.rounds > 0):
        raise GuardError("--hold review needs --rounds > 0")
    d = {"ts": fmt_ts(now), "hold": args.hold, "item": args.item, "quote": args.quote.strip(),
         "hours": args.hours, "rounds": args.rounds, "note": args.note or ""}
    data["decisions"].append(d)
    log_event(data, "decision", f"{args.hold} {args.item or ''}", now)
    return (f"decision recorded ({args.hold}{' ' + args.item if args.item else ''}); it lifts "
            "the hold only while a user message after the hold began contains the quote")


def cmd_item(args, data: dict, now: datetime) -> str:
    if not goal_active(data):
        raise GuardError("no open goal")
    items = data["items"]
    if args.action == "add":
        if args.id in items:
            raise GuardError(f"{args.id} already exists")
        if args.kind not in ITEM_KINDS:
            raise GuardError(f"--kind must be one of {', '.join(ITEM_KINDS)}")
        for ref in (args.blocks, args.spawned_by, args.after, args.continues):
            if ref and ref not in items:
                raise GuardError(f"{ref} is not in the ledger")
        prev = items.get(args.continues) if args.continues else None
        hypothesis = args.hypothesis or (prev or {}).get("hypothesis")
        if args.kind in HYPOTHESIS_KINDS and not hypothesis:
            raise GuardError("a feature item needs --hypothesis \"<prediction; effort ceiling; "
                             "exit decision>\": the outcome it is expected to move "
                             "(QUALITY_POLICY L11)")
        if args.blocks and items[args.blocks].get("status") != ACTIVE:
            raise GuardError(f"--blocks {args.blocks}: that item is not active")
        if args.blocks and args.kind != "bug":
            raise GuardError("--blocks is for a defect in active work (--kind bug); other "
                             "self-originated work waits for the user (PA-0143)")
        files = [f.strip() for f in (args.files or "").split(",") if f.strip()]
        clashes = declared_overlap(data, files, args.continues or args.id, args.after)
        if clashes:
            raise GuardError("declared files overlap active items (PA-0146): "
                             + "; ".join(clashes) + ". Use --after <item> to serialise.")
        active = [i for i, it in items.items()
                  if it.get("status") == ACTIVE and i != args.continues]
        if len(active) >= int(data["config"]["wip_limit"]):
            raise GuardError(f"WIP limit {data['config']['wip_limit']} reached "
                             f"({', '.join(sorted(active))}); finish or drop one first.")
        new = {"title": args.title, "kind": args.kind, "origin": args.origin,
               "status": "open", "opened": fmt_ts(now), "files": files,
               "branch": args.branch, "base": args.base, "after": args.after,
               "blocks": args.blocks, "spawned_by": args.spawned_by,
               "budget_hours": args.budget_hours, "rounds": [], "spent_hours": 0.0,
               "started": None, "hypothesis": hypothesis, "continues": args.continues,
               "dispositions": []}
        if prev is not None:
            # A rename keeps the history: opened time, spend, origin, budget and holds.
            was_active = prev.get("status") == ACTIVE
            _close_segment(prev, now)
            new["opened"] = prev["opened"]
            new["spent_hours"] = prev["spent_hours"]
            if prev.get("origin") == "self":
                new["origin"] = "self"
            new["budget_hours"] = args.budget_hours or prev.get("budget_hours")
            for key in ("blocks", "stall_response"):
                if prev.get(key) and not new.get(key):
                    new[key] = prev[key]
            if was_active:
                new["status"] = ACTIVE
                new["started"] = fmt_ts(now)
            prev["status"] = "renamed"
            prev["renamed_to"] = args.id
            prev["closed"] = fmt_ts(now)
        items[args.id] = new
        log_event(data, "item-add", args.id + (f" (continues {args.continues})"
                                               if args.continues else ""), now)
        return f"{args.id} added" + (f", continuing {args.continues}" if args.continues else "")
    if args.id not in items:
        raise GuardError(f"{args.id} is not in the ledger")
    item = items[args.id]
    if args.action in ("done", "drop"):
        _close_segment(item, now)
        item["status"] = "done" if args.action == "done" else "dropped"
        item["closed"] = fmt_ts(now)
        log_event(data, f"item-{args.action}", args.id, now)
        return f"{args.id} {item['status']}"
    if args.action == "reopen":
        if item.get("status") not in ("done", "dropped"):
            raise GuardError(f"{args.id} is {item.get('status')}, not closed")
        item["status"] = "open"
        log_event(data, "item-reopen", args.id, now)
        return f"{args.id} reopened; its spend ({spent_hours(item, now):.1f} h) continues"
    if args.action == "round":
        item.setdefault("rounds", []).append(fmt_ts(now))
        item["round_open"] = False
        log_event(data, "review-round", args.id, now)
        return f"{args.id}: round {len(item['rounds'])} recorded"
    if args.action == "disposition":
        if args.disposition_class not in DISPOSITION_CLASSES:
            raise GuardError("--class must be one of " + ", ".join(DISPOSITION_CLASSES))
        if not (args.evidence or "").strip() or not (args.next or "").strip():
            raise GuardError("--evidence (store rows, a log line, a reproduction) and --next "
                             "(the next action with a fresh prediction and budget) are required")
        item.setdefault("dispositions", []).append(
            {"ts": fmt_ts(now), "class": args.disposition_class,
             "evidence": args.evidence.strip(), "next": args.next.strip()})
        log_event(data, "disposition", f"{args.id} {args.disposition_class}", now)
        return f"{args.id}: disposition {args.disposition_class} recorded"
    raise GuardError(f"unknown item action {args.action}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("goal")
    g.add_argument("action", choices=["open", "close", "reopen", "reviewers"])
    g.add_argument("--text")
    g.add_argument("--metric")
    g.add_argument("--direction", choices=["up", "down"], default="up")
    g.add_argument("--baseline", type=float)
    g.add_argument("--evidence")
    g.add_argument("--reviewer", action="append")
    g.add_argument("--reason")

    c = sub.add_parser("checkpoint")
    c.add_argument("--value", type=float, required=True)
    c.add_argument("--evidence")
    c.add_argument("--note")

    d = sub.add_parser("decide")
    d.add_argument("--hold", choices=HOLDS, required=True)
    d.add_argument("--item")
    d.add_argument("--quote", required=True)
    d.add_argument("--hours", type=float)
    d.add_argument("--rounds", type=int)
    d.add_argument("--note")

    i = sub.add_parser("item")
    i.add_argument("action", choices=["add", "done", "drop", "reopen", "round", "disposition"])
    i.add_argument("id")
    i.add_argument("--title", default="")
    i.add_argument("--kind", default="feature")
    i.add_argument("--origin", choices=["user", "self"], default="self")
    i.add_argument("--hypothesis")
    i.add_argument("--blocks")
    i.add_argument("--spawned-by")
    i.add_argument("--after")
    i.add_argument("--continues")
    i.add_argument("--files")
    i.add_argument("--branch")
    i.add_argument("--base")
    i.add_argument("--budget-hours", type=float)
    i.add_argument("--class", dest="disposition_class")
    i.add_argument("--evidence")
    i.add_argument("--next")

    for name in ("report", "check"):
        r = sub.add_parser(name)
        r.add_argument("--transcript")

    h = sub.add_parser("hook")
    h.add_argument("event", choices=["stop", "pretooluse", "sessionstart"])
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = utcnow()
    if args.cmd == "hook":
        try:
            payload = json.loads(sys.stdin.read() or "{}")
            code, text = hook_main(args.event, payload)
        except Exception as exc:  # noqa: BLE001 - a broken guard must not wedge the session
            print(f"orchestration_guard: internal error ({exc!r}); not enforcing this time. "
                  "Fix scripts/orchestration_guard.py.", file=sys.stderr)
            return 1
        if text:
            print(text, file=sys.stderr if code else sys.stdout)
        return code
    data = load_ledger()
    if args.cmd in ("report", "check"):
        facts = read_transcript(args.transcript)
        print(render_report(data, facts, now))
        if args.cmd == "check":
            return 1 if any(t.holds or t.blocks_stop
                            for t in evaluate(data, facts, now)) else 0
        return 0
    try:
        handler = {"goal": cmd_goal, "checkpoint": cmd_checkpoint, "item": cmd_item,
                   "decide": cmd_decide}[args.cmd]
        if args.cmd == "goal" and args.action == "open" and not (args.text and args.metric):
            raise GuardError("goal open needs --text and --metric")
        message = handler(args, data, now)
    except GuardError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    save_ledger(data)
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
