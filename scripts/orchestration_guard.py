#!/usr/bin/env python3
"""Progress governance for autonomous, multi-agent work on this repository (BUG-0141).

An orchestrating session once ran for about 15 hours, dispatching review round
after review round and follow-up after follow-up, while the goal metric
(confirmed Juice Shop findings) moved by one. It never measured progress against
the goal, never stopped, and never told the user until they intervened. The
written rules it had (PA-0032, the overnight plan's "never stop building")
pushed it *away* from checking in. PA-0020's lesson applies: a rule addressed to
the same process that failed is not prevention. This script is the mechanical
half of PA-0141..PA-0147; Claude Code hooks call it (``.claude/settings.json``).

The **ledger** (``.claude/orchestration/ledger.json`` in the main checkout,
git-ignored) holds one goal with a measurable metric, its checkpoints, and the
work items dispatched for it. The hooks read the ledger plus the session
transcript, which holds the user's real messages and the session's own
PushNotification calls. A user message is the only thing that clears an
escalation. The session cannot write one.

Triggers (defaults in ``DEFAULT_CONFIG``):

* **checkpoint due**: more than ``checkpoint_hours`` since the last checkpoint and
  the last user message. The Stop hook blocks until ``checkpoint`` is run.
* **stall**: the metric has not improved for ``stall_hours`` since the goal
  opened, the last improvement, or the last user message. Dispatch is denied, and
  the Stop hook requires a PushNotification, until the user writes.
* **review-round cap**: ``review_round_cap`` review requests for one item since the
  last user message. The next review request for it is denied.
* **item budget**: an item active for more than ``item_budget_hours`` (from its
  start or the last user message). Dispatch for it is denied.
* **self-originated scope**: an item the session opened itself
  (``--origin self``) that is not a defect blocking an active item. It is
  dispatchable only after a user message newer than the item.
* **bug chain**: ``bug_chain_limit`` bugs spawned by one item's fixes. Dispatch
  for that item and its spawned bugs is denied until the user writes.
* **WIP limit / file overlap**: ``item add`` refuses more than ``wip_limit``
  active items, or declared files overlapping another active item's without
  ``--after``. ``audit`` (also run by the Stop hook) compares the active items'
  real branch diffs.

Usage::

    scripts/orchestration_guard.py goal open --text "..." --metric "confirmed findings" \\
        --baseline 6 --evidence run.out [--reviewer <agent-id> ...]
    scripts/orchestration_guard.py checkpoint --value 7 --evidence run.out --note "..."
    scripts/orchestration_guard.py item add FR-X-1 --title "..." --kind feature \\
        --origin user [--files a.py,b/] [--branch b --base ref] [--spawned-by ID]
    scripts/orchestration_guard.py item done FR-X-1
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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_CONFIG = {
    "checkpoint_hours": 3.0,
    "stall_hours": 6.0,
    "review_round_cap": 3,
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
ACTIVE = "active"
CLOSED_STATES = {"done", "dropped"}

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
    return {"version": 1, "config": dict(DEFAULT_CONFIG), "goal": None,
            "checkpoints": [], "items": {}, "events": []}


def load_ledger(path: Path | None = None) -> dict:
    path = path or ledger_path()
    if not path.exists():
        return empty_ledger()
    data = json.loads(path.read_text(encoding="utf-8"))
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(data.get("config") or {})
    data["config"] = cfg
    data.setdefault("checkpoints", [])
    data.setdefault("items", {})
    data.setdefault("events", [])
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


@dataclass
class TranscriptFacts:
    user_messages: list[datetime]
    pushes: list[datetime]
    dispatches: list[datetime]

    def last_user(self) -> datetime | None:
        return max(self.user_messages) if self.user_messages else None

    def user_after(self, when: datetime) -> bool:
        return any(t > when for t in self.user_messages)

    def push_after(self, when: datetime) -> bool:
        return any(t > when for t in self.pushes)


# An AskUserQuestion answer is a tool result the harness writes; the session cannot.
ANSWER_PREFIXES = ("Your questions have been answered", "The user answered")


def _is_answer(content) -> bool:
    if not isinstance(content, list):
        return False
    for part in content:
        if isinstance(part, dict) and part.get("type") == "tool_result":
            body = part.get("content")
            if isinstance(body, list):
                body = " ".join(b.get("text", "") for b in body if isinstance(b, dict))
            if isinstance(body, str) and body.lstrip().startswith(ANSWER_PREFIXES):
                return True
    return False


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


def is_real_user_line(entry: dict) -> bool:
    if entry.get("type") != "user" or entry.get("isSidechain") or entry.get("isMeta"):
        return False
    content = (entry.get("message") or {}).get("content")
    if _is_answer(content):
        return True
    text, tool_result = _text_of(content)
    text = text.strip()
    if tool_result or not text:
        return False
    return not text.startswith(NOT_USER_PREFIXES)


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
                if is_real_user_line(entry):
                    facts.user_messages.append(when)
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


# ----------------------------------------------------------------------- triggers


@dataclass
class Trigger:
    code: str
    since: datetime
    message: str
    items: tuple[str, ...] = ()
    blocks_stop: bool = False      # the Stop hook refuses to end the turn
    needs_user: bool = True        # cleared only by a user message after ``since``


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


def _item_start(item: dict, last_user: datetime | None) -> datetime:
    start = parse_ts(item.get("started") or item["opened"])
    return max(start, last_user) if last_user and last_user > start else start


def spawned_bugs(data: dict, item_id: str) -> list[tuple[str, dict]]:
    found = [(i, it) for i, it in data["items"].items()
             if it.get("spawned_by") == item_id and it.get("kind") == "bug"]
    return sorted(found, key=lambda pair: pair[1]["opened"])


def evaluate(data: dict, facts: TranscriptFacts, now: datetime) -> list[Trigger]:
    """Every trigger currently in force. Empty when no goal is open."""
    if not goal_active(data):
        return []
    cfg = data["config"]
    goal = data["goal"]
    last_user = facts.last_user()
    out: list[Trigger] = []

    # Checkpoint due.
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
            blocks_stop=True, needs_user=False))

    # Stall.
    base = last_improvement(data)
    if last_user and last_user > base:
        base = last_user
    stall_at = base + timedelta(hours=cfg["stall_hours"])
    if now > stall_at:
        out.append(Trigger(
            "stall", stall_at,
            f"STALL: the goal metric ({goal['metric']}) has not improved for "
            f"{hours(now - base):.1f} h (limit {cfg['stall_hours']:g} h) with no word from the "
            "user. Stop dispatching. Send the user the `report` (metric history, items, "
            "rounds, what is blocking) with PushNotification and end the turn; wait for "
            "their decision. Standing 'keep going' instructions do not cover a stall "
            "(PA-0141).",
            blocks_stop=cfg["push_required"] and not facts.push_after(stall_at)))

    for item_id, item in sorted(data["items"].items()):
        if item.get("status") in CLOSED_STATES:
            continue
        # Review-round cap: rounds since the user last wrote.
        rounds = [parse_ts(r) for r in item.get("rounds", [])]
        recent = [r for r in rounds if not last_user or r > last_user]
        cap = int(cfg["review_round_cap"])
        if len(recent) >= cap:
            out.append(Trigger(
                "review-cap", recent[cap - 1],
                f"{item_id}: {len(recent)} review rounds since the user last wrote (cap {cap}). "
                "Do not send another round. Tell the user what the rounds keep finding and "
                "propose: ship as is with stated residuals, narrow the scope, or redesign "
                "(PA-0142).", items=(item_id,)))
        # Budget.
        if item.get("status") == ACTIVE:
            budget = float(item.get("budget_hours") or cfg["item_budget_hours"])
            start = _item_start(item, last_user)
            if now > start + timedelta(hours=budget):
                out.append(Trigger(
                    "budget", start + timedelta(hours=budget),
                    f"{item_id}: over its {budget:g} h budget ({hours(now - start):.1f} h since "
                    "start or the user's last message). Report the overrun and ask whether to "
                    "continue, cut scope, or drop it (PA-0145).", items=(item_id,)))
        # Self-originated scope.
        if item.get("origin") == "self" and not item.get("blocks"):
            opened = parse_ts(item["opened"])
            if not facts.user_after(opened):
                out.append(Trigger(
                    "self-scope", opened,
                    f"{item_id}: opened by this session, not by the user, and it is not a "
                    "defect blocking an active item. It waits in the backlog until the user "
                    "approves it; list it in your next report (PA-0143).", items=(item_id,)))
        # Bug chain.
        chain = spawned_bugs(data, item_id)
        limit = int(cfg["bug_chain_limit"])
        if len(chain) >= limit:
            since = parse_ts(chain[limit - 1][1]["opened"])
            if not facts.user_after(since):
                ids = (item_id,) + tuple(i for i, _ in chain)
                out.append(Trigger(
                    "bug-chain", since,
                    f"{item_id}: its fixes have spawned {len(chain)} bugs "
                    f"({', '.join(i for i, _ in chain)}). Stop fixing forward. Measure the "
                    "shared mechanism's real behaviour, write down a redesign, and take it "
                    "to the user (PA-0144).", items=ids))
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
        "--evidence ...` (PA-0141).", blocks_stop=True, needs_user=False)


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
        return f"{item_id} is {item['status']}. Reopen it or add a new item."
    for trig in evaluate(data, facts, now):
        if trig.code == "stall":
            return trig.message
        if item_id in trig.items and trig.code != "review-cap" and trig.needs_user:
            return trig.message
    reviewers = set(data["goal"].get("reviewers", []))
    is_review = REVIEW_TAG in text.lower() or (
        tool in ("SendMessage", "mcp__claude-code-remote__send_message")
        and (tool_input.get("to") in reviewers or tool_input.get("session_id") in reviewers))
    if is_review:
        for trig in evaluate(data, facts, now):
            if trig.code == "review-cap" and item_id in trig.items:
                return trig.message
        item.setdefault("rounds", []).append(fmt_ts(now))
        log_event(data, "review-round", item_id, now)
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
                    needs_user=False))
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
    lines = [f"Goal ({goal['status']}): {goal['text']}",
             f"Metric: {goal['metric']} ({'higher' if goal.get('direction', 'up') == 'up' else 'lower'}"
             f" is better); baseline {goal.get('baseline')} at {goal['opened']}"]
    last_user = facts.last_user()
    lines.append(f"Last user message: {fmt_ts(last_user) if last_user else 'none seen'}; "
                 f"now {fmt_ts(now)}")
    lines.append("Checkpoints:")
    for cp in data["checkpoints"] or []:
        lines.append(f"  {cp['ts']}  {cp['value']}  {cp.get('note', '')}")
    if not data["checkpoints"]:
        lines.append("  (none)")
    lines.append(f"Last improvement: {fmt_ts(last_improvement(data))} "
                 f"({hours(now - last_improvement(data)):.1f} h ago)")
    lines.append("Items:")
    for item_id, item in sorted(data["items"].items()):
        bugs = len(spawned_bugs(data, item_id))
        lines.append(
            f"  {item_id} [{item.get('status')}] {item.get('kind')}/{item.get('origin')}: "
            f"{item.get('title', '')} | rounds {len(item.get('rounds', []))}"
            f" | bugs spawned {bugs} | opened {item['opened']}")
    trig = evaluate(data, facts, now)
    lines.append("Triggers in force:" if trig else "Triggers in force: none")
    for t in trig:
        lines.append(f"  - {t.code}: {t.message}")
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


def cmd_goal(args, data: dict, now: datetime) -> str:
    if args.action == "open":
        if goal_active(data):
            raise GuardError("a goal is already open; close it first (`goal close --reason`).")
        _check_evidence(args.evidence, None)
        data["goal"] = {"text": args.text, "metric": args.metric, "direction": args.direction,
                        "baseline": args.baseline, "opened": fmt_ts(now), "status": ACTIVE,
                        "reviewers": list(args.reviewer or []), "evidence": args.evidence}
        data["checkpoints"] = []
        data["items"] = {}
        log_event(data, "goal-open", args.text, now)
        return "goal opened"
    if args.action == "close":
        if not data.get("goal"):
            raise GuardError("no goal to close")
        data["goal"]["status"] = "closed"
        data["goal"]["closed"] = fmt_ts(now)
        log_event(data, "goal-close", args.reason or "", now)
        return "goal closed"
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


def cmd_item(args, data: dict, now: datetime) -> str:
    if not goal_active(data):
        raise GuardError("no open goal")
    items = data["items"]
    if args.action == "add":
        if args.id in items:
            raise GuardError(f"{args.id} already exists")
        if args.kind not in ITEM_KINDS:
            raise GuardError(f"--kind must be one of {', '.join(ITEM_KINDS)}")
        for ref in (args.blocks, args.spawned_by, args.after):
            if ref and ref not in items:
                raise GuardError(f"{ref} is not in the ledger")
        if args.blocks and items[args.blocks].get("status") != ACTIVE:
            raise GuardError(f"--blocks {args.blocks}: that item is not active")
        if args.blocks and args.kind != "bug":
            raise GuardError("--blocks is for a defect in active work (--kind bug); other "
                             "self-originated work waits for the user (PA-0143)")
        files = [f.strip() for f in (args.files or "").split(",") if f.strip()]
        clashes = declared_overlap(data, files, args.id, args.after)
        if clashes:
            raise GuardError("declared files overlap active items (PA-0146): "
                             + "; ".join(clashes) + ". Use --after <item> to serialise.")
        active = [i for i, it in items.items() if it.get("status") == ACTIVE]
        if len(active) >= int(data["config"]["wip_limit"]):
            raise GuardError(f"WIP limit {data['config']['wip_limit']} reached "
                             f"({', '.join(sorted(active))}); finish or drop one first.")
        items[args.id] = {"title": args.title, "kind": args.kind, "origin": args.origin,
                          "status": "open", "opened": fmt_ts(now), "files": files,
                          "branch": args.branch, "base": args.base, "after": args.after,
                          "blocks": args.blocks, "spawned_by": args.spawned_by,
                          "budget_hours": args.budget_hours, "rounds": []}
        log_event(data, "item-add", args.id, now)
        return f"{args.id} added"
    if args.id not in items:
        raise GuardError(f"{args.id} is not in the ledger")
    if args.action in ("done", "drop"):
        items[args.id]["status"] = "done" if args.action == "done" else "dropped"
        items[args.id]["closed"] = fmt_ts(now)
        log_event(data, f"item-{args.action}", args.id, now)
        return f"{args.id} {items[args.id]['status']}"
    if args.action == "round":
        items[args.id].setdefault("rounds", []).append(fmt_ts(now))
        log_event(data, "review-round", args.id, now)
        return f"{args.id}: round {len(items[args.id]['rounds'])} recorded"
    raise GuardError(f"unknown item action {args.action}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("goal")
    g.add_argument("action", choices=["open", "close", "reviewers"])
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

    i = sub.add_parser("item")
    i.add_argument("action", choices=["add", "done", "drop", "round"])
    i.add_argument("id")
    i.add_argument("--title", default="")
    i.add_argument("--kind", default="feature")
    i.add_argument("--origin", choices=["user", "self"], default="self")
    i.add_argument("--blocks")
    i.add_argument("--spawned-by")
    i.add_argument("--after")
    i.add_argument("--files")
    i.add_argument("--branch")
    i.add_argument("--base")
    i.add_argument("--budget-hours", type=float)

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
            return 1 if any(t.needs_user or t.blocks_stop
                            for t in evaluate(data, facts, now)) else 0
        return 0
    try:
        handler = {"goal": cmd_goal, "checkpoint": cmd_checkpoint, "item": cmd_item}[args.cmd]
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
