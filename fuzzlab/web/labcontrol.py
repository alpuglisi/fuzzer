"""Lab container control for the control panel's **Lab** page (component #12, with
component #1's ``lab/labctl.sh`` as the thing it drives).

One row per compose service in ``lab/compose.yaml`` — the generated PFF app and its
database, the opt-in downgrade front-end, and the ten browsable apps (``apps``
profile) — each with a live state and a Start/Stop control, so the lab's containers
no longer have to be brought up and down by hand from a terminal.

Design, in the control plane's existing terms (D11/D18):

* **The service list is derived from ``compose.yaml``, never hand-listed here.**
  ``PA-0059``(2) flagged exactly this duplication in ``labctl.sh``'s own force-clean
  list; this module parses the compose file (PyYAML is already a declared dependency,
  PA-0005), so a service added or removed there shows up or disappears here with no
  edit. Only the human-facing labels are a hand-kept map, and an unlabelled service
  still renders under its compose name.
* **Every action is ``lab/labctl.sh <start|stop> <service>``, run as a gated child
  process** through the launcher's existing :class:`~fuzzlab.web.runner.Runner` (argv
  list, no shell, live SSE output). The service name is resolved against the
  compose-derived list *before* it reaches argv (an unknown name is a 404, not an
  argument), and ``labctl.sh`` re-validates it against a strict pattern on its side.
  A profiled service's compose profile travels as ``PFF_PROFILE`` in the child's
  environment — the same knob ``labctl.sh up`` already takes.
* **State is read from the container engine's real post-state** (``labctl.sh ps``,
  ``PA-0059``(1)), parsed here against the compose-derived names so it is independent
  of each compose provider's container-naming scheme (``pff-lab_web_1`` under
  podman-compose, ``pff-lab-web-1`` under ``docker compose``).
* **Lab-only by construction.** Nothing here sends traffic to any target; it starts
  and stops this repo's own loopback-bound containers. It therefore sits outside the
  ``--authorized`` traffic gate, and inside the control plane's state-change gate
  (``SecurityGateMiddleware``) like every other ``POST /api/*``.

Pure and offline except :func:`fetch_states`, which is the one function that runs a
process (and is what the route tests replace).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from fuzzlab import procutil

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]                 # fuzzlab/web -> fuzzlab -> <repo>
LAB_DIR = REPO_ROOT / "lab"
COMPOSE_PATH = LAB_DIR / "compose.yaml"
LABCTL_PATH = LAB_DIR / "labctl.sh"

ACTIONS = ("start", "stop")

# Presentation only — which app each compose service serves. The *set* of services
# comes from compose.yaml (see the module banner); a service missing here simply
# renders under its compose name.
SERVICE_LABELS: dict[str, str] = {
    "db": "MariaDB — PFF database",
    "web": "Puppy Fort Factory (PFF) — php_laravel",
    "frontend": "h2→h1 downgrade front-end (D17, desync target)",
    "circlefeed": "CircleFeed — php_laravel",
    "huddlehub": "Huddle Hub — php_laravel",
    "booking": "Booking — php_laravel",
    "pictrail": "PicTrail — django",
    "loopcast": "LoopCast — go_net_http",
    "trackernest": "TrackerNest — spring_boot",
    "reelqueue": "ReelQueue — spring_boot",
    "wanderfare": "WanderFare — spring_boot",
    "forgecart": "ForgeCart — ruby_rails",
    "meadowmart": "MeadowMart — node_express",
}

# Compose short-syntax port strings this lab uses:
#   "127.0.0.1:${PFF_WEB_PORT:-8080}:80"   (host bind, env-overridable host port)
#   "127.0.0.1:8080:80"  /  "8080:80"      (literal forms, for completeness)
_PORT_RE = re.compile(
    r"^(?:(?P<host>[^:]+):)?"
    r"(?:\$\{(?P<var>[A-Za-z_][A-Za-z0-9_]*):-(?P<default>\d+)\}|(?P<literal>\d+))"
    r":(?P<container>\d+)(?:/(?:tcp|udp))?$"
)


@dataclass(frozen=True)
class LabService:
    """One compose service, as the Lab page shows it."""

    name: str
    label: str
    profile: str | None          # first compose profile, or None (default profile)
    bind_host: str | None        # host address the port is published on, if any
    host_port: int | None        # resolved host port (env override or default)
    url: str | None              # http://<bind_host>:<host_port>/ when published

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "label": self.label, "profile": self.profile,
            "bind_host": self.bind_host, "host_port": self.host_port, "url": self.url,
        }


def parse_port(spec: str, environ: Mapping[str, str] | None = None
               ) -> tuple[str | None, int | None]:
    """``(bind_host, host_port)`` of one compose port string, or ``(None, None)``.

    An ``${VAR:-default}`` host port resolves through ``environ`` (default: the
    process environment), so the page links where the lab is *actually* published.
    """
    m = _PORT_RE.match(spec.strip())
    if not m:
        return None, None
    env = os.environ if environ is None else environ
    if m.group("var"):
        raw = env.get(m.group("var"), m.group("default"))
    else:
        raw = m.group("literal")
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return m.group("host"), None
    return m.group("host"), port


def _load_compose(compose_path: Path) -> dict[str, Any]:
    data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{compose_path}: top level is not a mapping")
    return data


def project_name(compose_path: Path = COMPOSE_PATH) -> str:
    """The compose project name (``name:`` key; else the directory name, as compose does)."""
    data = _load_compose(compose_path)
    return str(data.get("name") or compose_path.resolve().parent.name)


def load_services(compose_path: Path = COMPOSE_PATH,
                  environ: Mapping[str, str] | None = None) -> list[LabService]:
    """Every service in ``compose_path``, in file order."""
    data = _load_compose(compose_path)
    services = data.get("services") or {}
    out: list[LabService] = []
    for name, svc in services.items():
        svc = svc or {}
        profiles = svc.get("profiles") or []
        profile = str(profiles[0]) if profiles else None
        bind_host: str | None = None
        host_port: int | None = None
        for p in svc.get("ports") or []:
            if isinstance(p, dict):            # long syntax
                bind_host = p.get("host_ip")
                try:
                    host_port = int(p.get("published")) if p.get("published") else None
                except (TypeError, ValueError):
                    host_port = None
            else:
                bind_host, host_port = parse_port(str(p), environ)
            if host_port is not None:
                break
        url = f"http://{bind_host}:{host_port}/" if (bind_host and host_port) else None
        out.append(LabService(
            name=str(name), label=SERVICE_LABELS.get(str(name), str(name)),
            profile=profile, bind_host=bind_host, host_port=host_port, url=url,
        ))
    return out


def available() -> bool:
    """Whether this checkout carries the lab (compose file + labctl) at all."""
    return COMPOSE_PATH.is_file() and LABCTL_PATH.is_file()


def services() -> list[LabService]:
    """The live service list, or ``[]`` when the lab directory is absent."""
    return load_services() if available() else []


def find(name: str) -> LabService | None:
    """Resolve a request-supplied service name against the compose-derived list."""
    for s in services():
        if s.name == name:
            return s
    return None


# --- container state -------------------------------------------------------

def service_of(container_name: str, project: str, known: set[str]) -> str | None:
    """Map an engine container name back to its compose service.

    Both providers name containers ``<project><sep><service><sep><index>``, with
    ``sep`` ``_`` (podman-compose) or ``-`` (``docker compose``); the service itself
    may contain either character, so the candidate is checked against ``known``.
    """
    for sep in ("_", "-"):
        prefix = f"{project}{sep}"
        if not container_name.startswith(prefix):
            continue
        rest = re.sub(r"[-_]\d+$", "", container_name[len(prefix):])
        if rest in known:
            return rest
    return None


def parse_ps(text: str, project: str, known: set[str]) -> dict[str, dict[str, str]]:
    """``labctl.sh ps`` output (``<name>\\t<state>\\t<status>`` lines) → per-service
    ``{"state": ..., "status": ..., "container": ...}``. A running container wins over
    a stopped one when a service has several (e.g. a stale index-2 container)."""
    out: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 2 or not parts[0]:
            continue
        name, state = parts[0].strip(), parts[1].strip().lower()
        status = parts[2].strip() if len(parts) > 2 else ""
        svc = service_of(name, project, known)
        if svc is None:
            continue
        prev = out.get(svc)
        if prev is None or (state == "running" and prev["state"] != "running"):
            out[svc] = {"state": state, "status": status, "container": name}
    return out


def state_for(service: LabService, states: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    """The fields the API adds to a service row from a :func:`parse_ps` result."""
    st = states.get(service.name)
    if st is None:
        return {"state": "absent", "status": "", "container": None, "running": False}
    return {"state": st["state"], "status": st.get("status", ""),
            "container": st.get("container"), "running": st["state"] == "running"}


async def fetch_states(timeout: float = 20.0) -> tuple[dict[str, dict[str, str]], str | None]:
    """Run ``labctl.sh ps`` and parse it. Returns ``(states, error)``; on any failure
    (no lab, no engine, timeout) ``states`` is empty and ``error`` says why — the page
    then shows every service as unknown rather than guessing."""
    if not available():
        return {}, "lab/compose.yaml or lab/labctl.sh not found in this checkout"
    # BUG-0125 sweep: `labctl.sh ps` forks the container engine; a timeout stops the
    # whole tree through procutil's supervisor, not only `bash` (whose child would
    # otherwise be left running).
    try:
        returncode, out, err, timed_out = await procutil.arun_bounded(
            ["bash", str(LABCTL_PATH), "ps"], timeout=timeout)
    except OSError as e:  # bash missing, permissions
        return {}, f"could not run labctl.sh: {e}"
    if timed_out:
        return {}, f"labctl.sh ps did not answer within {timeout:g}s"
    if returncode != 0:
        msg = err.decode(errors="replace").strip() or f"labctl.sh ps exited {returncode}"
        return {}, msg
    known = {s.name for s in services()}
    return parse_ps(out.decode(errors="replace"), project_name(), known), None


# --- actions ---------------------------------------------------------------

def control_argv(action: str, service: LabService) -> list[str]:
    """``bash lab/labctl.sh <action> <service>`` — the exact child argv (no shell)."""
    if action not in ACTIONS:
        raise ValueError(f"unknown lab action {action!r}")
    return ["bash", str(LABCTL_PATH), action, service.name]


def control_env(service: LabService, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The child's environment: the process env plus ``PFF_PROFILE`` for a profiled
    service (how ``labctl.sh`` enables a compose profile)."""
    env = dict(os.environ if base is None else base)
    if service.profile:
        env["PFF_PROFILE"] = service.profile
    else:
        env.pop("PFF_PROFILE", None)
    return env
