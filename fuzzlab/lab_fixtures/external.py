"""External lab fixtures: bWAPP and OWASP Juice Shop as loopback-only lab targets.

Component LAB (CC-LAB-0300, FR-LAB-300..304). The fixtures themselves are compose
projects under ``lab/external/<lab>/`` and are driven by ``lab/labctl.sh``, which hands
an external lab's lifecycle to ``lab/external/extctl.sh``. This module is the Python side
of that: the lab registry, the pinned upstream artefacts, the bWAPP download, the
compose pre-flight and the post-boot exposure check, and the bootstrap that brings a lab
to a usable state (bWAPP's installer, a Juice Shop account) and puts its lab identity in
the credential store.

Safety:

* **Loopback only.** A compose file whose resolved config publishes a port on anything
  but loopback, or uses the host's network/pid namespace, is refused before ``up``
  (:func:`config_problems`); after ``up`` every container of the project is inspected
  and the host's LISTEN table is read (:func:`exposure_problems`). Both fail closed.
* **Nothing is sent to a target without ``--authorized``** (D11). ``fetch`` downloads
  bWAPP's zip from its publisher and sends nothing to a lab.
* **Credentials** come from the credential store, the operator's gated env channel, or
  an interactive prompt -- never argv, logs or the repo -- and are written to the store
  only after a verified login (D12, PA-0007). The bootstrap client sends them only to
  the loopback base origin, follows no redirect and ignores proxy environment variables
  (PA-0082, PA-0098).
* **Licence.** bWAPP is CC BY-NC-ND: its zip is cached in a gitignored directory and
  never committed; the image build re-verifies its sha256.
"""

from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urljoin, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_DIR = REPO_ROOT / "lab" / "external"

# --- pinned upstream artefacts (the one source of truth; tests compare the Dockerfile and
# --- compose files against these, PA-0001) -------------------------------------------------
BUSYBOX_IMAGE = ("docker.io/library/busybox:1.37@sha256:"
                 "bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e")
PHP_IMAGE = ("mirror.gcr.io/library/php:5.6-apache@sha256:"
             "0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d")
MYSQL_IMAGE = ("docker.io/library/mysql:5.7@sha256:"
               "4bc6bc963e6d8443453676cae56536f4b8156d78bae03c0145cbe47c2aad73bb")
JUICE_SHOP_IMAGE = ("docker.io/bkimminich/juice-shop:v20.3.0@sha256:"
                    "cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27")
PINNED_IMAGES = frozenset({BUSYBOX_IMAGE, PHP_IMAGE, MYSQL_IMAGE, JUICE_SHOP_IMAGE})

BWAPP_ZIP_URL = "https://sourceforge.net/projects/bwapp/files/bWAPP/bWAPP_latest.zip/download"
BWAPP_ZIP_NAME = "bWAPP_latest.zip"
BWAPP_ZIP_SHA256 = "87b5363062b4be9d2aa91916f6396f0f7d56e8acca08b732440e863f8c9e4cd6"
BWAPP_ZIP_SIZE = 15_058_349

LAB_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PROJECT_LABEL = "com.docker.compose.project"


class ExternalLabError(RuntimeError):
    """A fixture operation failed; the message never carries a secret."""


@dataclass(frozen=True)
class LabMeta:
    """What compose cannot hold about a lab."""
    name: str
    #: The compose service that publishes the app's port.
    service: str
    port_env: str
    default_port: int
    container_port: int
    #: Where the app lives on its origin (bWAPP is served under a sub-path).
    app_path: str
    #: Any HTTP answer here means the web tier is up (PA-0050).
    ready_path: str
    identity: str
    default_username: str
    #: A password may be generated when none is supplied (the account is ours to create).
    may_generate_password: bool


LAB_META: dict[str, LabMeta] = {
    "bwapp": LabMeta("bwapp", "web", "BWAPP_PORT", 8092, 80, "/bWAPP/", "/bWAPP/login.php",
                     "bwapp-bee", "bee", False),
    "juice-shop": LabMeta("juice-shop", "app", "JUICE_PORT", 3000, 3000, "/",
                          "/rest/admin/application-version", "juice-user",
                          "juice-user@fuzzlab.lab", True),
}


# --- registry -------------------------------------------------------------------------

def discover_labs(root: Path = EXTERNAL_DIR) -> dict[str, Path]:
    """``{lab name: compose file}`` for every ``<root>/<name>/compose.yaml`` -- the
    registry is the directory layout (PA-0059(2)); ``extctl.sh`` derives it the same way."""
    out: dict[str, Path] = {}
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir()):
        compose = d / "compose.yaml"
        if d.is_dir() and LAB_NAME_RE.match(d.name) and compose.is_file():
            out[d.name] = compose
    return out


def compose_project(compose_file: Path) -> str:
    """The compose file's top-level ``name:`` (the project name)."""
    for line in compose_file.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^name:\s*([A-Za-z0-9_-]+)\s*$", line)
        if m:
            return m.group(1)
    raise ExternalLabError(f"{compose_file}: no top-level `name:`")


def lab_meta(name: str, root: Path = EXTERNAL_DIR) -> LabMeta:
    if not LAB_NAME_RE.match(name or "") or name not in discover_labs(root):
        raise ExternalLabError(f"unknown external lab {name!r} (known: "
                               f"{', '.join(discover_labs(root)) or 'none'})")
    if name not in LAB_META:
        raise ExternalLabError(f"external lab {name!r} has no LAB_META entry")
    return LAB_META[name]


def lab_port(meta: LabMeta, environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    raw = env.get(meta.port_env, "") or str(meta.default_port)
    if not raw.isdigit() or not 0 < int(raw) < 65536:
        raise ExternalLabError(f"{meta.port_env} must be a port number, got {raw!r}")
    return int(raw)


def base_url(meta: LabMeta, environ: Mapping[str, str] | None = None) -> str:
    """The lab's origin. Always ``127.0.0.1`` (the credential store keys by bare host;
    ``localhost`` would miss the stored identity)."""
    return f"http://127.0.0.1:{lab_port(meta, environ)}"


# --- bWAPP download -------------------------------------------------------------------

def cache_path(root: Path = EXTERNAL_DIR) -> Path:
    return root / "bwapp" / ".cache" / BWAPP_ZIP_NAME


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def fetch_bwapp(*, session: Any = None, dest: Path | None = None, timeout: float = 120.0,
                max_hops: int = 5, url: str = BWAPP_ZIP_URL,
                sha256: str = BWAPP_ZIP_SHA256, size: int = BWAPP_ZIP_SIZE) -> Path:
    """Download bWAPP's zip to the gitignored cache, verified by sha256 and size.

    An existing cached file is re-hashed, never trusted. Redirects (SourceForge hands
    the download to a mirror) are followed by hand, https only, at most ``max_hops``.
    This is an anonymous public download, so the host's own proxy/CA environment
    applies. On any mismatch the partial file is removed and ``ExternalLabError``
    raised -- never a substitute.

    One fetch runs at a time per cache directory (an exclusive ``flock`` on the
    directory itself): the stale-part sweep and the cache check would otherwise race a
    concurrent fetch, e.g. an operator's ``up bwapp`` beside a live test."""
    dest = cache_path() if dest is None else dest
    if dest.exists() and not dest.is_file():
        raise ExternalLabError(f"{dest} exists and is not a file")
    dest.parent.mkdir(parents=True, exist_ok=True)
    lock = os.open(dest.parent, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _fetch_locked(session=session, dest=dest, timeout=timeout,
                             max_hops=max_hops, url=url, sha256=sha256, size=size)
    finally:
        os.close(lock)                          # releases the lock


def _fetch_locked(*, session: Any, dest: Path, timeout: float, max_hops: int, url: str,
                  sha256: str, size: int) -> Path:
    for stale in dest.parent.glob(".bwapp-*.part"):     # a killed download's leftovers
        stale.unlink()
    if dest.is_file():
        digest, got = _sha256_file(dest)
        if digest == sha256 and got == size:
            return dest
        dest.unlink()
    if session is None:
        import requests
        session = requests.Session()
    fd, tmp_name = tempfile.mkstemp(prefix=".bwapp-", suffix=".part", dir=dest.parent)
    tmp = Path(tmp_name)
    try:
        current = url
        for _ in range(max_hops + 1):
            if urlsplit(current).scheme != "https":
                raise ExternalLabError(f"refusing a non-https download hop: {current}")
            resp = session.get(current, stream=True, timeout=timeout, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                resp.close()
                if not location:
                    raise ExternalLabError("a download redirect without a Location")
                current = urljoin(current, location)
                continue
            if resp.status_code != 200:
                resp.close()
                raise ExternalLabError(f"bWAPP download failed: HTTP {resp.status_code}")
            h = hashlib.sha256()
            got = 0
            with os.fdopen(fd, "wb") as fh:
                fd = -1
                for chunk in resp.iter_content(1 << 20):
                    if not chunk:
                        continue
                    got += len(chunk)
                    if got > size:
                        raise ExternalLabError("bWAPP download is larger than the pinned size")
                    h.update(chunk)
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            resp.close()
            if got != size or h.hexdigest() != sha256:
                raise ExternalLabError(
                    f"bWAPP download does not match the pin (sha256 {h.hexdigest()}, "
                    f"{got} bytes; expected {sha256}, {size} bytes)")
            os.replace(tmp, dest)
            dfd = os.open(dest.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return dest
        raise ExternalLabError(f"too many redirects fetching {url}")
    finally:
        if fd != -1:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


# --- compose pre-flight -----------------------------------------------------------------

_PORT_SPLIT = re.compile(r"^(?:\[(?P<ip6>[^\]]*)\]|(?P<ip>[^:\[\]]*)):(?P<rest>.+)$")


def port_binding_problems(service: str, binding: Any) -> list[str]:
    """Problems with one ``ports:`` entry: it must name an explicit, literal loopback
    host IP. Handles the short (``"127.0.0.1:8092:80"``, ranges, ``/tcp``) and the long
    syntax (``{host_ip, published, target}``) and a rendered config's dicts."""
    if isinstance(binding, Mapping):
        host_ip = binding.get("host_ip")
        if host_ip in (None, ""):
            return [f"{service}: port {binding!r} has no host_ip (binds every interface)"]
        return _host_ip_problems(service, str(host_ip), binding)
    if isinstance(binding, int):
        return [f"{service}: port {binding!r} has no host IP (binds every interface)"]
    text = str(binding).strip().split("/", 1)[0]
    parts = text.count(":")
    if text.startswith("["):
        m = _PORT_SPLIT.match(text)
        if not m or m.group("rest").count(":") != 1:
            return [f"{service}: cannot parse port binding {binding!r}"]
        return _host_ip_problems(service, m.group("ip6"), binding)
    if parts < 2:
        return [f"{service}: port {binding!r} has no host IP (binds every interface)"]
    host_ip = text.split(":", 1)[0]
    return _host_ip_problems(service, host_ip, binding)


def _host_ip_problems(service: str, host_ip: str, binding: Any) -> list[str]:
    from fuzzlab.core.net import is_loopback_host
    if "$" in host_ip:
        return [f"{service}: port {binding!r} takes its host IP from interpolation"]
    if host_ip.strip().lower() == "localhost":
        return [f"{service}: port {binding!r}: name the address (127.0.0.1), not localhost"]
    if not is_loopback_host(host_ip):
        return [f"{service}: port {binding!r} is published on {host_ip!r}, not loopback"]
    return []


#: ``network_mode`` values a fixture may use: anything else (``host``, podman's
#: ``ns:<path>``, ``slirp4netns``/``pasta`` options, ``container:<id>``) can join the
#: host's namespace or reach its loopback, so it is refused (an allowlist, review A1).
ALLOWED_NETWORK_MODES = frozenset({"", "none", "bridge", "default"})


def config_problems(doc: Mapping[str, Any]) -> list[str]:
    """Safety problems in a compose document (raw file or rendered ``config``): every
    published port on a literal loopback IP; ``network_mode`` only from an allowlist (or
    ``service:`` another service of this project); no external or host-driver network;
    no host pid namespace and no privileged container."""
    problems: list[str] = []
    services = doc.get("services") or {}
    if not isinstance(services, Mapping):
        return ["compose document has no services mapping"]
    networks = doc.get("networks") or {}
    if not isinstance(networks, Mapping):
        problems.append("top-level networks is not a mapping")
        networks = {}
    for net_name, net in networks.items():
        net = net if isinstance(net, Mapping) else {}
        if net.get("external") not in (None, False, "false", "False"):
            problems.append(f"network {net_name}: external (not owned by the project)")
        if str(net.get("name") or "") == "host" or str(net.get("driver") or "") == "host":
            problems.append(f"network {net_name}: the host network")
    for name, svc in services.items():
        if not isinstance(svc, Mapping):
            problems.append(f"{name}: not a mapping")
            continue
        mode = str(svc.get("network_mode") or "")
        if mode.startswith("service:"):
            if mode.split(":", 1)[1] not in services:
                problems.append(f"{name}: network_mode {mode!r} names no service of this project")
        elif mode not in ALLOWED_NETWORK_MODES:
            problems.append(f"{name}: network_mode {mode!r} is not allowed")
        if str(svc.get("pid") or "") == "host":
            problems.append(f"{name}: pid: host")
        if svc.get("privileged") in (True, "true", "True"):
            problems.append(f"{name}: privileged")
        for binding in svc.get("ports") or []:
            problems += port_binding_problems(str(name), binding)
    return problems


def load_compose_document(text: str) -> Mapping[str, Any]:
    """A rendered ``config`` output: JSON when the provider supports it, else YAML."""
    try:
        doc = json.loads(text)
    except ValueError:
        import yaml
        doc = yaml.safe_load(text)
    if not isinstance(doc, Mapping):
        raise ExternalLabError("compose config is not a mapping")
    return doc


# --- post-boot exposure check -----------------------------------------------------------

def exposure_problems(inspects: list[Mapping[str, Any]], host_listeners: Iterable[Any],
                      project: str | None = None,
                      netns_of: Callable[[int], str | None] | None = None,
                      host_netns: str | None = None) -> tuple[list[str], list[str]]:
    """``(problems, notes)`` for a project's containers (engine ``inspect`` output) and
    the host's LISTEN table. Fails closed: no container, host networking, a binding with
    an empty (= every interface) or non-loopback ``HostIp``, or a non-loopback host
    listener on a published port. ``NetworkMode`` must be ``bridge``/``default``/``none``,
    a network of the project (``<project>_...``) or another project container's
    namespace; and, where it can be read, a container's network namespace must not be
    the host's (``netns_of(State.Pid)`` vs ``host_netns``) -- whatever the engine calls
    its mode (review A1). A published port with no host listener is a note (an engine
    without a userland proxy publishes through NAT only); ``inspect`` is the
    authoritative check (PA-0130(4))."""
    from fuzzlab.core.net import is_loopback_host
    problems: list[str] = []
    notes: list[str] = []
    if not inspects:
        return ["no container of the project was found (cannot prove it is loopback-only)"], notes
    published: set[int] = set()
    ids = {str(c.get("Id") or "") for c in inspects} - {""}
    for c in inspects:
        cname = str(c.get("Name") or c.get("Id") or "?").lstrip("/")
        hc = c.get("HostConfig") or {}
        mode = str(hc.get("NetworkMode") or "")
        joined = mode.split(":", 1)[1] if mode.startswith("container:") else None
        if not (mode in ("bridge", "default", "none")
                or (project and mode.startswith(project + "_"))
                or (joined and any(i.startswith(joined) for i in ids))):
            problems.append(f"{cname}: network mode {mode!r} is not a project network")
        pid = (c.get("State") or {}).get("Pid")
        if netns_of is not None and host_netns and isinstance(pid, int) and pid > 0:
            ns = netns_of(pid)
            if ns and ns == host_netns:
                problems.append(f"{cname}: runs in the host's network namespace")
        if hc.get("Privileged"):
            problems.append(f"{cname}: privileged")
        bindings: dict[str, list[Any]] = {}
        for source in (hc.get("PortBindings") or {},
                       (c.get("NetworkSettings") or {}).get("Ports") or {}):
            for key, val in source.items():
                bindings.setdefault(key, []).extend(val or [])
        for cport, binds in bindings.items():
            for b in binds:
                host_ip = str((b or {}).get("HostIp") or "")
                host_port = str((b or {}).get("HostPort") or "")
                if not host_ip:
                    problems.append(f"{cname}: {cport} published on every interface "
                                    f"(empty HostIp)")
                elif not is_loopback_host(host_ip):
                    problems.append(f"{cname}: {cport} published on {host_ip}")
                if host_port.isdigit():
                    published.add(int(host_port))
    seen: set[int] = set()
    for lst in host_listeners:
        if lst.port in published:
            seen.add(lst.port)
            if not lst.is_loopback():
                problems.append(f"host listens on {lst.address}:{lst.port} (a published port)")
    for port in sorted(published - seen):
        notes.append(f"port {port} is published with no host listener (NAT-only publish); "
                     f"inspect is authoritative")
    return problems, notes


def published_port(meta: LabMeta, project: str, engine: str, *,
                   runner: Callable[..., Any] | None = None) -> tuple[str, int]:
    """``(host, port)``: the loopback address the running project actually publishes for
    the lab's app (review A9: the bootstrap must target the running lab, not whatever
    the port variable says now), host as the binding names it (``127.0.0.1``, ``::1``).
    Raises on any engine error, when there is none, or when it is not on loopback."""
    import subprocess

    from fuzzlab.core.net import is_loopback_host
    from fuzzlab.procutil import ProcUtilError
    if runner is None:
        from fuzzlab.procutil import run_bounded as runner
    try:
        ids = _engine_json(engine, ["ps", "-q", "--no-trunc", "--filter",
                                    f"label={PROJECT_LABEL}={project}", "--filter",
                                    f"label=com.docker.compose.service={meta.service}"],
                           runner).split()
        inspects = json.loads(_engine_json(engine, ["inspect", *ids], runner)) if ids else []
    except (ExternalLabError, ValueError, OSError, subprocess.TimeoutExpired,
            ProcUtilError) as exc:
        raise ExternalLabError(f"cannot read the published port of {project}: "
                               f"{type(exc).__name__}: {exc}") from None
    for c in inspects if isinstance(inspects, list) else []:
        sources = ((c.get("HostConfig") or {}).get("PortBindings") or {},
                   (c.get("NetworkSettings") or {}).get("Ports") or {})
        for source in sources:
            for b in source.get(f"{meta.container_port}/tcp") or []:
                port = str((b or {}).get("HostPort") or "")
                host = str((b or {}).get("HostIp") or "")
                if port.isdigit() and is_loopback_host(host):
                    return host, int(port)
    raise ExternalLabError(f"{project}: no running {meta.service} container publishes "
                           f"{meta.container_port} on loopback (is the lab up?)")


def _engine_json(engine: str, args: list[str], runner: Callable[..., Any]) -> Any:
    res = runner([engine, *args], timeout=60)
    if res.returncode != 0:
        raise ExternalLabError(f"`{engine} {args[0]}` failed (exit {res.returncode})")
    return res.stdout


def check_exposure(project: str, engine: str, *, runner: Callable[..., Any] | None = None,
                   listeners: Callable[[], list[Any]] | None = None
                   ) -> tuple[list[str], list[str]]:
    """Inspect every container carrying the project's compose label and the host's
    LISTEN table. Any engine error is a problem (fail closed)."""
    if engine not in ("docker", "podman"):
        raise ExternalLabError(f"unknown engine {engine!r}")
    import subprocess

    from fuzzlab.procutil import ProcUtilError, host_netns, netns_of
    if runner is None:
        from fuzzlab.procutil import run_bounded as runner
    if listeners is None:
        from fuzzlab.procutil import host_listen_sockets as listeners
    try:
        ids = _engine_json(engine, ["ps", "-a", "-q", "--no-trunc", "--filter",
                                    f"label={PROJECT_LABEL}={project}"], runner).split()
        inspects = json.loads(_engine_json(engine, ["inspect", *ids], runner)) if ids else []
        host_listeners = listeners()
    except (ExternalLabError, ValueError, OSError, subprocess.TimeoutExpired,
            ProcUtilError) as exc:
        return [f"exposure check could not inspect the project: {type(exc).__name__}: "
                f"{exc}"], []
    if not isinstance(inspects, list):
        return ["exposure check could not inspect the project: unexpected inspect output"], []
    return exposure_problems(inspects, host_listeners, project=project,
                             netns_of=lambda pid: netns_of(pid) or None,
                             host_netns=host_netns())


# --- bWAPP security-level log (BUG-0311) --------------------------------------------

#: The prefix of the line `lab/external/bwapp/apache-level-log.conf` writes per request.
LEVEL_LOG_PREFIX = "fuzzlab-level "
_LEVEL_LINE = re.compile(r'^fuzzlab-level (\S+) "(.*)"$')
#: The level cookie values a scored bWAPP run may carry: bWAPP's own level 0, or no
#: cookie (bWAPP redirects such a request to its login or level page). An allowlist
#: (PA-0310(1)): PHP compares the cookie loosely (``"01"``, ``"1.0"`` select level 1)
#: and URL-decodes it, so naming the bad values cannot be complete.
LEVEL_LOG_ALLOWED = frozenset({"0", "-"})


def bwapp_level_problems(log_text: str, controls: Iterable[str], *,
                         min_requests: int = 1000) -> list[str]:
    """Problems in a bWAPP container's level log (its ``docker logs`` stdout).

    ``controls`` are markers of requests the caller sent with ``security_level=1``. Each
    must appear with level ``1``, which shows the log carries the violation the check
    looks for. Every other logged request must carry an allowed level, there must be at
    least ``min_requests`` of them, and every level line must parse (none is dropped
    silently).

    Stated limit: Apache's ``%{security_level}C`` matches the cookie name without regard
    to case, while PHP's ``$_COOKIE`` is case-sensitive, so a request carrying
    ``SECURITY_LEVEL=0; security_level=1`` would log ``0`` and run at level 1. No pass
    injects the cookie."""
    controls = list(controls)
    problems: list[str] = []
    entries: list[tuple[str, str]] = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line.startswith(LEVEL_LOG_PREFIX):
            continue
        m = _LEVEL_LINE.match(line)
        if m is None:
            problems.append(f"unparsed level line: {line[:200]!r}")
            continue
        entries.append((m.group(1), m.group(2)))
    for marker in controls:
        seen = [lvl for lvl, req in entries if marker in req]
        if "1" not in seen:
            problems.append(f"control {marker!r} not logged with level 1 (seen: {seen})")
    sent = [(lvl, req) for lvl, req in entries if not any(m in req for m in controls)]
    if len(sent) < min_requests:
        problems.append(f"the level log saw only {len(sent)} requests (< {min_requests})")
    bad = [(lvl, req) for lvl, req in sent if lvl not in LEVEL_LOG_ALLOWED]
    if bad:
        counts: dict[str, int] = {}
        for lvl, _req in bad:
            counts[lvl] = counts.get(lvl, 0) + 1
        problems.append(f"{len(bad)} requests carried a level outside "
                        f"{sorted(LEVEL_LOG_ALLOWED)}: {counts}; e.g. {bad[:3]}")
    return problems


# --- bootstrap HTTP client --------------------------------------------------------------

def _default_session() -> Any:
    import requests

    from fuzzlab.core.http import DEFAULT_BROWSER_HEADERS
    s = requests.Session()
    s.headers.update(DEFAULT_BROWSER_HEADERS)
    return s


class _LabClient:
    """A credential-sending client for one loopback origin: no proxies (``trust_env``
    off), no automatic redirects, a timeout on every request, browser headers
    (PA-0061/0062), and a refusal of any URL outside the origin (PA-0082/0098)."""

    def __init__(self, origin: str, *, session_factory: Callable[[], Any] | None = None,
                 timeout: float = 15.0):
        from fuzzlab.core.net import is_loopback_host
        parts = urlsplit(origin)
        if parts.scheme != "http" or not parts.hostname or not is_loopback_host(parts.hostname):
            raise ExternalLabError(f"refusing a non-loopback lab origin: {origin!r}")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise ExternalLabError(f"the lab origin must be scheme://host:port, got {origin!r}")
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self._factory = session_factory or _default_session
        self.session = self._new_session()
        self.timeout = timeout

    def _new_session(self) -> Any:
        s = self._factory()
        s.trust_env = False
        s.proxies = {}
        return s

    def url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ExternalLabError(f"not an origin-relative path: {path!r}")
        return self.origin + path

    def request(self, method: str, path: str, *, anonymous: bool = False, **kw: Any) -> Any:
        """``anonymous``: on a fresh session with no cookies (a differential's control)."""
        kw["allow_redirects"] = False
        kw.setdefault("timeout", self.timeout)
        session = self._new_session() if anonymous else self.session
        return session.request(method, self.url(path), **kw)

    def location(self, resp: Any, path: str) -> str:
        """A redirect's target, resolved against the request's own URL (``path``) --
        read, never followed."""
        return urljoin(self.url(path), resp.headers.get("Location", ""))


def wait_ready(client: _LabClient, path: str, *, deadline: float = 180.0,
               clock: Callable[[], float] = time.monotonic,
               sleep: Callable[[float], None] = time.sleep) -> None:
    """Return once ``path`` gives any HTTP answer (PA-0050); raise at the deadline."""
    end = clock() + deadline
    while True:
        try:
            client.request("GET", path).close()
            return
        except ExternalLabError:
            raise
        except Exception:  # noqa: BLE001 - connection refused/reset while the lab boots
            if clock() >= end:
                raise ExternalLabError(f"{client.origin}{path} gave no answer within "
                                       f"{deadline:.0f}s") from None
            sleep(1.0)


# --- credentials -------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolvedCredential:
    username: str
    password: str
    #: keyring | env | prompt | generated
    source: str

    def __repr__(self) -> str:  # never leak the password
        return f"ResolvedCredential(username={self.username!r}, source={self.source!r})"


def resolve_credential(meta: LabMeta, *, host: str, keyring_store: Any, opened_store: Any,
                       prompt: Callable[[str], str] | None, generate: bool
                       ) -> ResolvedCredential:
    """Keyring first (a store with the env channel off), then the operator's opened store
    (whose gated ``FUZZLAB_CRED_<HOST>_<IDENTITY>`` channel follows the operator's own
    ``allow_env_credentials`` switch), then an interactive prompt (TTY only; an empty
    answer is refused), then -- with no prompt, for a lab whose account we create -- a
    fresh random password."""
    cred = keyring_store.get(host, meta.identity)
    if cred is not None:
        return ResolvedCredential(cred.username, cred.password, "keyring")
    cred = opened_store.get(host, meta.identity)
    if cred is not None:
        return ResolvedCredential(cred.username, cred.password, "env")
    if prompt is not None:
        pw = prompt(f"password for {meta.identity} ({meta.default_username}): ")
        if pw:
            return ResolvedCredential(meta.default_username, pw, "prompt")
        raise ExternalLabError("no password entered")
    if generate and meta.may_generate_password:
        return ResolvedCredential(meta.default_username, secrets.token_urlsafe(24), "generated")
    raise ExternalLabError(
        f"no credential for {meta.identity!r} on {host}: run `fuzzlab session set-credential "
        f"--host {host} --identity {meta.identity} --username {meta.default_username}`, or run "
        f"this from a terminal to be prompted")


def _tty_prompt() -> Callable[[str], str] | None:
    return getpass.getpass if sys.stdin.isatty() else None


# --- bootstrap ---------------------------------------------------------------------------

BWAPP_INSTALLED = "bWAPP has been installed successfully!"
BWAPP_ALREADY = "The bWAPP database already exists..."


@dataclass
class BootstrapResult:
    lab: str
    identity: str
    credential_source: str
    stored: bool
    notes: list[str]


def _bwapp_install(client: _LabClient, *, deadline: float, clock: Callable[[], float],
                   sleep: Callable[[float], None]) -> str:
    end = clock() + deadline
    while True:
        try:
            resp = client.request("GET", "/bWAPP/install.php", params={"install": "yes"})
            text = resp.text
        except Exception:  # noqa: BLE001 - the DB may still be initialising
            text = ""
        for marker in (BWAPP_INSTALLED, BWAPP_ALREADY):
            if marker in text:
                return marker
        if clock() >= end:
            raise ExternalLabError("bWAPP's installer did not report success within "
                                   f"{deadline:.0f}s")
        sleep(2.0)


def bootstrap_bwapp(client: _LabClient, cred: ResolvedCredential, *, deadline: float = 180.0,
                    clock: Callable[[], float] = time.monotonic,
                    sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Install bWAPP's database (idempotent) and verify a level-0 login for ``cred`` by a
    positive differential (PA-0007): ``portal.php`` redirects to ``login.php`` without
    the session and answers 200 with it."""
    meta = LAB_META["bwapp"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes = [_bwapp_install(client, deadline=deadline, clock=clock, sleep=sleep)]
    anon = client.request("GET", "/bWAPP/portal.php", anonymous=True)
    login_url, portal_url = client.url("/bWAPP/login.php"), client.url("/bWAPP/portal.php")
    if anon.status_code != 302 or client.location(anon, "/bWAPP/portal.php") != login_url:
        raise ExternalLabError(f"bWAPP portal.php does not require a login "
                               f"(HTTP {anon.status_code})")
    login = client.request("POST", "/bWAPP/login.php", data={
        "login": cred.username, "password": cred.password,
        "security_level": "0", "form": "submit"})
    if login.status_code != 302 or client.location(login, "/bWAPP/login.php") != portal_url:
        raise ExternalLabError(
            "bWAPP login failed for the stored identity; if a run changed its password, "
            "run `./labctl.sh reset bwapp --authorized`")
    level = client.session.cookies.get("security_level")
    if level != "0":
        raise ExternalLabError(f"bWAPP security level is {level!r}, not 0")
    portal = client.request("GET", "/bWAPP/portal.php")
    if portal.status_code != 200:
        raise ExternalLabError(f"bWAPP portal.php with the session: HTTP {portal.status_code}")
    notes.append("level-0 login verified")
    return notes


def bootstrap_juice_shop(client: _LabClient, cred: ResolvedCredential, *,
                         deadline: float = 180.0,
                         clock: Callable[[], float] = time.monotonic,
                         sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Check the label environment (``safetyMode: disabled``), then log in -- registering
    the account through Juice Shop's own API when the login fails -- and verify it by a
    positive differential: ``whoami`` names the account, and ``/profile`` answers 200
    with the ``token`` cookie and not without it. Both read the cookie the app's own JS
    sets, not the bearer header."""
    meta = LAB_META["juice-shop"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []
    cfg = client.request("GET", "/rest/admin/application-configuration")
    try:
        mode = cfg.json()["config"]["challenges"]["safetyMode"]
    except (ValueError, KeyError, TypeError):
        raise ExternalLabError("cannot read Juice Shop's challenges.safetyMode") from None
    if mode != "disabled":
        raise ExternalLabError(f"Juice Shop challenges.safetyMode is {mode!r}, not 'disabled' "
                               f"(the fixture sets NODE_ENV=unsafe); its ground truth assumes it")
    notes.append("safetyMode disabled")

    def login() -> str | None:
        r = client.request("POST", "/rest/user/login",
                           json={"email": cred.username, "password": cred.password})
        if r.status_code != 200:
            return None
        try:
            return r.json()["authentication"]["token"]
        except (ValueError, KeyError, TypeError):
            return None

    token = login()
    if token is None:
        reg = client.request("POST", "/api/Users", json={
            "email": cred.username, "password": cred.password,
            "passwordRepeat": cred.password})
        if reg.status_code != 201:
            if "unique" in reg.text:
                raise ExternalLabError(
                    "Juice Shop already has this account and the stored password does not "
                    "log in; run `./labctl.sh reset juice-shop --authorized`")
            raise ExternalLabError(f"Juice Shop registration failed: HTTP {reg.status_code}")
        notes.append("account registered")
        token = login()
        if token is None:
            raise ExternalLabError("Juice Shop login failed right after registration")
    # whoami (like /profile) reads the `token` cookie the app's own JS sets.
    who = client.request("GET", "/rest/user/whoami", anonymous=True, cookies={"token": token})
    try:
        email = who.json()["user"]["email"]
    except (ValueError, KeyError, TypeError):
        email = None
    if email != cred.username:
        raise ExternalLabError("Juice Shop whoami does not name the logged-in account")
    anon = client.request("GET", "/profile", anonymous=True)
    authed = client.request("GET", "/profile", anonymous=True, cookies={"token": token})
    if authed.status_code != 200 or anon.status_code == 200:
        raise ExternalLabError(f"Juice Shop /profile: {anon.status_code} anonymous, "
                               f"{authed.status_code} with the token (want non-200 / 200)")
    notes.append("login verified")
    return notes


_BOOTSTRAPS = {"bwapp": bootstrap_bwapp, "juice-shop": bootstrap_juice_shop}


def bootstrap(name: str, *, environ: Mapping[str, str] | None = None,
              port: int | None = None, host: str = "127.0.0.1",
              keyring_store: Any = None, opened_store: Any = None,
              prompt: Callable[[str], str] | None = None, generate: bool = True,
              session_factory: Callable[[], Any] | None = None,
              deadline: float = 180.0) -> BootstrapResult:
    """Bring ``name`` to a usable state and store its lab identity (only after a verified
    login). ``host``/``port`` name the running lab's published address (default: the
    port variable's ``127.0.0.1`` base)."""
    meta = lab_meta(name)
    shown = f"[{host}]" if ":" in host else host
    origin = f"http://{shown}:{port}" if port else base_url(meta, environ)
    client = _LabClient(origin, session_factory=session_factory)
    host = urlsplit(client.origin).hostname or "127.0.0.1"
    if keyring_store is None or opened_store is None:
        from fuzzlab.core.config import load_config
        from fuzzlab.core.credentials import CredentialStore
        if keyring_store is None:
            keyring_store = CredentialStore(allow_env=False)
        if opened_store is None:
            opened_store = CredentialStore.open(load_config())
    cred = resolve_credential(meta, host=host, keyring_store=keyring_store,
                              opened_store=opened_store, prompt=prompt, generate=generate)
    notes = _BOOTSTRAPS[name](client, cred, deadline=deadline)
    stored = False
    if cred.source != "keyring":
        keyring_store.set(host, meta.identity, cred.username, cred.password)
        stored = True
    return BootstrapResult(name, meta.identity, cred.source, stored, notes)


# --- CLI ----------------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m fuzzlab.lab_fixtures.external",
                                description="External lab fixtures (run via lab/labctl.sh).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("info", help="print `<project> <port> <url>` for a lab")
    s.add_argument("lab")
    s = sub.add_parser("fetch", help="download and verify bWAPP's zip into the cache")
    s.add_argument("lab")
    s = sub.add_parser("check-config", help="refuse a rendered compose config that is not "
                                            "loopback-only (reads the file or stdin)")
    s.add_argument("lab")
    s.add_argument("--file", default="-")
    s = sub.add_parser("check-exposure", help="inspect the running project (fail closed)")
    s.add_argument("lab")
    s.add_argument("--engine", required=True, choices=["docker", "podman"])
    s.add_argument("--project", required=True)
    s = sub.add_parser("bootstrap", help="install / register the lab identity "
                                         "(sends traffic: needs --authorized)")
    s.add_argument("lab")
    s.add_argument("--authorized", action="store_true")
    s.add_argument("--engine", choices=["docker", "podman"],
                   help="with --project: target the port the running project publishes")
    s.add_argument("--project")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        meta = lab_meta(args.lab)
        if args.cmd == "info":
            project = compose_project(discover_labs()[meta.name])
            print(f"{project} {lab_port(meta)} {base_url(meta)}{meta.app_path}")
            return 0
        if args.cmd == "fetch":
            if meta.name != "bwapp":
                print(f"{meta.name}: nothing to fetch (pinned image)")
                return 0
            print(f"bWAPP zip verified: {fetch_bwapp()}")
            return 0
        if args.cmd == "check-config":
            text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text("utf-8")
            problems = config_problems(load_compose_document(text))
            for line in problems:
                print(f"REFUSED: {line}", file=sys.stderr)
            return 1 if problems else 0
        if args.cmd == "check-exposure":
            problems, notes = check_exposure(args.project, args.engine)
            for line in notes:
                print(f"note: {line}")
            for line in problems:
                print(f"EXPOSED: {line}", file=sys.stderr)
            return 3 if problems else 0
        if args.cmd == "bootstrap":
            if not args.authorized:
                print("bootstrap sends traffic to the lab: pass --authorized "
                      "(lab-only, your own loopback lab)", file=sys.stderr)
                return 2
            host, port = "127.0.0.1", None
            if args.project and args.engine:
                host, port = published_port(meta, args.project, args.engine)
            res = bootstrap(meta.name, port=port, host=host, prompt=_tty_prompt())
            print(f"{res.lab}: identity {res.identity!r} ready "
                  f"({res.credential_source}{', stored' if res.stored else ''}); "
                  + "; ".join(res.notes))
            return 0
    except ExternalLabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - credential/keyring/HTTP/OS errors: one line
        from fuzzlab.core.credentials import CredentialError
        import requests
        if not isinstance(exc, (CredentialError, requests.RequestException, OSError)):
            raise
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
