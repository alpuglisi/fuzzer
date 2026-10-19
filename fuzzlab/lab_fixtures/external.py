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
CRAWL_MAZE_PYTHON_IMAGE = ("docker.io/library/python:3.9-slim@sha256:"
                           "2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b")
SECDEVLABS_GOLANG_IMAGE = ("docker.io/library/golang:1.14@sha256:"
                           "1a7173b5b9a3af3e29a5837e0b2027e1c438fd1b83bbee8f221355087ad416d6")
SECDEVLABS_MARIADB_IMAGE = ("docker.io/library/mariadb:10.6.3@sha256:"
                            "3b6f9fa1d406e168998d62501b2ee4f27d53138bebfcdac03540758996c5ff1d")
SECDEVLABS_PYTHON38_IMAGE = ("docker.io/library/python:3.8@sha256:"
                             "d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c")
#: sstype's upstream Dockerfile says `python:3` and its requirements `tornado`, both
#: unpinned: pinned here to the releases current when the fixture was built.
SECDEVLABS_PYTHON312_IMAGE = ("docker.io/library/python:3.12-slim@sha256:"
                              "a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1")
#: vinijr-blog's upstream base is `php:apache` (unpinned): pinned to 8.3, from Google's
#: Docker Hub mirror (as bWAPP's PHP_IMAGE; Docker Hub rate-limits this host).
SECDEVLABS_PHP_IMAGE = ("mirror.gcr.io/library/php:8.3-apache@sha256:"
                        "f8506a19d79cad7fcf0c8049f1ed2208824961018fdc10bd80f324094dcd36bd")
#: mongection's upstream bases are `node` and `mongo` (unpinned): Node 20 and MongoDB
#: 4.4 (Mongoose 5's driver era), from Google's Docker Hub mirror.
SECDEVLABS_NODE20_IMAGE = ("mirror.gcr.io/library/node:20-alpine@sha256:"
                           "fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293")
SECDEVLABS_MONGO_IMAGE = ("mirror.gcr.io/library/mongo:4.4@sha256:"
                          "4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef")
PINNED_IMAGES = frozenset({BUSYBOX_IMAGE, PHP_IMAGE, MYSQL_IMAGE, JUICE_SHOP_IMAGE,
                           CRAWL_MAZE_PYTHON_IMAGE, SECDEVLABS_GOLANG_IMAGE,
                           SECDEVLABS_MARIADB_IMAGE, SECDEVLABS_PYTHON38_IMAGE,
                           SECDEVLABS_PYTHON312_IMAGE, SECDEVLABS_PHP_IMAGE,
                           SECDEVLABS_NODE20_IMAGE, SECDEVLABS_MONGO_IMAGE})

BWAPP_ZIP_URL = "https://sourceforge.net/projects/bwapp/files/bWAPP/bWAPP_latest.zip/download"
BWAPP_ZIP_NAME = "bWAPP_latest.zip"
BWAPP_ZIP_SHA256 = "87b5363062b4be9d2aa91916f6396f0f7d56e8acca08b732440e863f8c9e4cd6"
BWAPP_ZIP_SIZE = 15_058_349

#: Google's Security Crawl Maze (a crawler-coverage testbed: each page links one
#: resource one way, ``*.found`` expected), built from this pinned commit.
CRAWL_MAZE_REPO = "https://github.com/google/security-crawl-maze"
CRAWL_MAZE_COMMIT = "2a0dd0a75e39925ded887bcd25016e8b3ce0f2b3"
#: Its Flask app's dependencies for the image's Python (3.9: Flask 1.0.2 needs a Python
#: before 3.10's `collections` change, as upstream's own 3.6), fetched on the host and
#: installed offline by the build (a build container may sit behind a TLS-intercepting
#: proxy it does not trust), each verified by sha256.
CRAWL_MAZE_WHEELS = {
    "Flask-1.0.2-py2.py3-none-any.whl":
        "a080b744b7e345ccfcbc77954861cb05b3c63786e93f2b3875e0913d44b43f05",
    "Werkzeug-1.0.1-py2.py3-none-any.whl":
        "2de2a5db0baeae7b2d2664949077c2ac63fbd16d98da0ff71837f7d1dea3fd43",
    "Jinja2-2.11.3-py2.py3-none-any.whl":
        "03e47ad063331dd6a3f04a43eddca8a966a26ba0c5b7207a9a9e4e08f1b29419",
    ("MarkupSafe-2.0.1-cp39-cp39-manylinux_2_5_x86_64.manylinux1_x86_64."
     "manylinux_2_12_x86_64.manylinux2010_x86_64.whl"):
        "1f2ade76b9903f39aa442b4aadd2177decb66525062db244b35d71d0ee8599b6",
    "itsdangerous-1.1.0-py2.py3-none-any.whl":
        "b12271b2047cb23eeb98c8b5622e2e5c5e9abd9784a153e9d8ef9cb4dd09d749",
    "click-7.1.2-py2.py3-none-any.whl":
        "dacca89f4bfadd5de3d7489b7c8a566eee0d3676333fbb50030263894c38c0dc",
}

LAB_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PROJECT_LABEL = "com.docker.compose.project"


#: secDevLabs (globocom, BSD-3-Clause), CC-LAB-0303: a suite of small deliberately
#: vulnerable apps, one external lab per app. The source is checked out at this commit
#: on the host and each app's dependencies are fetched and verified there (the build
#: containers sit behind a TLS-intercepting proxy they do not trust); images build
#: offline.
SECDEVLABS_REPO = "https://github.com/globocom/secDevLabs"
SECDEVLABS_COMMIT = "10be438496e928c66567749f0aaf0bb976052bc9"
#: lab name -> the app's directory in the pinned checkout.
SECDEVLABS_APPS = {
    "secdevlabs-copy-n-paste": "owasp-top10-2021-apps/a3/copy-n-paste",
    "secdevlabs-gossip-world": "owasp-top10-2021-apps/a3/gossip-world",
    "secdevlabs-sstype": "owasp-top10-2021-apps/a3/sstype",
    "secdevlabs-vinijr-blog": "owasp-top10-2021-apps/a5/vinijr-blog",
    "secdevlabs-amarelo-designs": "owasp-top10-2021-apps/a8/amarelo-designs",
    "secdevlabs-mongection": "owasp-top10-2021-apps/a3/mongection",
}
#: lab name -> the Python distributions its image installs offline (`fetch_pypi_dists`):
#: the app's own requirements.txt pins, each file's sha256 as PyPI publishes it.
SECDEVLABS_PYPI = {
    # upstream's requirements say `flask` (unpinned): Flask 3.1.0 and its dependencies
    "secdevlabs-amarelo-designs": {
        "blinker-1.9.0-py3-none-any.whl":
            "ba0efaa9080b619ff2f3459d1d500c57bddea4a6b424b60a91141db6fd2f08bc",
        "click-8.5.0-py3-none-any.whl":
            "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360",
        "flask-3.1.0-py3-none-any.whl":
            "d667207822eb83f1c4b50949b1623c8fc8d51f2341d65f72e1a1815397551136",
        "itsdangerous-2.2.0-py3-none-any.whl":
            "c6242fc49e35958c8b15141343aa660db5fc54d4f13a1db01a3f5891b98700ef",
        "jinja2-3.1.6-py3-none-any.whl":
            "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67",
        ("markupsafe-3.0.4-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64."
         "manylinux_2_28_x86_64.whl"):
            "8e124f974786f831d6043728e38296969d3579db8896fe004682f5758e613581",
        "werkzeug-3.1.9-py3-none-any.whl":
            "6392e50c78460ba618e5b21f08a71f59c99ce99cdc6cf6e3dd7e6ccca8754fab",
    },
    "secdevlabs-sstype": {
        ("tornado-6.4.2-cp38-abi3-manylinux_2_5_x86_64.manylinux1_x86_64."
         "manylinux_2_17_x86_64.manylinux2014_x86_64.whl"):
            "bca9eb02196e789c9cb5c3c7c0f04fb447dc2adffd95265b2c7223a8a615ccbf",
    },
    "secdevlabs-gossip-world": {
        "Click-7.0-py2.py3-none-any.whl":
            "2335065e6395b9e67ca716de5f7526736bfa6ceead690adf616d925bdc622b13",
        "dominate-2.3.4-py2.py3-none-any.whl":
            "59abf22fe4072a97978afece563155279b3c3d6f26cb9fbbca28d0acc318cb1b",
        "Flask-1.0.2-py2.py3-none-any.whl":
            "a080b744b7e345ccfcbc77954861cb05b3c63786e93f2b3875e0913d44b43f05",
        "Flask-Bootstrap-3.3.7.1.tar.gz":
            "cb08ed940183f6343a64e465e83b3a3f13c53e1baabb8d72b5da4545ef123ac8",
        "Flask_Cors-3.0.7-py2.py3-none-any.whl":
            "7ad56ee3b90d4955148fc25a2ecaa1124fc84298471e266a7fea59aeac4405a5",
        "itsdangerous-1.1.0-py2.py3-none-any.whl":
            "b12271b2047cb23eeb98c8b5622e2e5c5e9abd9784a153e9d8ef9cb4dd09d749",
        "Jinja2-2.10-py2.py3-none-any.whl":
            "74c935a1b8bb9a3947c50a54766a969d4846290e1e788ea44c1392163723c3bd",
        "MarkupSafe-1.1.0.tar.gz":
            "4e97332c9ce444b0c2c38dd22ddc61c743eb208d916e4265a2a3b575bdccb1d3",
        "mysqlclient-1.3.13.tar.gz":
            "ff8ee1be84215e6c30a746b728c41eb0701a46ca76e343af445b35ce6250644f",
        "six-1.11.0-py2.py3-none-any.whl":
            "832dc0e10feb1aa2c68dcc57dbb658f1c7e65b9b61af69048abc87a2db00a0eb",
        "visitor-0.1.3.tar.gz":
            "2c737903b2b6864ebc6167eef7cf3b997126f1aa94bdf590f90f1436d23e480a",
        "Werkzeug-0.14.1-py2.py3-none-any.whl":
            "d5da73735293558eb1651ee2fddc4d0dedcfa06538b8813a2e20011583c9e49b",
    },
}


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
    #: None for a lab without a login (nothing to bootstrap).
    identity: str | None
    default_username: str
    #: A password may be generated when none is supplied (the account is ours to create).
    may_generate_password: bool


LAB_META: dict[str, LabMeta] = {
    "bwapp": LabMeta("bwapp", "web", "BWAPP_PORT", 8092, 80, "/bWAPP/", "/bWAPP/login.php",
                     "bwapp-bee", "bee", False),
    "juice-shop": LabMeta("juice-shop", "app", "JUICE_PORT", 3000, 3000, "/",
                          "/rest/admin/application-version", "juice-user",
                          "juice-user@fuzzlab.lab", True),
    "security-crawl-maze": LabMeta("security-crawl-maze", "app", "CRAWLMAZE_PORT", 3061,
                                   8080, "/", "/", None, "", False),
    "secdevlabs-copy-n-paste": LabMeta("secdevlabs-copy-n-paste", "api", "SDL_CNP_PORT",
                                       3071, 10001, "/", "/healthcheck", None, "", False),
    "secdevlabs-mongection": LabMeta("secdevlabs-mongection", "server", "SDL_MONGECTION_PORT",
                                     3077, 10001, "/", "/", None, "", False),
    "secdevlabs-amarelo-designs": LabMeta("secdevlabs-amarelo-designs", "app",
                                          "SDL_AMARELO_PORT", 3076, 5000, "/", "/", None,
                                          "", False),
    "secdevlabs-vinijr-blog": LabMeta("secdevlabs-vinijr-blog", "app", "SDL_VINIJR_PORT",
                                      3075, 80, "/", "/", None, "", False),
    "secdevlabs-sstype": LabMeta("secdevlabs-sstype", "server", "SDL_SSTYPE_PORT", 3073,
                                 10001, "/", "/", None, "", False),
    "secdevlabs-gossip-world": LabMeta("secdevlabs-gossip-world", "app", "SDL_GOSSIP_PORT",
                                       3072, 10007, "/", "/login", "sdl-gossip-user",
                                       "fuzzlab_user", True),
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


def crawl_maze_source(root: Path = EXTERNAL_DIR) -> Path:
    """Where the Crawl Maze's pinned source is checked out (gitignored)."""
    return root / "security-crawl-maze" / ".cache" / "src"


def dist_project(filename: str) -> tuple[str, str]:
    """``(project, version)`` of a wheel or sdist file name (PEP 427 / sdist naming)."""
    if filename.endswith(".whl"):
        parts = filename.split("-")
        return parts[0], parts[1]
    for ext_ in (".tar.gz", ".zip", ".tar.bz2"):
        if filename.endswith(ext_):
            project, _, version = filename[:-len(ext_)].rpartition("-")
            return project, version
    raise ExternalLabError(f"{filename}: not a wheel or sdist name")


def _pypi_get(url: str, timeout: float) -> bytes:
    import urllib.request
    with urllib.request.urlopen(url, timeout=timeout) as resp:      # verified TLS
        return resp.read()


def fetch_pypi_dists(pins: Mapping[str, str], dest: Path, *, timeout: float = 600.0,
                     get=_pypi_get) -> Path:
    """Download each pinned distribution (``{file name: sha256}``) from PyPI into
    ``dest`` on the host (the host's proxy and CA environment apply), so an image can
    install them with no network. PyPI's own published digest must equal the pin, and
    the bytes must hash to it; a cached file is re-hashed, never trusted; a mismatch
    leaves nothing behind and raises."""
    import hashlib
    import json as _json
    dest.mkdir(parents=True, exist_ok=True)

    def ok(name: str) -> bool:
        path = dest / name
        return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == pins[name]

    for name, digest in pins.items():
        if ok(name):
            continue
        (dest / name).unlink(missing_ok=True)       # a mismatched copy never stays
        project, version = dist_project(name)
        try:
            meta = _json.loads(get(f"https://pypi.org/pypi/{project}/{version}/json",
                                   timeout))
            entry = next(u for u in meta.get("urls", []) if u.get("filename") == name)
            if entry.get("digests", {}).get("sha256") != digest:
                raise ExternalLabError(f"{name}: PyPI publishes another sha256 than the pin")
            data = get(entry["url"], timeout)
        except ExternalLabError:
            raise
        except (OSError, ValueError, StopIteration, KeyError) as exc:
            raise ExternalLabError(f"{name}: download failed ({type(exc).__name__})") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise ExternalLabError(f"{name}: sha256 mismatch after download")
        tmp = dest / (name + ".part")
        tmp.write_bytes(data)
        tmp.replace(dest / name)
    for name in pins:
        if not ok(name):
            (dest / name).unlink(missing_ok=True)
            raise ExternalLabError(f"{name}: sha256 mismatch or missing after download")
    return dest


def fetch_crawl_maze_wheels(*, dest: Path | None = None, timeout: float = 600.0,
                            wheels: Mapping[str, str] | None = None, get=_pypi_get) -> Path:
    """The Crawl Maze image's pinned wheels in the gitignored cache (`fetch_pypi_dists`)."""
    return fetch_pypi_dists(CRAWL_MAZE_WHEELS if wheels is None else wheels,
                            crawl_maze_source().parent / "wheels" if dest is None else dest,
                            timeout=timeout, get=get)


def checkout_pinned(dest: Path, repo: str, commit: str, *, timeout: float = 600.0,
                    label: str = "checkout") -> Path:
    """Check ``repo`` out at ``commit`` into ``dest`` (gitignored cache). A checkout
    already at ``commit`` is kept; anything else there is replaced. The checkout's HEAD
    is verified -- never a substitute."""
    import shutil
    import subprocess

    from fuzzlab.procutil import run_bounded

    def git(*args: str) -> str:
        res = run_bounded(["git", "-C", str(dest), *args], timeout=timeout)
        if res.returncode != 0:
            raise ExternalLabError(f"git {args[0]} failed: {(res.stderr or '').strip()[:200]}")
        return res.stdout.strip()

    if (dest / ".git").is_dir():
        try:
            if git("rev-parse", "HEAD") == commit:
                return dest
        except ExternalLabError:
            pass
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        git("init", "-q")
        git("remote", "add", "origin", repo)
        git("fetch", "-q", "--depth", "1", "origin", commit)
        git("checkout", "-q", "--detach", "FETCH_HEAD")
        head = git("rev-parse", "HEAD")
    except (ExternalLabError, subprocess.TimeoutExpired, OSError):
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if head != commit:
        shutil.rmtree(dest, ignore_errors=True)
        raise ExternalLabError(f"{label} checkout is {head}, not {commit}")
    return dest


def fetch_crawl_maze(*, dest: Path | None = None, repo: str = CRAWL_MAZE_REPO,
                     commit: str = CRAWL_MAZE_COMMIT, timeout: float = 600.0) -> Path:
    """Check the Crawl Maze's source out at ``commit`` into the gitignored cache (its
    compose file builds from there; `checkout_pinned`)."""
    return checkout_pinned(crawl_maze_source() if dest is None else dest, repo, commit,
                           timeout=timeout, label="crawl maze")


def secdevlabs_checkout(root: Path = EXTERNAL_DIR) -> Path:
    """The one pinned secDevLabs checkout every app lab copies from (gitignored)."""
    return root / ".cache" / "secdevlabs" / "src"


def go_vendor(moddir: Path, *, timeout: float = 900.0) -> None:
    """Fetch a Go module's dependencies with the host's Go, verify every one against
    the module's own ``go.sum`` (``go mod verify``), and vendor them, so its image
    builds offline. Raises when Go is missing or any module fails verification."""
    import shutil

    from fuzzlab.procutil import run_bounded
    go = shutil.which("go")
    if go is None:
        raise ExternalLabError("Go is not installed on this host: needed to vendor the "
                               "app's modules (they are verified against its go.sum)")
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
    for args in (["mod", "download"], ["mod", "verify"], ["mod", "vendor"]):
        res = run_bounded([go, *args], timeout=timeout, cwd=str(moddir), env=env)
        if res.returncode != 0:
            raise ExternalLabError(f"go {' '.join(args)} failed: "
                                   f"{(res.stderr or res.stdout or '').strip()[-200:]}")
        if args[1] == "verify" and "all modules verified" not in (res.stdout or ""):
            raise ExternalLabError("go mod verify did not verify every module")


def npm_install(pkgdir: Path, *, timeout: float = 900.0) -> None:
    """Install a Node package's locked dependencies with the host's npm (``npm ci``:
    exactly the lockfile, each package checked against its ``integrity`` hash; no
    install scripts), so its image needs no registry. Raises when npm is missing or
    the install fails (an integrity mismatch fails it)."""
    import shutil

    from fuzzlab.procutil import run_bounded
    npm = shutil.which("npm")
    if npm is None:
        raise ExternalLabError("npm is not installed on this host: needed to install the "
                               "app's locked packages (checked against its lockfile)")
    res = run_bounded([npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
                      timeout=timeout, cwd=str(pkgdir))
    if res.returncode != 0 or not (pkgdir / "node_modules").is_dir():
        raise ExternalLabError(f"npm ci failed: {(res.stderr or res.stdout or '').strip()[-200:]}")


def fetch_secdevlabs_app(lab: str, *, root: Path = EXTERNAL_DIR, repo: str = SECDEVLABS_REPO,
                         commit: str = SECDEVLABS_COMMIT, timeout: float = 900.0) -> Path:
    """The app of secDevLabs lab ``lab``, copied from the pinned checkout into
    ``<lab>/.cache/app`` with its dependencies fetched and verified on the host (Go:
    `go_vendor`). The image builds from there with no network."""
    import shutil
    if lab not in SECDEVLABS_APPS:
        raise ExternalLabError(f"{lab!r} is not a secDevLabs app lab")
    src = checkout_pinned(secdevlabs_checkout(root), repo, commit, timeout=timeout,
                          label="secDevLabs")
    dest = root / lab / ".cache" / "app"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src / SECDEVLABS_APPS[lab], dest, symlinks=True)
    for gomod in sorted(dest.rglob("go.mod")):
        go_vendor(gomod.parent, timeout=timeout)
    for lock in sorted(dest.rglob("package-lock.json")):
        if "node_modules" not in lock.parts:
            npm_install(lock.parent, timeout=timeout)
    if lab in SECDEVLABS_PYPI:
        fetch_pypi_dists(SECDEVLABS_PYPI[lab], root / lab / ".cache" / "dists",
                         timeout=timeout)
    return dest


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
    identity: str | None
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


_CSRF_FIELD = re.compile(r'name="_csrf_token"[^>]*value="([^"]+)"')


def bootstrap_secdevlabs_gossip_world(client: _LabClient, cred: ResolvedCredential, *,
                                      deadline: float = 180.0,
                                      clock: Callable[[], float] = time.monotonic,
                                      sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """Log in through the app's own form (its session-bound ``_csrf_token`` read from the
    form first), registering the account the same way when the login fails, and verify
    it by a positive differential: ``/gossip`` answers 200 with the session and
    redirects to ``/login`` without it."""
    meta = LAB_META["secdevlabs-gossip-world"]
    wait_ready(client, meta.ready_path, deadline=deadline, clock=clock, sleep=sleep)
    notes: list[str] = []

    def post_form(path: str, fields: dict[str, str]) -> Any:
        m = _CSRF_FIELD.search(client.request("GET", path).text or "")
        if m is None:
            raise ExternalLabError(f"gossip-world {path}: no _csrf_token in the form")
        return client.request("POST", path, data={**fields, "_csrf_token": m.group(1)})

    def logged_in() -> bool:
        r = post_form("/login", {"username": cred.username, "password": cred.password})
        return r.status_code == 302 and r.headers.get("Location", "").endswith("/gossip")

    if not logged_in():
        reg = post_form("/register", {"username": cred.username, "password1": cred.password,
                                      "password2": cred.password})
        if reg.status_code != 302 or not reg.headers.get("Location", "").endswith("/login"):
            raise ExternalLabError(f"gossip-world registration failed: HTTP {reg.status_code}")
        notes.append("account registered")
        if not logged_in():
            raise ExternalLabError(
                "gossip-world login failed after registration (an account of that name with "
                "another password? run `./labctl.sh reset secdevlabs-gossip-world --authorized`)")
    authed = client.request("GET", "/gossip")
    anon = client.request("GET", "/gossip", anonymous=True)
    if authed.status_code != 200 or anon.status_code != 302:
        raise ExternalLabError(f"gossip-world /gossip: {anon.status_code} anonymous, "
                               f"{authed.status_code} logged in (want 302 / 200)")
    notes.append("login verified")
    # the comment form lives on a gossip's own page: a fresh lab has none, so one is
    # seeded (once), and /gossip/1 -- the ground truth's comment point -- exists
    if 'href="/gossip/1"' not in (authed.text or ""):
        post_form("/newgossip", {"title": "Welcome", "subtitle": "a seeded gossip",
                                 "text": "The lab's first gossip (bootstrap)."})
        if 'href="/gossip/1"' not in (client.request("GET", "/gossip").text or ""):
            raise ExternalLabError("gossip-world: the seeded gossip is not /gossip/1 "
                                   "(reset the lab: ./labctl.sh reset ... --authorized)")
        notes.append("gossip 1 seeded")
    return notes


_BOOTSTRAPS = {"bwapp": bootstrap_bwapp, "juice-shop": bootstrap_juice_shop,
               "secdevlabs-gossip-world": bootstrap_secdevlabs_gossip_world}


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
    if meta.identity is None:
        return BootstrapResult(name, None, "none", False, ["no login: nothing to bootstrap"])
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
    s = sub.add_parser("fetch", help="fetch and verify a lab's pinned source (bWAPP's zip, "
                                     "the Crawl Maze's commit) into the cache")
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
            if meta.name in SECDEVLABS_APPS:
                print(f"secDevLabs at {SECDEVLABS_COMMIT[:12]}, {meta.name}'s app and its "
                      f"verified dependencies: {fetch_secdevlabs_app(meta.name)}")
                return 0
            if meta.name == "security-crawl-maze":
                print(f"crawl maze source at {CRAWL_MAZE_COMMIT[:12]}: {fetch_crawl_maze()}")
                print(f"crawl maze wheels verified: {fetch_crawl_maze_wheels()}")
                return 0
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
            if res.identity is None:
                print(f"{res.lab}: " + "; ".join(res.notes))
                return 0
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
