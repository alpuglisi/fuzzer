"""Static checks for the external lab fixtures (bWAPP, Juice Shop): CC-LAB-0300,
CC-LAB-0301, FR-LAB-300..304. Always run; nothing here starts a container or sends
traffic.

* loopback: every compose file under ``lab/`` and every shell script under ``lab/`` and
  ``scripts/`` publishes on loopback only (BUG-0130 / PA-0130 lint, extended to the new
  fixtures), proven on synthetic offenders (PA-0034(2));
* pins: images registry-qualified (PA-0060) and pinned by digest, equal to the one
  source of truth in ``fuzzlab.lab_fixtures.external`` (PA-0001);
* licence: no bWAPP byte is tracked, and the build verifies the zip's sha256 (the verify
  block is run for real on temp files);
* ground truth: both contracts load, use only scoreable classes, carry reach and
  provenance tags, and every point passes the destructive and transaction rules;
* the label environment (Juice Shop ``NODE_ENV: unsafe``);
* the Python side: fetch, pre-flight, exposure check and bootstrap against fakes.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

from fuzzlab.lab_fixtures import external as ext
from fuzzlab.labels import contract
from fuzzlab.procutil import run_bounded

REPO = Path(__file__).resolve().parent.parent
LAB = REPO / "lab"
EXTERNAL = LAB / "external"
GT_DIRS = {"bwapp": LAB / "ground-truth-bwapp", "juice-shop": LAB / "ground-truth-juice-shop"}


# --- 1. compose loopback lint (every compose file under lab/) ------------------------------

def _compose_files() -> list[Path]:
    return sorted(p for p in LAB.rglob("compose*.y*ml") if ".cache" not in p.parts)


def test_the_lint_sees_every_compose_file_including_the_new_fixtures():
    files = {p.relative_to(REPO).as_posix() for p in _compose_files()}
    assert {"lab/compose.yaml", "lab/external/bwapp/compose.yaml",
            "lab/external/juice-shop/compose.yaml"} <= files


@pytest.mark.parametrize("path", _compose_files(), ids=lambda p: p.relative_to(REPO).as_posix())
def test_every_compose_file_publishes_on_loopback_only(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert ext.config_problems(doc) == []


_COMPOSE_OFFENDERS = {
    "0.0.0.0 host": {"services": {"a": {"ports": ["0.0.0.0:80:80"]}}},
    "bare host:container": {"services": {"a": {"ports": ["8092:80"]}}},
    "container port only": {"services": {"a": {"ports": ["3000"]}}},
    "int port": {"services": {"a": {"ports": [3000]}}},
    "IPv6 wildcard": {"services": {"a": {"ports": ["[::]:80:80"]}}},
    "routable address": {"services": {"a": {"ports": ["192.168.1.5:80:80"]}}},
    "interpolated host": {"services": {"a": {"ports": ["${HOST_IP:-127.0.0.1}:80:80"]}}},
    "localhost name": {"services": {"a": {"ports": ["localhost:80:80"]}}},
    "range without host": {"services": {"a": {"ports": ["8000-8010:8000-8010"]}}},
    "long syntax without host_ip": {"services": {"a": {"ports": [{"target": 80,
                                                                   "published": 8092}]}}},
    "long syntax empty host_ip": {"services": {"a": {"ports": [{"target": 80, "host_ip": ""}]}}},
    "long syntax wildcard": {"services": {"a": {"ports": [{"target": 80, "host_ip": "0.0.0.0"}]}}},
    "host network": {"services": {"a": {"network_mode": "host"}}},
    "host pid": {"services": {"a": {"pid": "host"}}},
    "privileged": {"services": {"a": {"privileged": True}}},
    "another project's container": {"services": {"a": {"network_mode": "container:other"}}},
    "unknown service namespace": {"services": {"a": {"network_mode": "service:ghost"}}},
}


@pytest.mark.parametrize("name", sorted(_COMPOSE_OFFENDERS))
def test_the_compose_lint_flags_synthetic_offenders(name):
    assert ext.config_problems(_COMPOSE_OFFENDERS[name]), name


@pytest.mark.parametrize("ports", [
    ["127.0.0.1:8092:80"], ["127.0.0.1:${BWAPP_PORT:-8092}:80"], ["127.0.0.1:8000-8010:8000-8010"],
    ["[::1]:80:80/tcp"], ["127.0.0.1::80"],
    [{"target": 80, "published": "8092", "host_ip": "127.0.0.1"}],
])
def test_the_compose_lint_passes_loopback_bindings(ports):
    doc = {"services": {"a": {"ports": ports}, "b": {"network_mode": "service:a"},
                        "c": {"network_mode": "none"}}}
    assert ext.config_problems(doc) == []


# --- 2. shell publish lint (lab/ and scripts/) --------------------------------------------

_RUN_LINE = re.compile(r"\b(?:docker|podman)\s+(?:container\s+)?run\b")
_PUBLISH = re.compile(r"(?:^|\s)(?:-p|--publish)(?:\s+|=)(\S+)")
_HOST_NET = re.compile(r"--(?:network|net)(?:\s+|=)host\b")


def shell_publish_problems(text: str, name: str = "<mem>") -> list[str]:
    """A ``docker|podman run`` (continuation lines joined) that publishes a port without
    a literal 127.0.0.1 host, or that uses the host network."""
    out = []
    joined = re.sub(r"\\\n", " ", text)
    for n, line in enumerate(joined.splitlines(), 1):
        if line.lstrip().startswith("#") or not _RUN_LINE.search(line):
            continue
        if _HOST_NET.search(line):
            out.append(f"{name}:{n}: host network")
        for spec in _PUBLISH.findall(line):
            if not spec.strip("'\"").startswith("127.0.0.1:"):
                out.append(f"{name}:{n}: publishes {spec}")
    return out


def _shell_files() -> list[Path]:
    return sorted([*LAB.rglob("*.sh"), *(REPO / "scripts").rglob("*.sh")])


def test_no_shell_script_publishes_beyond_loopback():
    problems = []
    for path in _shell_files():
        problems += shell_publish_problems(path.read_text(encoding="utf-8"),
                                           path.relative_to(REPO).as_posix())
    assert problems == []


@pytest.mark.parametrize("src", [
    "docker run -d -p 3000:3000 img\n",
    "podman run -p 0.0.0.0:80:80 img\n",
    "docker run --publish=8080:80 img\n",
    "docker container run \\\n  -p 9000:9000 img\n",
    "docker run --network host img\n",
    "podman run --net=host img\n",
])
def test_the_shell_lint_flags_synthetic_offenders(src):
    assert shell_publish_problems(src), src


def test_the_shell_lint_passes_loopback_publishes():
    assert shell_publish_problems("docker run -p 127.0.0.1:3000:3000 img\n"
                                  "# docker run -p 80:80 (a comment)\n") == []


# --- 3. pins --------------------------------------------------------------------------

def _image_refs() -> list[tuple[str, str]]:
    refs = []
    for path in sorted(EXTERNAL.rglob("*")):
        if path.name == "Dockerfile":
            for m in re.finditer(r"^FROM\s+(\S+)", path.read_text("utf-8"), re.M):
                refs.append((path.relative_to(REPO).as_posix(), m.group(1)))
        elif path.name == "compose.yaml":
            for name, svc in (yaml.safe_load(path.read_text("utf-8"))["services"]).items():
                if "image" in svc:
                    refs.append((f"{path.relative_to(REPO).as_posix()}:{name}", svc["image"]))
    return refs


def test_every_external_image_is_registry_qualified_and_pinned_by_digest():
    refs = _image_refs()
    assert len(refs) == len(ext.PINNED_IMAGES)
    for where, ref in refs:
        host = ref.split("/", 1)[0]
        assert "." in host, f"{where}: {ref} is not registry-qualified (PA-0060)"
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{where}: {ref} is not digest-pinned"
        assert ref in ext.PINNED_IMAGES, f"{where}: {ref} differs from the pinned constant"


def test_every_service_without_a_build_has_a_pinned_image():
    for path in sorted(EXTERNAL.glob("*/compose.yaml")):
        for name, svc in yaml.safe_load(path.read_text("utf-8"))["services"].items():
            assert "build" in svc or svc.get("image") in ext.PINNED_IMAGES, (path, name)


# --- 4. licence: the build verifies the zip; nothing of bWAPP is tracked -----------------

DOCKERFILE = EXTERNAL / "bwapp" / "Dockerfile"


def _stages(text: str) -> list[str]:
    parts = re.split(r"(?m)^(?=FROM\s)", text)
    return [p for p in parts if p.startswith("FROM")]


def _verify_block(text: str) -> str:
    begin = text.index("# VERIFY_BLOCK_BEGIN")
    end = text.index("# VERIFY_BLOCK_END")
    lines = [ln for ln in text[begin:end].splitlines() if not ln.lstrip().startswith("#")]
    body = re.sub(r"\\\n", " ", "\n".join(lines)).strip()
    assert body.startswith("RUN "), body
    return body[4:]


def test_the_verify_step_uses_only_variables_declared_in_its_own_stage():
    """An ARG declared before the first FROM is empty inside a stage (review A1)."""
    text = DOCKERFILE.read_text("utf-8")
    stage = next(s for s in _stages(text) if "# VERIFY_BLOCK_BEGIN" in s)
    declared = set(re.findall(r"(?m)^ARG\s+([A-Z0-9_]+)", stage))
    for env_line in re.findall(r"(?m)^ENV\s+(.+)$", stage):
        declared |= set(re.findall(r"([A-Z0-9_]+)=", env_line))
    used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", _verify_block(text)))
    assert "BWAPP_SHA256" in used and used <= declared, used - declared


def test_the_pinned_sha256_is_the_dockerfile_default_and_checked_before_unzip():
    text = DOCKERFILE.read_text("utf-8")
    assert re.search(rf"(?m)^ARG BWAPP_SHA256={ext.BWAPP_ZIP_SHA256}$", text)
    block = _verify_block(text)
    assert block.index("sha256sum -c") < block.index("unzip")
    assert "|| true" not in block and "set +e" not in block


def _zip_with_install_php() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bWAPP/install.php", "<?php // fixture\n")
        zf.writestr("README.txt", "outside bWAPP/\n")
    return buf.getvalue()


def _run_verify(tmp_path: Path, sha: str) -> tuple[subprocess.CompletedProcess, Path]:
    data = _zip_with_install_php()
    z = tmp_path / "in.zip"
    z.write_bytes(data)
    dest = tmp_path / "dest"
    shell = shutil.which("busybox")
    argv = [shell, "sh", "-c"] if shell else ["sh", "-c"]   # the image's shell, never bash
    env = {"PATH": "/usr/bin:/bin", "ZIP": str(z), "DEST": str(dest), "BWAPP_SHA256": sha}
    res = run_bounded([*argv, _verify_block(DOCKERFILE.read_text("utf-8"))], timeout=30,
                      cwd=str(tmp_path), env=env)
    return res, dest


@pytest.mark.skipif(shutil.which("unzip") is None and shutil.which("busybox") is None,
                    reason="no unzip on this host for the matching-hash case")
def test_the_verify_block_extracts_on_the_right_hash(tmp_path):
    sha = hashlib.sha256(_zip_with_install_php()).hexdigest()
    res, dest = _run_verify(tmp_path, sha)
    assert res.returncode == 0, res.stderr
    assert (dest / "bWAPP" / "install.php").is_file()
    assert not (dest / "README.txt").exists()          # only bWAPP/* is extracted


@pytest.mark.parametrize("sha", ["0" * 64, ""], ids=["wrong", "empty"])
def test_the_verify_block_fails_and_extracts_nothing_on_a_bad_hash(tmp_path, sha):
    res, dest = _run_verify(tmp_path, sha)
    assert res.returncode != 0
    assert not dest.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["in.zip"]


def test_nothing_disables_tls_verification():
    for path in (Path(ext.__file__), DOCKERFILE, EXTERNAL / "extctl.sh"):
        text = path.read_text("utf-8")
        assert "verify=False" not in text and "--insecure" not in text, path
        assert not re.search(r"\bcurl\b[^\n]*\s-k\b", text), path


#: Built from parts so this file does not itself match.
_BANNERS = ("bWAPP, or a buggy " + "web application", "Malik " + "Mesellem", "MME " + "BVBA",
            "@MME" + "_IT")
_PAGE_SET = {"sqli_1.php", "xss_get.php", "htmli_get.php", "bugs.txt", "install.php",
             "portal.php"}


def licence_problems(files: dict[str, bytes]) -> list[str]:
    out = []
    for rel, data in files.items():
        parts = rel.split("/")
        if "bWAPP" in parts[:-1]:
            out.append(f"{rel}: a bWAPP/ directory")
        if rel.startswith("lab/") and rel.endswith(".zip"):
            out.append(f"{rel}: an archive under lab/")
        if parts[-1] in _PAGE_SET:
            out.append(f"{rel}: a bWAPP page file name")
        text = data.decode("utf-8", "replace")
        out += [f"{rel}: bWAPP banner text" for b in _BANNERS if b in text]
    return out


def _tracked() -> dict[str, bytes]:
    names = run_bounded(["git", "ls-files", "-z"], timeout=60, cwd=str(REPO)).stdout
    out = {}
    for rel in filter(None, names.split("\0")):
        path = REPO / rel
        if path.is_file():
            out[rel] = path.read_bytes()
    return out


def test_no_bwapp_source_is_tracked():
    assert licence_problems(_tracked()) == []


def test_the_licence_guard_flags_a_synthetic_bwapp_tree():
    banner = ("<?php /* " + _BANNERS[0] + " */").encode()
    assert len(licence_problems({
        "lab/external/bwapp/bWAPP/sqli_1.php": banner,
        "lab/bWAPP_latest.zip": b"PK",
        "docs/x.md": ("Copyright " + _BANNERS[2]).encode(),
        "tests/fixtures/page.html": ("<p>" + _BANNERS[3] + "</p>").encode(),
    })) >= 5


def test_the_bwapp_cache_and_trees_are_gitignored():
    for rel in ("lab/external/bwapp/.cache/bWAPP_latest.zip", "lab/external/bwapp/bWAPP/x.php",
                "lab/external/bwapp/other.zip"):
        res = run_bounded(["git", "check-ignore", "-q", rel], timeout=30, cwd=str(REPO))
        assert res.returncode == 0, rel


# --- 5. ground truth -------------------------------------------------------------------

def scoreable_classes() -> set[str]:
    """A class is in scope iff it is in the labels-schema enum, some default strategy
    records it, and its category has a rule (design rev 2, 5.1; PA-0001: derived)."""
    from fuzzlab.audit.rules import load_rules
    from fuzzlab.core.runmode import to_category
    from fuzzlab.oracle.strategies import default_strategies
    schema = json.loads((REPO / "fuzzlab/labels/schemas/labels.schema.json").read_text())
    enum = set(schema["$defs"]["case"]["properties"]["vuln_class"]["enum"]) - {"none"}
    recorded = {s.vuln_class for s in default_strategies()}
    ruled = {r.category for r in load_rules()}
    return {vc for vc in enum & recorded if to_category(vc) in ruled}


_REACH = re.compile(r"^\[reach: (crawl,gt|crawl|gt|none - [^\]]+)\] \[prov: ([^\]]+)\] \S")


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_each_ground_truth_dir_loads(lab):
    gt = contract.load(GT_DIRS[lab])
    assert gt.positives() and gt.negatives()


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_ground_truth_uses_only_scoreable_classes(lab):
    allowed = scoreable_classes()
    for case in contract.load(GT_DIRS[lab]).cases:
        assert case.vuln_class in allowed, (case.case_id, case.vuln_class)


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_every_case_carries_reach_and_provenance_tags(lab):
    for case in contract.load(GT_DIRS[lab]).cases:
        assert case.notes and _REACH.match(case.notes), case.case_id


def reach_of(case) -> set[str]:
    tag = _REACH.match(case.notes).group(1)
    return set() if tag.startswith("none") else set(tag.split(","))


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_every_reachable_case_has_its_point(lab):
    gt = contract.load(GT_DIRS[lab])
    points = {p.key for p in gt.points}
    for case in gt.cases:
        if not reach_of(case):
            continue        # [reach: none] (B-r2.6)
        if case.vuln_class == "xss-stored" and case.source_url:
            assert any(k[0] == case.source_url for k in points), case.case_id
        else:
            assert (case.url, case.method, case.param) in points, case.case_id


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_case_ids_are_opaque(lab):
    words = {w for vc in scoreable_classes() for w in re.split(r"[-_]", vc)}
    for case in contract.load(GT_DIRS[lab]).cases:
        assert re.fullmatch(r"[A-Z]+-\d{4}", case.case_id)
        assert not any(w.upper() in case.case_id for w in words if len(w) > 2)


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_negatives_are_testable_by_a_run_derived_from_the_positives(lab):
    """D14 derives a run's categories from the positives: a negative of another category
    would never get a candidate (B-r2.4)."""
    from fuzzlab.core.runmode import categories_from_vuln_classes, to_category
    gt = contract.load(GT_DIRS[lab])
    cats = set(categories_from_vuln_classes(c.vuln_class for c in gt.positives()))
    for case in gt.negatives():
        assert to_category(case.vuln_class) in cats, case.case_id


def gt_point_problems(points) -> list[str]:
    from fuzzlab.core.urls import destructive_reason, transaction_reason
    out = []
    for p in points:
        for rule in (destructive_reason, transaction_reason):
            if rule(p.url) is not None:
                out.append(f"{p.url}: {rule.__name__}")
    return out


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_every_ground_truth_point_passes_the_destructive_and_transaction_rules(lab):
    """A ground-truth point is exempt from the send gate (allow_explicit), so the
    contract itself must never name a destructive or transaction URL (B9)."""
    assert gt_point_problems(contract.load(GT_DIRS[lab]).points) == []


def test_the_ground_truth_point_check_flags_synthetic_offenders():
    pts = [contract.InjectionPoint("/bWAPP/update.php", "GET", "x", "query"),
           contract.InjectionPoint("/rest/basket/1/checkout", "POST", "x", "body")]
    assert len(gt_point_problems(pts)) == 2


@pytest.mark.parametrize("lab", sorted(GT_DIRS))
def test_the_expected_results_csv_is_tracked_not_ignored(lab):
    rel = (GT_DIRS[lab] / "expectedresults.csv").relative_to(REPO).as_posix()
    res = run_bounded(["git", "check-ignore", "-q", rel], timeout=30, cwd=str(REPO))
    assert res.returncode == 1, f"{rel} is gitignored (PA-0038)"


# --- 6. label environment and registry --------------------------------------------------

def test_juice_shop_runs_with_its_unsafe_config():
    doc = yaml.safe_load((EXTERNAL / "juice-shop/compose.yaml").read_text("utf-8"))
    assert doc["services"]["app"]["environment"]["NODE_ENV"] == "unsafe"


def test_the_registry_is_the_directory_layout():
    labs = ext.discover_labs()
    assert set(labs) == set(ext.LAB_META) == set(GT_DIRS)
    for name, compose in labs.items():
        assert ext.compose_project(compose) == f"fuzzlab-{name}"
        doc = yaml.safe_load(compose.read_text("utf-8"))
        ports = [p for s in doc["services"].values() for p in s.get("ports", [])]
        meta = ext.LAB_META[name]
        assert ports == [f"127.0.0.1:${{{meta.port_env}:-{meta.default_port}}}:"
                         f"{meta.container_port}"]


def test_the_bwapp_db_has_no_network_and_its_socket_volume_is_tmpfs():
    doc = yaml.safe_load((EXTERNAL / "bwapp/compose.yaml").read_text("utf-8"))
    assert doc["services"]["db"]["network_mode"] == "none"
    assert "ports" not in doc["services"]["db"]
    assert doc["volumes"]["bwapp-mysqld-sock"]["driver_opts"]["type"] == "tmpfs"


def test_every_external_service_drops_capabilities():
    for path in sorted(EXTERNAL.glob("*/compose.yaml")):
        for name, svc in yaml.safe_load(path.read_text("utf-8"))["services"].items():
            assert svc.get("cap_drop") == ["ALL"], (path, name)
            assert "no-new-privileges:true" in svc.get("security_opt", []), (path, name)


# --- 7. fetch -------------------------------------------------------------------------

class _Resp:
    def __init__(self, status=200, body=b"", headers=None, text=None, js=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.text = text if text is not None else body.decode("latin-1")
        self._js = js

    def iter_content(self, n):
        for i in range(0, len(self._body), max(n, 1)):
            yield self._body[i:i + n]

    def json(self):
        if self._js is None:
            raise ValueError("no json")
        return self._js

    def close(self):
        pass


class _FetchSession:
    def __init__(self, hops):
        self.hops = list(hops)
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.hops.pop(0)


def test_fetch_follows_https_redirects_and_verifies(tmp_path):
    body = b"x" * 1000
    sess = _FetchSession([_Resp(302, headers={"Location": "https://mirror.example/f.zip"}),
                          _Resp(200, body)])
    out = ext.fetch_bwapp(session=sess, dest=tmp_path / "c" / "z.zip",
                          sha256=hashlib.sha256(body).hexdigest(), size=len(body))
    assert out.read_bytes() == body
    assert all(kw["allow_redirects"] is False and kw["timeout"] for _, kw in sess.calls)
    assert [p.name for p in (tmp_path / "c").iterdir()] == ["z.zip"]


@pytest.mark.parametrize("hops,size_delta", [
    ([_Resp(200, b"y" * 1000)], 0),                                          # wrong hash
    ([_Resp(200, b"x" * 999)], 0),                                           # short
    ([_Resp(200, b"x" * 1001)], 0),                                          # long
    ([_Resp(302, headers={"Location": "http://mirror.example/f.zip"})], 0),  # downgrade
    ([_Resp(404)], 0),
])
def test_fetch_refuses_a_mismatch_and_leaves_nothing(tmp_path, hops, size_delta):
    body = b"x" * 1000
    with pytest.raises(ext.ExternalLabError):
        ext.fetch_bwapp(session=_FetchSession(hops), dest=tmp_path / "c" / "z.zip",
                        sha256=hashlib.sha256(body).hexdigest(), size=len(body))
    assert list((tmp_path / "c").iterdir()) == []


def test_fetch_rehashes_a_cached_file_and_replaces_a_bad_one(tmp_path):
    body = b"x" * 10
    dest = tmp_path / "z.zip"
    dest.write_bytes(b"tampered!!")
    sess = _FetchSession([_Resp(200, body)])
    ext.fetch_bwapp(session=sess, dest=dest, sha256=hashlib.sha256(body).hexdigest(), size=10)
    assert dest.read_bytes() == body and len(sess.calls) == 1
    ext.fetch_bwapp(session=_FetchSession([]), dest=dest,
                    sha256=hashlib.sha256(body).hexdigest(), size=10)   # valid cache: no call


# --- 8. exposure check --------------------------------------------------------------------

class _L:
    def __init__(self, address, port):
        self.address, self.port = address, port

    def is_loopback(self):
        import ipaddress
        return ipaddress.ip_address(self.address).is_loopback


def _inspect(host_ip="127.0.0.1", port="8092", mode="bridge"):
    return {"Name": "/x", "HostConfig": {"NetworkMode": mode,
                                         "PortBindings": {"80/tcp": [{"HostIp": host_ip,
                                                                      "HostPort": port}]}}}


def test_a_loopback_publish_passes():
    problems, notes = ext.exposure_problems([_inspect()], [_L("127.0.0.1", 8092)])
    assert problems == [] and notes == []


@pytest.mark.parametrize("inspects,listeners", [
    ([], []),                                                    # nothing found: fail closed
    ([_inspect(host_ip="")], []),                                # "" = every interface
    ([_inspect(host_ip="0.0.0.0")], []),
    ([_inspect(host_ip="::")], []),
    ([_inspect(mode="host")], []),
    ([_inspect()], [_L("0.0.0.0", 8092)]),                       # a wildcard host listener
    ([_inspect()], [_L("::", 8092)]),
])
def test_the_exposure_check_fails_closed(inspects, listeners):
    problems, _ = ext.exposure_problems(inspects, listeners)
    assert problems


def test_an_empty_host_ip_is_named_as_every_interface():
    problems, _ = ext.exposure_problems([_inspect(host_ip="")], [])
    assert any("every interface" in p for p in problems), problems


def test_a_nat_only_publish_is_a_note_not_a_pass_or_a_failure():
    problems, notes = ext.exposure_problems([_inspect()], [])
    assert problems == [] and notes


class _Runner:
    def __init__(self, ps="", inspect="[]", fail=None):
        self.ps, self.inspect, self.fail = ps, inspect, fail
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        rc = 1 if self.fail and self.fail in argv else 0
        out = self.ps if "ps" in argv else self.inspect
        return subprocess.CompletedProcess(argv, rc, out, "")


def test_check_exposure_selects_by_the_exact_project_label():
    r = _Runner(ps="abc\n", inspect=json.dumps([_inspect()]))
    problems, _ = ext.check_exposure("fuzzlab-bwapp", "docker", runner=r,
                                     listeners=lambda: [_L("127.0.0.1", 8092)])
    assert problems == []
    assert "label=com.docker.compose.project=fuzzlab-bwapp" in r.calls[0]
    assert r.calls[1][:2] == ["docker", "inspect"]


@pytest.mark.parametrize("runner", [_Runner(ps=""), _Runner(ps="abc", fail="inspect"),
                                    _Runner(ps="abc", inspect="not json"),
                                    _Runner(fail="ps")])
def test_check_exposure_fails_closed_on_engine_errors(runner):
    problems, _ = ext.check_exposure("p", "podman", runner=runner, listeners=lambda: [])
    assert problems


def test_host_listen_sockets_sees_a_real_loopback_listener():
    import socket
    from fuzzlab.procutil import host_listen_sockets
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        found = [lst for lst in host_listen_sockets() if lst.port == port]
        assert found and all(lst.is_loopback() for lst in found)
    finally:
        s.close()


# --- 9. bootstrap ---------------------------------------------------------------------

class _Jar(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


class _FakeLabSession:
    """Routes ``(method, path)`` to a handler; records every call's kwargs."""

    def __init__(self, routes, log):
        self.routes, self.log = routes, log
        self.cookies = _Jar()
        self.headers = {}
        self.trust_env = True
        self.proxies = {"http": "http://proxy"}

    def request(self, method, url, **kw):
        from urllib.parse import urlsplit
        self.log.append((method, url, kw, self))
        return self.routes[(method, urlsplit(url).path)](self, kw)


def _bwapp_routes(password_ok="bug", level_set=None):
    def install(s, kw):
        return _Resp(200, text="<p>The bWAPP database already exists...</p>")

    def portal(s, kw):
        if s.cookies.get("PHPSESSID") == "auth":
            return _Resp(200, text="portal")
        return _Resp(302, headers={"Location": "login.php"})

    def login(s, kw):
        if kw["data"]["password"] != password_ok:
            return _Resp(200, text="Invalid credentials")
        s.cookies["PHPSESSID"] = "auth"
        s.cookies["security_level"] = level_set or kw["data"]["security_level"]
        return _Resp(302, headers={"Location": "portal.php"})

    return {("GET", "/bWAPP/login.php"): lambda s, kw: _Resp(200, text="login"),
            ("GET", "/bWAPP/install.php"): install, ("GET", "/bWAPP/portal.php"): portal,
            ("POST", "/bWAPP/login.php"): login}


class _Store:
    def __init__(self, cred=None):
        self.cred, self.sets = cred, []

    def get(self, host, identity):
        return self.cred

    def set(self, host, identity, username, password):
        self.sets.append((host, identity, username, password))


class _Cred:
    def __init__(self, u, p):
        self.username, self.password = u, p


def _boot(name, routes, keyring, opened, log, **kw):
    return ext.bootstrap(name, environ={}, keyring_store=keyring, opened_store=opened,
                         session_factory=lambda: _FakeLabSession(routes, log),
                         deadline=1.0, **kw)


def test_bwapp_bootstrap_stores_only_after_a_verified_level_0_login(capsys, caplog):
    log = []
    keyring = _Store()
    res = _boot("bwapp", _bwapp_routes(), keyring, _Store(_Cred("bee", "bug")), log)
    assert res.stored and keyring.sets == [("127.0.0.1", "bwapp-bee", "bee", "bug")]
    assert res.credential_source == "env"
    for method, url, kw, sess in log:
        assert url.startswith("http://127.0.0.1:8092/")
        assert kw["allow_redirects"] is False and kw["timeout"]
        assert sess.trust_env is False and sess.proxies == {}
    out = capsys.readouterr()
    assert "bug" not in out.out + out.err + caplog.text


def test_bwapp_bootstrap_never_stores_an_unverified_password():
    keyring = _Store()
    with pytest.raises(ext.ExternalLabError, match="reset bwapp"):
        _boot("bwapp", _bwapp_routes(password_ok="other"), keyring,
              _Store(_Cred("bee", "bug")), [])
    assert keyring.sets == []


def test_bwapp_bootstrap_refuses_a_login_that_is_not_level_0():
    keyring = _Store()
    with pytest.raises(ext.ExternalLabError, match="security level"):
        _boot("bwapp", _bwapp_routes(level_set="2"), keyring, _Store(_Cred("bee", "bug")), [])
    assert keyring.sets == []


def test_a_keyring_credential_is_not_rewritten():
    keyring = _Store(_Cred("bee", "bug"))
    res = _boot("bwapp", _bwapp_routes(), keyring, _Store(), [])
    assert res.credential_source == "keyring" and not res.stored and keyring.sets == []


def _juice_routes(state):
    def cfg(s, kw):
        return _Resp(200, js={"config": {"challenges": {"safetyMode": state["mode"]}}})

    def login(s, kw):
        body = kw["json"]
        if state["users"].get(body["email"]) == body["password"]:
            return _Resp(200, js={"authentication": {"token": "T-" + body["email"]}})
        return _Resp(401, text="Invalid email or password.")

    def register(s, kw):
        body = kw["json"]
        assert "role" not in body and body["password"] == body["passwordRepeat"]
        if body["email"] in state["users"]:
            return _Resp(400, text='{"message":"Validation error","errors":'
                                   '[{"message":"email must be unique"}]}')
        state["users"][body["email"]] = body["password"]
        return _Resp(201, js={"status": "success"})

    def whoami(s, kw):
        tok = (kw.get("cookies") or {}).get("token", "")
        return _Resp(200, js={"user": {"email": tok[2:]} if tok else {}})

    def profile(s, kw):
        return _Resp(200 if (kw.get("cookies") or {}).get("token") else 500)

    return {("GET", "/rest/admin/application-version"): lambda s, kw: _Resp(200),
            ("GET", "/rest/admin/application-configuration"): cfg,
            ("POST", "/rest/user/login"): login, ("POST", "/api/Users"): register,
            ("GET", "/rest/user/whoami"): whoami, ("GET", "/profile"): profile}


def test_juice_bootstrap_registers_then_is_idempotent():
    state = {"mode": "disabled", "users": {}}
    keyring = _Store()
    res = _boot("juice-shop", _juice_routes(state), keyring, _Store(), [], prompt=None)
    assert res.credential_source == "generated" and res.stored
    assert "account registered" in res.notes
    (host, ident, user, pw), = keyring.sets
    assert (host, ident, user) == ("127.0.0.1", "juice-user", "juice-user@fuzzlab.lab")
    assert state["users"] == {user: pw} and len(pw) >= 24
    res2 = _boot("juice-shop", _juice_routes(state), _Store(_Cred(user, pw)), _Store(), [])
    assert res2.credential_source == "keyring" and "account registered" not in res2.notes


def test_juice_bootstrap_refuses_a_safe_mode_lab():
    with pytest.raises(ext.ExternalLabError, match="safetyMode"):
        _boot("juice-shop", _juice_routes({"mode": "auto", "users": {}}), _Store(), _Store(), [])


def test_juice_bootstrap_with_a_stale_password_says_reset_and_stores_nothing():
    state = {"mode": "disabled", "users": {"juice-user@fuzzlab.lab": "changed"}}
    keyring = _Store()
    with pytest.raises(ext.ExternalLabError, match="reset juice-shop"):
        _boot("juice-shop", _juice_routes(state), keyring,
              _Store(_Cred("juice-user@fuzzlab.lab", "old")), [])
    assert keyring.sets == []


def test_bwapp_never_generates_a_password():
    with pytest.raises(ext.ExternalLabError, match="set-credential"):
        _boot("bwapp", _bwapp_routes(), _Store(), _Store(), [], prompt=None)


@pytest.mark.parametrize("origin", ["http://10.0.0.5:8092", "https://127.0.0.1:8092",
                                    "http://127.0.0.1:8092/bWAPP/", "http://example.com"])
def test_the_lab_client_refuses_anything_but_a_loopback_http_origin(origin):
    with pytest.raises(ext.ExternalLabError):
        ext._LabClient(origin, session_factory=lambda: _FakeLabSession({}, []))


def test_the_lab_client_refuses_a_path_that_would_leave_the_origin():
    c = ext._LabClient("http://127.0.0.1:1", session_factory=lambda: _FakeLabSession({}, []))
    for bad in ("//evil.example/x", "http://evil.example/", "x"):
        with pytest.raises(ext.ExternalLabError):
            c.url(bad)


def test_the_cli_bootstrap_without_authorized_sends_nothing(capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("bootstrap must not run")
    monkeypatch.setattr(ext, "bootstrap", boom)
    assert ext.main(["bootstrap", "bwapp"]) == 2
    assert "--authorized" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["80a", "0", "70000", "-1"])
def test_a_bad_port_variable_is_refused(value):
    with pytest.raises(ext.ExternalLabError):
        ext.lab_port(ext.LAB_META["bwapp"], {"BWAPP_PORT": value})


def test_check_config_cli_refuses_a_rendered_wildcard(tmp_path, capsys):
    f = tmp_path / "c.json"
    f.write_text(json.dumps({"services": {"app": {"ports": [
        {"mode": "ingress", "target": 3000, "published": "3000", "protocol": "tcp"}]}}}))
    assert ext.main(["check-config", "juice-shop", "--file", str(f)]) == 1
    assert "REFUSED" in capsys.readouterr().err
