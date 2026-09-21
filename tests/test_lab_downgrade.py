"""Phase 9 T9.5: the opt-in h2->h1 downgrade front-end (desync research target, D17).

Config-only, default-off. Validated structurally (YAML + config text) offline, plus a
`docker compose config` profile-gating check when the Docker CLI is present.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

LAB = Path(__file__).resolve().parents[1] / "lab"
COMPOSE = LAB / "compose.yaml"
NGINX = LAB / "downgrade" / "nginx.conf"
DOCKER = shutil.which("docker")


def _compose():
    return yaml.safe_load(COMPOSE.read_text())


def test_frontend_is_gated_off_by_a_profile():
    fe = _compose()["services"]["frontend"]
    assert fe["profiles"] == ["desync"]              # not started by a plain `up`


def test_frontend_is_loopback_only():
    fe = _compose()["services"]["frontend"]
    assert all(p.startswith("127.0.0.1:") for p in fe["ports"])   # never 0.0.0.0


def test_frontend_mounts_config_and_depends_on_web():
    fe = _compose()["services"]["frontend"]
    assert any("downgrade/nginx.conf:/etc/nginx/nginx.conf" in v for v in fe["volumes"])
    assert "web" in fe["depends_on"]


def test_default_lab_services_are_unchanged():
    # db + web still there; frontend is the only addition and it is profile-gated
    svcs = _compose()["services"]
    assert {"db", "web"} <= set(svcs)
    assert svcs["web"]["ports"] == ["127.0.0.1:${PFF_WEB_PORT:-8080}:80"]


def test_nginx_config_does_h2_to_h1_downgrade():
    conf = NGINX.read_text()
    assert "http2  on;" in conf or "http2 on;" in conf   # accept HTTP/2 (h2c) at the front
    assert "proxy_http_version 1.1;" in conf             # downgrade to HTTP/1.1 upstream
    assert "server web:80;" in conf                      # forwards to the app tier
    assert "proxy_pass http://pff_app;" in conf


def test_env_example_documents_downgrade_port():
    assert "PFF_DOWNGRADE_PORT" in (LAB / ".env.example").read_text()


@pytest.mark.skipif(DOCKER is None, reason="docker CLI not available")
def test_compose_profile_gating_via_docker():
    def services(*args):
        out = subprocess.run([DOCKER, "compose", "-f", str(COMPOSE), *args,
                              "config", "--services"], capture_output=True, text=True,
                             cwd=str(LAB), timeout=60)
        assert out.returncode == 0, out.stderr
        return set(out.stdout.split())

    assert "frontend" not in services()                          # default off
    assert "frontend" in services("--profile", "desync")         # enabled by the profile
