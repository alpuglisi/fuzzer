"""CC-LAB-0247 (Lane 7, Gate E, S17): offline checks on `lab/compose.yaml`
that don't need a real compose provider -- parse the file as YAML and
assert the two safety properties the plan's own risk register calls out:

- every service's `ports:` entries are loopback-only (`127.0.0.1:...`),
  never `0.0.0.0` or unbound (CLAUDE.md's Safety section, non-negotiable).
- every one of the 10 browsable-app services has its own, distinct
  `networks:` key (S17: a real SSRF exists in this lab -- ReelQueue's
  `/api/content/thumbnail-import` -- so no app may reach another by
  service-name DNS even though every host port is loopback-only), while
  the 3 original services (`db`/`web`/`frontend`) keep their pre-existing
  no-`networks:`-key shape unchanged (a compose service with an explicit
  `networks:` key stops auto-joining the implicit default network rather
  than joining both, so this is sufficient by itself).

A live `docker compose config` / `podman compose --profile apps config`
run (Gate E's own manual verification) additionally proves the *rendered*
config resolves the same way; this module is the fast, host-independent
regression guard for the same two properties.
"""

from __future__ import annotations

from pathlib import Path

import yaml

COMPOSE_PATH = Path("lab/compose.yaml")

#: The 3 services that predate Lane 7 -- deliberately left with no
#: `networks:` key (still on the implicit default network, unchanged).
PRE_EXISTING_SERVICES = frozenset({"db", "web", "frontend"})

#: The 10 browsable-app services Lane 7 adds -- each must have its own,
#: distinct dedicated network.
BROWSABLE_APP_SERVICES = frozenset(
    {
        "circlefeed",
        "huddlehub",
        "booking",
        "pictrail",
        "loopcast",
        "trackernest",
        "reelqueue",
        "wanderfare",
        "forgecart",
        "meadowmart",
    }
)


def _load_compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_every_service_and_the_expected_set_are_both_present() -> None:
    doc = _load_compose()
    services = set(doc["services"])
    assert PRE_EXISTING_SERVICES <= services
    assert BROWSABLE_APP_SERVICES <= services


def test_every_port_binding_is_loopback_only() -> None:
    doc = _load_compose()
    for name, service in doc["services"].items():
        for binding in service.get("ports", []):
            assert isinstance(binding, str), f"{name}: expected a 'host:port:port' string, got {binding!r}"
            assert binding.startswith("127.0.0.1:"), (
                f"{name}: port binding {binding!r} is not loopback-only "
                f"(CLAUDE.md Safety: never bind a container port to 0.0.0.0)"
            )


def test_pre_existing_services_keep_no_networks_key() -> None:
    doc = _load_compose()
    for name in PRE_EXISTING_SERVICES:
        service = doc["services"].get(name)
        if service is None:
            continue  # frontend is profile-gated (desync) but always defined here
        assert "networks" not in service, (
            f"{name}: gained a 'networks:' key -- this would also drop it off the "
            f"implicit default network the other pre-existing services still share"
        )


def test_every_browsable_app_has_its_own_distinct_network() -> None:
    doc = _load_compose()
    seen_networks: dict[str, str] = {}
    for name in BROWSABLE_APP_SERVICES:
        service = doc["services"][name]
        nets = service.get("networks")
        assert nets, f"{name}: missing a 'networks:' key (S17: must not join the implicit default network)"
        assert isinstance(nets, list) and len(nets) == 1, (
            f"{name}: expected exactly one dedicated network, got {nets!r}"
        )
        net = nets[0]
        assert net not in seen_networks, (
            f"{name}: network {net!r} is already used by {seen_networks[net]!r} "
            f"-- S17 requires one distinct network per app"
        )
        seen_networks[net] = name


def test_every_declared_network_is_referenced_by_exactly_one_service() -> None:
    doc = _load_compose()
    declared = set(doc.get("networks", {}))
    referenced: dict[str, str] = {}
    for name, service in doc["services"].items():
        for net in service.get("networks", []):
            assert net not in referenced, f"network {net!r} referenced by both {referenced[net]!r} and {name!r}"
            referenced[net] = name
    assert declared == set(referenced), (
        f"declared networks {declared} and referenced networks {set(referenced)} must match exactly "
        f"(a stray unused or unreferenced network is a config drift, not a real isolation boundary)"
    )
