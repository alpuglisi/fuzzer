"""Real, on-host verification of CC-LAB-0073's CWE-915 mass-assignment pair
(``ruby_rails``): assembles the real generated Rails app, runs a real
``bundle install``, migrates a real per-run SQLite database (including the
Phase-B ``AddRoleToUsers`` migration this lane adds -- see
``fuzzlab/labgen/emitters/ruby_rails/stack/skeleton/db/migrate/
20260922000001_add_role_to_users.rb``), boots a real ``bin/rails server``,
and sends real HTTP PATCH requests whose body carries an attacker-controlled
`role` field alongside the legitimate `bio` field the endpoint actually
intends to accept.

The observable divergence this test asserts against is exactly the one
Shopify's own research (`docs/research/site-architecture-survey-
functionality-shopify.md` §2) and the plan's own "Decided" block name: a
merchant/customer profile-update endpoint whose `permit!` twin lets the
attacker also set a privileged field (`role`) the form was never meant to
expose, while the `permit(:username, :bio)` twin silently drops it.

Skip-guarded (PA-0005/PA-0035) on `rails_boot_available()`. Marked
`@pytest.mark.slow`. Each cell gets its own fresh `RailsLiveBootHarness`
(and therefore its own fresh per-run SQLite database) -- the two twins share
one seeded `shopper1` row by convention, so testing them against the same
booted app in sequence would let the first request's write leak into the
second twin's assertion.
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not rails_boot_available(),
    reason=(
        "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
        "network reachability (PA-0005/PA-0035) -- see rails_live_boot.rails_boot_available()"
    ),
)

MANIFEST_PATH = "lab/manifests/mass_assignment_rails_sample.yaml"


@pytest.mark.slow
def test_vulnerable_permit_bang_lets_an_attacker_set_the_role_column() -> None:
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    vulnerable = cells["LABGEN-RR-0004"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with RailsLiveBootHarness(emitter, [vulnerable]) as harness:
        resp = harness.patch(
            "/cell/labgen_rr_0004",
            data={"user[bio]": "updated via a real HTTP PATCH", "user[role]": "admin"},
        )
        assert resp.status == 200, resp.body
        body = json.loads(resp.body)
        assert body["bio"] == "updated via a real HTTP PATCH"
        # The real finding: an attacker-controlled field the form was never
        # meant to expose reached a real ActiveRecord write, via a real
        # HTTP round trip -- not a template-text inspection.
        assert body["role"] == "admin"


@pytest.mark.slow
def test_secure_explicit_allowlist_drops_the_role_field() -> None:
    manifest = load_manifest(MANIFEST_PATH)
    cells = {c.cell_id: c for c in manifest.cells}
    emitter = RailsEmitter()
    secure = cells["LABGEN-RR-0005"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with RailsLiveBootHarness(emitter, [secure]) as harness:
        resp = harness.patch(
            "/cell/labgen_rr_0005",
            data={"user[bio]": "updated via a real HTTP PATCH", "user[role]": "admin"},
        )
        assert resp.status == 200, resp.body
        body = json.loads(resp.body)
        # The legitimate field still applies...
        assert body["bio"] == "updated via a real HTTP PATCH"
        # ...but the attacker-controlled field is silently dropped by
        # Rails' own strong-parameters allowlist, never reaching the write
        # -- the seeded row's default, never the attacker's requested value.
        assert body["role"] == "customer"
