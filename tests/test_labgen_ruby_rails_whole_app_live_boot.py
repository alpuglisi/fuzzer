"""Phase D whole-app conformance for ``ruby_rails`` -- "ForgeCart"
(`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §5/§9.5, `CC-LAB-0079`/
`FR-LAB-83`).

Every prior Rails live-boot test (`test_labgen_ruby_rails_live_boot.py`,
`..._webhook_signature_live_boot.py`, `..._mass_assignment_live_boot.py`,
`..._insecure_deserialization_live_boot.py`) boots one or two cells at a
time, in isolation. This is the whole-app gap the dispatch instructions
named explicitly: assemble **every** cell this stack has ever built --
Phase A's illustrative shape, all three Phase B sample pairs, and Phase C's
five real ForgeCart pages, 12 cells in total -- onto one real, single
``bin/rails server`` boot, and prove every real page (the five real-URL
cells, plus the fixed inert surrounding pages) actually serves over a real
HTTP round trip, with no route collision and no cell shadowing another.

Skip-guarded (PA-0005/PA-0035) on ``rails_boot_available()``, exactly like
every other Rails live-boot test in this stack. Marked ``@pytest.mark.slow``
(one real ``bundle install`` + boot round trip for the whole assembled app).
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.labgen.conformance.rails_live_boot import RailsLiveBootHarness, rails_boot_available
from fuzzlab.labgen.emitters.ruby_rails import RailsEmitter, url_path_for
from fuzzlab.labgen.schema import Cell, Pipeline, Route, SinkContext, load_manifest

pytestmark = pytest.mark.skipif(
    not rails_boot_available(),
    reason=(
        "rails live-boot harness requires ruby + bundle on PATH and real RubyGems "
        "network reachability (PA-0005/PA-0035) -- see rails_live_boot.rails_boot_available()"
    ),
)

SAMPLE_MANIFESTS = (
    "lab/manifests/webhook_signature_rails_sample.yaml",
    "lab/manifests/mass_assignment_rails_sample.yaml",
    "lab/manifests/insecure_deserialization_rails_sample.yaml",
    "lab/manifests/shopify_forgecart_real_pages.yaml",
)


def _illustrative_cell(cell_id: str) -> Cell:
    # Phase A's one illustrative shape, LABGEN-RR-0001 -- see
    # test_labgen_ruby_rails_live_boot.py's own copy of this helper (not
    # imported cross-test-module, per this stack's own convention of every
    # live-boot test file being independently readable).
    return Cell(
        cell_id=cell_id,
        vuln_class="xss",
        stack_profile="ruby_rails",
        route=Route(method="GET", path=url_path_for(cell_id)),
        sink_context=SinkContext(family="html_body"),
        transform=Pipeline(),
    )


def _all_cells() -> list[Cell]:
    cells = [_illustrative_cell("LABGEN-RR-0001")]
    for path in SAMPLE_MANIFESTS:
        cells += load_manifest(path).cells
    return cells


@pytest.mark.slow
def test_whole_app_boots_with_every_cell_registered_together() -> None:
    """Every cell this stack has ever built (12 total: 1 Phase A + 6 Phase B
    + 5 Phase C) renders and boots onto one real, single Rails process --
    proving the full assembled app (not one cell tested in isolation) is
    what actually gets served, and that no two cells' routes collide."""
    cells = _all_cells()
    assert len(cells) == 12
    emitter = RailsEmitter()
    for cell in cells:
        assert emitter.supports(cell.vuln_class, cell.sink_context), cell.cell_id

    with RailsLiveBootHarness(emitter, cells) as harness:
        # The health check every prior single-cell test also asserts --
        # confirms the process is actually up before probing app routes.
        assert harness.get("/up").status == 200

        # -- ForgeCart's fixed, inert surrounding pages (Phase C) --------
        home = harness.get("/")
        assert home.status == 200
        assert "ForgeCart" in home.body

        products = harness.get("/products")
        assert products.status == 200
        assert json.loads(products.body) == {"products": []}

        cart = harness.get("/cart")
        assert cart.status == 200
        assert json.loads(cart.body) == {"items": []}

        dashboard = harness.get("/admin")
        assert dashboard.status == 200
        assert "ForgeCart admin" in dashboard.body

        orders = harness.get("/admin/orders")
        assert orders.status == 200
        assert json.loads(orders.body) == {"orders": []}

        # -- ForgeCart's five real vulnerability pages (Phase C) ---------
        # /search -- reflected XSS, the storefront search box.
        search = harness.get("/search", params={"q": "<b>forgecart-search</b>"})
        assert search.status == 200
        assert "<b>forgecart-search</b>" in search.body

        # /webhooks/orders/create -- vulnerable twin: a correctly-forged
        # signature is still accepted (D20 `partial` -- the vulnerability is
        # a timing side channel, not a functional bypass; see
        # test_labgen_ruby_rails_webhook_signature_live_boot.py for the real
        # timing-differential proof this whole-app test does not repeat).
        import base64
        import hashlib
        import hmac

        secret = "whsec_lab_lab_only_not_a_real_secret"
        body = b'{"order_id": 1}'
        # Base64-encoded digest -- matches the real Shopify
        # `X-Shopify-Hmac-SHA256` mechanism this cell reproduces
        # (`Base64.strict_encode64(OpenSSL::HMAC.digest(...))` server-side).
        sig = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
        good = harness.post(
            "/webhooks/orders/create", raw_body=body,
            headers={"X-Shopify-Hmac-SHA256": sig, "Content-Type": "application/json"},
        )
        assert good.status == 200, good.body

        # /webhooks/customers/update -- secure twin: same real signature
        # mechanism, still correctly accepts a valid signature.
        good2 = harness.post(
            "/webhooks/customers/update", raw_body=body,
            headers={"X-Shopify-Hmac-SHA256": sig, "Content-Type": "application/json"},
        )
        assert good2.status == 200, good2.body

        # /admin/customers/update -- CWE-915 mass assignment, vulnerable:
        # the attacker-controlled `role` field reaches the write.
        mass = harness.post(
            "/admin/customers/update",
            data={"user[bio]": "whole-app boot check", "user[role]": "admin"},
        )
        assert mass.status == 200, mass.body
        assert json.loads(mass.body)["role"] == "admin"

        # /admin/products/import -- CWE-502 insecure deserialization,
        # vulnerable: a `!ruby/object:OpenStruct` YAML tag is honored.
        yaml_payload = "--- !ruby/object:OpenStruct\ntable:\n  imported: true\n"
        deser = harness.post("/admin/products/import", data={"yaml_payload": yaml_payload})
        assert deser.status == 200, deser.body
        assert "OpenStruct" in deser.body

        # -- Phase A/B's own pre-existing cells, still reachable ---------
        illustrative = harness.get(url_path_for("LABGEN-RR-0001"), params={"q": "<i>still-here</i>"})
        assert illustrative.status == 200
        assert "<i>still-here</i>" in illustrative.body
