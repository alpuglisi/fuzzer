"""Unit coverage for the `spring_boot` emitter's first `price_integrity_
bypass` cell (`CC-LAB-0188`, `FR-LAB-143`): Netflix's fifth real page, a
subscription plan-upgrade/downgrade endpoint at `POST /api/subscription/
change-plan`.

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot_account_billing.py`'s own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/price_integrity_netflix_subscription_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-JV-0009": "VULNERABLE",  # client_trusted_amount: reflects the client's own monthly_charge
    "LABGEN-JV-0010": "SECURE",  # server_recomputed_amount: looks the real price up by plan_tier
}


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def test_manifest_loads_and_validates() -> None:
    assert set(_cells()) == set(_EXPECTED_VERDICTS)


def test_verdict_matches_expected() -> None:
    matrix = load_safety_matrix()
    for cell_id, cell in _cells().items():
        result = verdict(cell.transform, cell.sink_context, matrix)
        assert result.verdict == _EXPECTED_VERDICTS[cell_id], cell_id


def test_spring_boot_supports_every_sample_cell() -> None:
    emitter = SpringBootEmitter()
    for cell in _cells().values():
        assert emitter.supports(cell.vuln_class, cell.sink_context) is True


def test_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = SpringBootEmitter()
    for cell in _cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_vulnerable_twin_reflects_client_price_secure_twin_recomputes() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0009"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0010"])[0].content.decode("utf-8")

    # Both parse the same two JSON fields (the shared minimal-pair source)...
    assert 'root.path("plan_tier").asText()' in vulnerable_src
    assert 'root.path("monthly_charge").asText()' in vulnerable_src
    assert 'root.path("plan_tier").asText()' in secure_src
    assert 'root.path("monthly_charge").asText()' in secure_src
    # ...but only the vulnerable twin echoes the client-submitted value back.
    assert '"monthly_charge\\":" + clientMonthlyCharge' in vulnerable_src
    assert '"monthly_charge\\":" + clientMonthlyCharge' not in secure_src
    # ...and only the secure twin looks the price up in its own fixed map.
    assert "planPrices.get(planTier)" in secure_src
    assert "planPrices.get(planTier)" not in vulnerable_src
    assert "PostMapping" in vulnerable_src and "PostMapping" in secure_src


def test_secure_twin_price_map_is_data_driven_not_a_disguised_constant() -> None:
    """`CC-LAB-0212`'s adequacy-review lesson applied proactively: the secure
    twin's map must have more than one distinct price, and the price served
    must depend on which plan_tier key is looked up, not a single constant
    dressed up as a map."""
    emitter = SpringBootEmitter()
    src = emitter.render(_cells()["LABGEN-JV-0010"])[0].content.decode("utf-8")
    assert 'planPrices.put("basic", new java.math.BigDecimal("6.99"))' in src
    assert 'planPrices.put("standard", new java.math.BigDecimal("15.49"))' in src
    assert 'planPrices.put("premium", new java.math.BigDecimal("22.99"))' in src
    assert "Unknown plan_tier" in src  # fails closed on an unrecognized tier, no silent default


def test_all_controllers_have_disjoint_class_names() -> None:
    """Netflix's fifth cell must not collide with any of its other four real
    pages' generated class names/paths."""
    emitter = SpringBootEmitter()
    all_paths = set()
    for manifest_path in (
        "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
        "lab/manifests/xxe_netflix_sample.yaml",
        "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml",
        "lab/manifests/access_control_netflix_billing_sample.yaml",
        _MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 12
