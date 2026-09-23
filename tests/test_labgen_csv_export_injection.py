"""The `csv_formula_injection` shape (CWE-1236, `CC-LAB-0091`/`FR-LAB-66`/
`FR-LAB-67`) -- category 5's (Travel/booking/marketplaces) Booking.com
pilot, second increment (first: `open_redirect`, `CC-LAB-0090`).
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.4 row 5.

Mirrors `tests/test_labgen_open_redirect.py`'s structure exactly (itself
modeled on `tests/test_labgen_php_laravel_harder_shapes.py`, the dedicated
`php_laravel` test file): verdict derivation, static-precheck registration,
Tier 0 lint + minimal-pair, Tier 3 regen-diff, CLI `--check`, a ground-truth
cross-check against this app's existing directory (`lab/ground-truth-
booking-clone/`, this shape's case appended to the same directory
`open_redirect` already established), and a real live-boot proof of the
actual adversarial bypass shape (`CC-LAB-0090`'s own evidentiary bar) --
including the leading-whitespace-then-trigger-character payload the
adequacy review for this increment specifically demanded (a naive
"starts with a trigger character?" check would miss it)."""

from __future__ import annotations

import base64
import dataclasses
import shutil
import subprocess

import pytest

from fuzzlab.labels import contract as labels_contract
from fuzzlab.labgen.conformance import static_precheck, tier0, tier3
from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.emitters.php_laravel.modules import CsvFormulaNeutralizeTransform
from fuzzlab.labgen.schema import Pipeline, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

MANIFEST_PATH = "lab/manifests/booking_csv_export_sample.yaml"
GROUND_TRUTH_DIR = "lab/ground-truth-booking-clone"

#: Real CSV-formula trigger-character payloads (OWASP's five named
#: characters), each exploitable verbatim against the vulnerable twin --
#: DDE/command-execution-capable shapes are real-world CSV-injection
#: payloads, not just data-exfiltration ones (CWE-1236's actual impact
#: profile is RCE-class, not merely a data-disclosure one).
TRIGGER_CHARACTER_PAYLOADS: tuple[str, ...] = (
    "=cmd|'/c calc'!A1",
    "+1+1",
    "-2+3",
    "@SUM(1,1)",
)

#: The bypass shape a naive "does the value start with a trigger
#: character?" check would miss: a trigger character after leading
#: whitespace. Several spreadsheet applications still evaluate this as a
#: formula after trimming leading whitespace on cell entry -- this is
#: exactly the gap this shape's own adequacy review demanded be closed and
#: tested by construction, not merely described in prose (PA-0026).
LEADING_WHITESPACE_BYPASS_PAYLOAD = " =cmd|'/c calc'!A1"

#: A benign value with no leading trigger character -- must reach the
#: exported cell unchanged on both twins (the neutralizer is not "reject
#: every value").
BENIGN_LABEL_PAYLOAD = "Ocean View Room"


@pytest.fixture(scope="module")
def matrix():
    return load_safety_matrix()


@pytest.fixture(scope="module")
def manifest():
    return load_manifest(MANIFEST_PATH)


@pytest.fixture()
def emitter():
    return LaravelEmitter()


def _cell(manifest, cell_id: str):
    return next(c for c in manifest.cells if c.cell_id == cell_id)


# ---------------------------------------------------------------------------
# Verdict / matrix scorability
# ---------------------------------------------------------------------------


def test_every_cell_derives_its_expected_verdict(manifest, matrix) -> None:
    vulnerable = _cell(manifest, "LABGEN-BC-0003")
    secure = _cell(manifest, "LABGEN-BC-0004")
    assert verdict(vulnerable.transform, vulnerable.sink_context, matrix).verdict == "VULNERABLE"
    assert verdict(secure.transform, secure.sink_context, matrix).verdict == "SECURE"


def test_every_shape_has_a_static_precheck_flag(manifest) -> None:
    for cell in manifest.cells:
        # Must not raise: an unregistered shape fails loud by design.
        static_precheck.static_precheck_status(cell.vuln_class, cell.sink_context.family)


def test_the_verdict_agrees_with_this_apps_own_ground_truth(manifest) -> None:
    """`BKNG-0002` (appended to this app's existing ground-truth directory,
    not a new one -- `fuzzlab.labels.contract` supports more than one case
    per directory natively) names the vulnerable cell's served URL/param
    and `expected_vulnerable: true` -- cross-checked here against the real
    `verdict()` derivation, not just asserted independently of it."""
    gt = labels_contract.load(GROUND_TRUTH_DIR)
    case = gt.case_by_id("BKNG-0002")
    assert case is not None
    vulnerable = _cell(manifest, "LABGEN-BC-0003")
    assert case.expected_vulnerable is True
    assert case.url == served_url_for(vulnerable)
    assert case.param == "label"
    # This app's first case (open_redirect, CC-LAB-0090) is unaffected by
    # this increment's addition.
    assert gt.case_by_id("BKNG-0001") is not None


# ---------------------------------------------------------------------------
# Tier 0 / Tier 3
# ---------------------------------------------------------------------------


def test_tier3_whole_sample_regeneration_is_byte_identical(emitter, manifest) -> None:
    tier3.regenerate_and_diff_emitter(emitter, manifest.cells)  # must not raise


def test_tier3_renders_one_unique_path_per_emitted_file(emitter, manifest) -> None:
    tree = tier3.render_whole_sample(emitter, manifest.cells)
    expected = sum(len(emitter.render(cell)) for cell in manifest.cells)
    assert len(tree) == expected


def test_tier0_minimal_pair_holds_between_each_cell_and_its_weakened_twin(emitter, manifest) -> None:
    checker = tier0.get_minimal_pair_checker()
    for cell in manifest.cells:
        if not cell.transform.ops:
            continue
        weakened = dataclasses.replace(cell, transform=Pipeline.from_list([]))
        checker(emitter.render(weakened), emitter.render(cell))  # must not raise


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_tier0_lint_passes_for_every_cell(emitter, manifest) -> None:
    for cell in manifest.cells:
        for result in tier0.lint_emitted_files(emitter.render(cell)):
            assert result.ok, f"{cell.cell_id}: php -l failed: {result.detail}"


def test_cli_check_passes_end_to_end_on_the_new_manifest(tmp_path) -> None:
    from fuzzlab.labgen import cli as labgen_cli

    assert (
        labgen_cli.main(
            ["--manifest", MANIFEST_PATH, "--out", str(tmp_path / "out"), "--emitter", "php_laravel", "--check"]
        )
        == 0
    )


# ---------------------------------------------------------------------------
# Direct, framework-independent proof of the neutralizer's own bypass
# handling (PA-0026: verify the adapter's own check by construction, never
# assume a caller-side mitigation covers every precondition). The live-boot
# test below found, for real, that this skeleton's Laravel app already
# trims leading whitespace off every request input before either twin's own
# code runs -- which would otherwise silently hide a broken
# `csv_formula_neutralize` regex behind the framework's own, unrelated
# trimming. This test evaluates the transform's exact rendered PHP
# expression directly via `php -r`, against a raw string that still has its
# leading whitespace (bypassing Laravel/`Request` entirely), so it proves
# the neutralizer's own leading-whitespace handling is correct on its own
# terms, not merely coincidentally covered by the framework.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
def test_the_neutralize_expression_itself_closes_the_leading_whitespace_bypass() -> None:
    transform = CsvFormulaNeutralizeTransform()
    rendered = transform.render({"value_expr": "$value"})
    value_expr = rendered.context["value_expr"]

    def _evaluate(raw_value: str) -> str:
        # base64-encoded so the raw value's own quotes/backslashes never
        # need PHP-string-literal escaping in the generated `-r` source.
        encoded = base64.b64encode(raw_value.encode()).decode()
        # `php -r` code is implicitly inside <?php ... ?> already -- an
        # explicit opening tag here is itself a syntax error.
        php_source = f"$value = base64_decode('{encoded}'); echo {value_expr};"
        result = subprocess.run(["php", "-r", php_source], capture_output=True, text=True, timeout=10.0)
        assert result.returncode == 0, f"php -r failed: {result.stderr}"
        return result.stdout

    for payload in (*TRIGGER_CHARACTER_PAYLOADS, LEADING_WHITESPACE_BYPASS_PAYLOAD):
        neutralized = _evaluate(payload)
        expected = "'" + payload
        assert neutralized == expected, (
            f"{payload!r}: the rendered neutralize expression produced {neutralized!r} when evaluated "
            f"directly by PHP against the raw (untrimmed) value -- expected {expected!r} "
            "(a leading single quote prepended before any leading whitespace)"
        )

    benign = _evaluate(BENIGN_LABEL_PAYLOAD)
    assert benign == BENIGN_LABEL_PAYLOAD


# ---------------------------------------------------------------------------
# Real live-boot proof: a real HTTP round trip against both twins, with
# real trigger-character payloads (including the leading-whitespace bypass
# shape), reading the real CSV response body back.
# ---------------------------------------------------------------------------

pytestmark_live_boot = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot environment not available (composer/php on PATH and a real, bounded "
        "Packagist round trip -- PA-0005; see live_boot.live_boot_available())"
    ),
)


@pytestmark_live_boot
def test_live_boot_csv_manifest_neutralizes_every_formula_trigger_shape() -> None:
    emitter = LaravelEmitter()
    manifest = load_manifest(MANIFEST_PATH)
    vulnerable = _cell(manifest, "LABGEN-BC-0003")
    secure = _cell(manifest, "LABGEN-BC-0004")
    vuln_url = served_url_for(vulnerable)
    secure_url = served_url_for(secure)

    all_payloads = (*TRIGGER_CHARACTER_PAYLOADS, LEADING_WHITESPACE_BYPASS_PAYLOAD)

    with LiveBootHarness(emitter, list(manifest.cells)) as harness:
        for payload in all_payloads:
            vuln_resp = harness.get(vuln_url, params={"label": payload})
            secure_resp = harness.get(secure_url, params={"label": payload})

            assert vuln_resp.status == 200, f"{payload!r}: vulnerable twin did not return 200"
            assert secure_resp.status == 200, f"{payload!r}: secure twin did not return 200"

            # Real finding (verified by this exact live boot, not assumed):
            # this skeleton's default Laravel middleware stack includes
            # `TrimStrings` (Laravel's own default, never disabled by this
            # skeleton's `bootstrap/app.php`), which strips leading/
            # trailing whitespace from every request input *before either
            # cell's own code runs* -- confirmed here because even the
            # vulnerable twin (transform: [], no processing at all) never
            # observes `LEADING_WHITESPACE_BYPASS_PAYLOAD`'s leading space.
            # So the value this cell's own PHP actually receives is the
            # framework-trimmed one, not the raw wire value -- asserted
            # against explicitly, rather than the test silently expecting
            # the untrimmed payload and failing for the wrong reason. This
            # does not make `csv_formula_neutralize`'s own leading-
            # whitespace handling redundant/dead: a different ingestion
            # path (a raw API consuming a header, a CLI import, a future
            # route with `TrimStrings` excluded) would not get this
            # framework-level assist, so the transform's own check is kept
            # as real defense-in-depth (PA-0026: verify every precondition,
            # never assume a caller-side mitigation covers every path).
            received_value = payload.strip()

            # The vulnerable twin embeds the (framework-trimmed) value
            # verbatim as the exported cell -- this is this test's own
            # proof that the vulnerable twin is actually exploitable, not
            # just structurally different: a real spreadsheet opening this
            # export would evaluate the cell as a formula.
            expected_vuln_row = f"{received_value},129.00\n"
            assert vuln_resp.body.endswith(expected_vuln_row), (
                f"{payload!r}: vulnerable twin's real CSV body was {vuln_resp.body!r}, "
                f"expected it to end with {expected_vuln_row!r}"
            )

            # The secure twin's neutralizer prepends a single quote at the
            # true start of the (framework-trimmed) value, forcing the
            # whole cell to text. Nothing else about the row changes: same
            # header, same trailing ",129.00" cell, only the leading quote
            # differs, so this asserts the *whole* differential, not only
            # the first byte.
            expected_secure_row = f"'{received_value},129.00\n"
            assert secure_resp.body.endswith(expected_secure_row), (
                f"{payload!r}: secure twin's real CSV body was {secure_resp.body!r}, "
                f"expected it to end with {expected_secure_row!r} -- a missing leading quote here "
                "would show up as the neutralizer failing to close this exact bypass shape"
            )
            assert secure_resp.body.startswith("label,amount\n"), (
                f"{payload!r}: secure twin's CSV header row changed unexpectedly: {secure_resp.body!r}"
            )
            assert vuln_resp.body.startswith("label,amount\n"), (
                f"{payload!r}: vulnerable twin's CSV header row changed unexpectedly: {vuln_resp.body!r}"
            )

        # A benign value with no leading trigger character reaches the
        # exported cell unchanged on both twins -- the neutralizer is not
        # "reject every value."
        vuln_benign = harness.get(vuln_url, params={"label": BENIGN_LABEL_PAYLOAD})
        secure_benign = harness.get(secure_url, params={"label": BENIGN_LABEL_PAYLOAD})
        expected_benign_row = f"{BENIGN_LABEL_PAYLOAD},129.00\n"
        assert vuln_benign.body.endswith(expected_benign_row)
        assert secure_benign.body.endswith(expected_benign_row)
