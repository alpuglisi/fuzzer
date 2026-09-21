"""End-to-end test for `php_current` against a small REAL sample of
Ryder's Puppy Fort Factory's actual pages (`lab/manifests/phase0_real_pages_sample.yaml`).

Proves the module inventory built for one illustrative SQLi pair (see
`tests/test_labgen_php_current.py`) generalizes to real page shapes drawn
from `puppy-fort-factory/VULNERABILITIES.md` and
`lab/ground-truth/labels.json` (`PFF-0001`, `PFF-0004`, `PFF-0005`,
`PFF-0006`), spanning two vulnerability classes and three sink-context
families, without a wholly new per-page template each time -- only a
handful of new source/transform/sink/complexity modules
(`fuzzlab/labgen/modules/`) plus a per-page static-parameter profile
(`fuzzlab.labgen.emitters.php_current._PAGE_PARAMS`).

Does not require the live containerized lab: this test only compares the
rendered PHP's structure/logic against the pages' *documented* behavior
(`puppy-fort-factory/VULNERABILITIES.md`), never runs it against a real
database. Live regeneration-and-diff against the running container is
separate, on-host work.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from fuzzlab.labgen.emitters.php_current import PhpCurrentEmitter
from fuzzlab.labgen.schema import Cell, load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/phase0_real_pages_sample.yaml"


def _load_cells() -> dict[str, Cell]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {cell.cell_id: cell for cell in manifest.cells}


_CELLS = _load_cells()

# (cell_id, expected_verdict) per lab/ground-truth/labels.json's real-world
# labels for these pages (PFF-0001 product.php, PFF-0006 blog_post.php,
# PFF-0004 login.php, PFF-0005 profile.php -- all expected_vulnerable=true
# for the raw/unmediated cell; this sample's secure twins are this task's
# own addition, not in labels.json, since the real app has no param_bind
# variant of these pages).
_EXPECTED_VERDICTS = {
    "LABGEN-RP-0001": "VULNERABLE",  # product.php, raw concat
    "LABGEN-RP-0002": "SECURE",  # product.php, param_bind twin
    "LABGEN-RP-0003": "VULNERABLE",  # blog_post.php, raw concat
    "LABGEN-RP-0004": "SECURE",  # blog_post.php, param_bind twin
    "LABGEN-RP-0005": "VULNERABLE",  # login.php, raw concat
    "LABGEN-RP-0006": "SECURE",  # login.php, param_bind twin
    "LABGEN-RP-0007": "VULNERABLE",  # profile.php, no escaping
    "LABGEN-RP-0008": "SECURE",  # profile.php, html_entity_escape twin
}


def test_manifest_loads_and_validates() -> None:
    assert set(_CELLS) == set(_EXPECTED_VERDICTS)


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_verdict_matches_the_real_pages_documented_vulnerability_status(cell_id: str) -> None:
    # Cross-checks this sample's cells against the same derived-verdict
    # engine every other lane's cells go through -- not asserted by fiat,
    # derived from (pipeline, sink_context, safety_matrix) like any other
    # cell (D20).
    cell = _CELLS[cell_id]
    matrix = load_safety_matrix()
    result = verdict(cell.transform, cell.sink_context, matrix)
    assert result.verdict == _EXPECTED_VERDICTS[cell_id]


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_php_current_supports_every_real_page_cell(cell_id: str) -> None:
    emitter = PhpCurrentEmitter()
    cell = _CELLS[cell_id]
    assert emitter.supports(cell.vuln_class, cell.sink_context) is True


@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_render_is_byte_deterministic_across_two_calls(cell_id: str) -> None:
    emitter = PhpCurrentEmitter()
    cell = _CELLS[cell_id]
    first = emitter.render(cell)
    second = emitter.render(cell)
    assert first == second


def test_product_php_and_blog_post_php_reuse_the_same_module_set() -> None:
    # product.php and blog_post.php are two different real pages with the
    # same sink-context shape (sql_numeric_literal, GET id) -- the whole
    # point of this task's sample. Their rendered output must differ only
    # in the table name / cell metadata, never in which modules composed
    # them.
    emitter = PhpCurrentEmitter()
    product = emitter.render(_CELLS["LABGEN-RP-0001"])[0].content.decode("utf-8")
    blog_post = emitter.render(_CELLS["LABGEN-RP-0003"])[0].content.decode("utf-8")
    assert "get_param -> identity -> sql_numeric_lookup -> single_statement" in product
    assert "get_param -> identity -> sql_numeric_lookup -> single_statement" in blog_post
    assert "FROM products" in product
    assert "FROM posts" in blog_post


def test_login_php_uses_post_source_and_string_literal_sink() -> None:
    emitter = PhpCurrentEmitter()
    content = emitter.render(_CELLS["LABGEN-RP-0005"])[0].content.decode("utf-8")
    assert "$_POST['username']" in content
    assert "WHERE username = '\" . $username . \"'" in content
    # The password check is present as sink boilerplate but is not the
    # cell's own injection point (matches lab/ground-truth/labels.json's
    # PFF-1008: password is non-vulnerable, hashed before use).
    assert "md5(" in content


def test_login_php_secure_twin_binds_the_username_parameter() -> None:
    emitter = PhpCurrentEmitter()
    content = emitter.render(_CELLS["LABGEN-RP-0006"])[0].content.decode("utf-8")
    assert "$stmt->execute([$username, $password_hash])" in content
    assert "\" . $username" not in content


def test_profile_php_reads_a_stored_field_not_a_request_parameter() -> None:
    emitter = PhpCurrentEmitter()
    content = emitter.render(_CELLS["LABGEN-RP-0007"])[0].content.decode("utf-8")
    assert "$_GET" not in content
    assert "$_POST" not in content
    assert "$currentUser['bio']" in content
    assert "echo '<div class=\"bio\">' . $bio . '</div>';" in content


def test_profile_php_secure_twin_escapes_before_echo() -> None:
    emitter = PhpCurrentEmitter()
    content = emitter.render(_CELLS["LABGEN-RP-0008"])[0].content.decode("utf-8")
    assert "echo '<div class=\"bio\">' . htmlspecialchars($bio) . '</div>';" in content


@pytest.mark.skipif(shutil.which("php") is None, reason="php CLI not available on this build host (PA-0005 pattern)")
@pytest.mark.parametrize("cell_id", sorted(_EXPECTED_VERDICTS))
def test_generated_php_is_syntactically_valid(cell_id: str) -> None:
    emitter = PhpCurrentEmitter()
    content = emitter.render(_CELLS[cell_id])[0].content
    with tempfile.TemporaryDirectory() as tmpdir:
        php_path = Path(tmpdir) / "cell.php"
        php_path.write_bytes(content)
        result = subprocess.run(
            ["php", "-l", str(php_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"php -l failed:\nstdout={result.stdout}\nstderr={result.stderr}"
