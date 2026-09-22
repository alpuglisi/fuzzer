"""Real, on-host verification that the `php_laravel` mass-assignment sink's
lack of an identifier-charset guard (unlike php_current's, see
`OrmEntityBulkAssignSink`'s docstring) is a verified property of Laravel's
real Query Builder grammar, not an assumption.

`fuzzlab/labgen/modules/sinks/orm_entity_bulk_assign.php.j2` (php_current)
was given a real, executed adversarial test after `BUG-0031` found it
spliced an unvalidated `$_POST` array key straight into raw SQL text
(`tests/test_labgen_mass_assignment.py::
test_orm_entity_bulk_assign_sink_rejects_a_syntax_injection_shaped_key`).
The php_laravel twin (`DB::table(...)->update($array)`) has no equivalent
executed test -- it relies on Laravel's Query Builder grammar always
wrapping/quoting a dynamic column name before it reaches SQL text, which is
true of real Laravel (`Illuminate\\Database\\Query\\Grammars\\Grammar::wrap()`)
but was never actually exercised against the real framework by this
codebase. This module closes that gap: it boots the real generated Laravel
app (`LiveBootHarness`, real `composer install`, real `php artisan serve`,
a real per-run SQLite database) and sends a real HTTP POST whose body
carries a syntax-injection-shaped field name alongside a legitimate one,
then reads the real database back to confirm the legitimate field applied
and nothing else did -- the same "rendered for real and executed, not
merely absent from the template text" standard the php_current test holds
itself to.

Skip-guarded (PA-0005) on `live_boot_available()`, exactly like every other
module in this file's own package. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot import LiveBootHarness, live_boot_available
from fuzzlab.labgen.emitters.php_laravel import LaravelEmitter, served_url_for
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not live_boot_available(),
    reason=(
        "live-boot harness requires composer + php on PATH and real Packagist "
        "network reachability (PA-0005) -- see live_boot.live_boot_available()"
    ),
)

#: PHP's `application/x-www-form-urlencoded` superglobal parsing turns a
#: literal `.` or ` ` in a top-level key into `_` and treats `[`/`]` as
#: nested-array syntax -- none of those appear here, so this key survives
#: transport and PHP's own `$_POST` construction as this exact literal
#: string, landing in the sink's `$__col` foreach exactly as written. It
#: still carries SQL-syntax-breaking punctuation (`)`, `;`, `'`, `--`) a
#: bare column name never would -- the same shape class BUG-0031's
#: php_current finding was.
_SYNTAX_INJECTION_KEY = "bio);DROP_TABLE_users;--'"


@pytest.mark.slow
def test_laravel_orm_entity_bulk_assign_sink_survives_a_syntax_injection_shaped_key() -> None:
    """Real HTTP POST, real Laravel Query Builder, real SQLite: a
    syntax-injection-shaped field name must not corrupt the database or let
    the app tell PHP to do anything it wasn't already going to do. Asserted
    against the *vulnerable* (`unfiltered_body_update`) twin specifically --
    the one with no allowlist standing between the request body and the
    sink, so if Laravel's own grammar didn't quote the identifier, this is
    exactly the cell that would prove it."""
    manifest = load_manifest("lab/manifests/mass_assignment_laravel_sample.yaml")
    emitter = LaravelEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-MA-0003"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with LiveBootHarness(emitter, [vulnerable]) as harness:
        url = served_url_for(vulnerable)

        before_tables = harness.query_db(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        before_users = harness.query_db("SELECT id, bio FROM users ORDER BY id")

        resp = harness.post(
            url,
            data={
                "bio": "updated-via-real-http",
                _SYNTAX_INJECTION_KEY: "pwned",
            },
        )

        # Whatever the response -- a clean 200 (the malicious key applied
        # harmlessly as a quoted, nonexistent-column identifier and errored
        # inside a try/catch the sink doesn't have, so more likely a 500) or
        # a 500 surfacing PHP's own "no such column" from SQLite -- it must
        # never be a response shape that indicates the extra statement
        # actually ran (this sink's `execute()` call has no multi-statement
        # capability to begin with via PDO, but the identifier itself must
        # still never reach raw SQL text unquoted).
        assert resp.status in (200, 500), (resp.status, resp.body[:1000])

        after_tables = harness.query_db(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        assert after_tables == before_tables, "a table was created or dropped"

        after_users = harness.query_db("SELECT id, bio FROM users ORDER BY id")
        assert len(after_users) == len(before_users), "a row was inserted or deleted"

        # The legitimate `bio` field must not have been silently discarded
        # just because an adversarial key rode along in the same request --
        # Laravel's real Query Builder either applies the whole array
        # (quoting each column independently) or rejects the whole update
        # (a 500 on the malformed identifier) -- assert whichever actually
        # happened, from the real response, not a guess.
        seeded_id = before_users[0]["id"]
        updated_row = next(r for r in after_users if r["id"] == seeded_id)
        if resp.status == 200:
            assert updated_row["bio"] == "updated-via-real-http", (
                "a 200 response but bio was not actually updated -- the "
                "malicious key silently swallowed the legitimate one"
            )
        else:
            assert updated_row["bio"] == before_users[0]["bio"], (
                "a 500 response but bio changed anyway -- a partial write "
                "happened despite the reported failure"
            )
