"""Live-boot conformance check for `spring_boot` (`CC-LAB-0130`, TrackerNest,
category 3's Atlassian pick, one cell only per that entry's pre-change
review).

Unlike most `tests/test_labgen_*` modules, this is a **real, on-host
integration test**: it assembles a real Spring Boot project from the
checked-in skeleton plus a real manifest's real `SpringBootEmitter` output,
runs a real `mvn package` against Maven Central, boots a real executable jar
(`java -jar`), and makes real HTTP requests against it -- one cell per
harness instance (see `live_boot_spring_boot.py`'s own docstring for why the
two twin cells share a route and are never booted together).

Skip-guarded (PA-0005) on `spring_boot_boot_available()` -- java + mvn on
PATH and Maven Central actually reachable -- so this SKIPS cleanly, not
fails, in any environment without them. Marked `@pytest.mark.slow` (a real
`mvn package` against the network).

**What this proves, and what it does not.** Real boot + real HTTP responses
+ a real payload differential on the `LABGEN-SSTI-0001`/`LABGEN-SSTI-0002`
twin pair: the vulnerable twin evaluates the tainted `macroExpr` query
parameter as an OGNL expression (`7*7` -> `49`); the secure twin only ever
selects among a fixed macro-name map (`7*7` -> "Unknown macro", `welcome` ->
its fixed body), never compiling tainted input as an expression. This proves
live-boot capability and one real, observable payload differential -- the
same bar `php_laravel`'s very first live-boot test set (`CC-LAB-0054`) --
not an oracle-grade Tier 2 parity gate, and not XXE/insecure-deserialization
(deferred to a follow-on entry, `CC-LAB-0130`'s "Out of scope" section).
"""

from __future__ import annotations

import pytest

from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest

pytestmark = pytest.mark.skipif(
    not spring_boot_boot_available(),
    reason=(
        "live-boot harness requires java + mvn on PATH and real Maven Central "
        "network reachability (PA-0005) -- see live_boot_spring_boot.spring_boot_boot_available()"
    ),
)


@pytest.mark.slow
def test_ssti_vulnerable_twin_evaluates_ognl_expression_for_real() -> None:
    """The vulnerable cell (`user_supplied_template_compile`) must actually
    evaluate an attacker-supplied arithmetic OGNL expression server-side --
    the classic, well-established `7*7` -> `49` SSTI proof-of-concept shape
    (never a destructive/RCE-shaped payload; this is a benign expression-
    evaluation proof, matching this project's existing corpus-example
    convention for SSTI cells)."""
    manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    vulnerable = cells["LABGEN-SSTI-0001"]
    assert emitter.supports(vulnerable.vuln_class, vulnerable.sink_context)

    with SpringBootLiveBootHarness(emitter, vulnerable) as harness:
        resp = harness.get("/wiki/pages/render", params={"macroExpr": "7*7"})
        assert resp.status == 200, resp.body
        assert "49" in resp.body, resp.body


@pytest.mark.slow
def test_ssti_secure_twin_never_evaluates_the_tainted_value() -> None:
    """The secure cell (`file_loaded_template_name`) must treat the same
    tainted value as a macro **name** only: the same `7*7` payload that
    evaluates to `49` on the vulnerable twin must NOT evaluate here (it is
    simply an unrecognized macro name), while a real, fixed, developer-
    defined macro name still resolves to its real fixed body -- proving the
    secure twin's lookup path actually runs, not merely that evaluation is
    absent."""
    manifest = load_manifest("lab/manifests/ssti_spring_boot_sample.yaml")
    emitter = SpringBootEmitter()
    cells = {c.cell_id: c for c in manifest.cells}
    secure = cells["LABGEN-SSTI-0002"]
    assert emitter.supports(secure.vuln_class, secure.sink_context)

    with SpringBootLiveBootHarness(emitter, secure) as harness:
        injection_resp = harness.get("/wiki/pages/render", params={"macroExpr": "7*7"})
        assert injection_resp.status == 200, injection_resp.body
        assert "49" not in injection_resp.body, injection_resp.body
        assert "Unknown macro" in injection_resp.body, injection_resp.body

        legitimate_resp = harness.get("/wiki/pages/render", params={"macroExpr": "welcome"})
        assert legitimate_resp.status == 200, legitimate_resp.body
        assert "Welcome to the team wiki!" in legitimate_resp.body, legitimate_resp.body
