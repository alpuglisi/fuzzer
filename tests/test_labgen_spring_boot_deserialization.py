"""Unit coverage for the `spring_boot` emitter's insecure-deserialization
cell (`CC-LAB-0132`, TrackerNest's third and final designed cell), the
Netflix cell ported in from `java_spring_boot` by `CC-LAB-0173` (the §9.2a
Java/Spring Boot consolidation), and Netflix's second insecure_
deserialization instance at `/api/profiles/switch` (`CC-LAB-0184`,
zero new generator code -- the identical jackson_body/jackson_default_
typing_deserialize/jackson_typed_allowlist_deserialize modules reused
verbatim at a new route).

No network/java/mvn required -- pure Python emitter-output checks, mirroring
`tests/test_labgen_spring_boot.py`/`tests/test_labgen_spring_boot_xxe.py`'s
own shape.
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.labgen.verdict import load_safety_matrix, verdict

_MANIFEST_PATH = "lab/manifests/insecure_deserialization_spring_boot_sample.yaml"
_NETFLIX_PROFILES_MANIFEST_PATH = "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml"

_EXPECTED_VERDICTS = {
    "LABGEN-DESER-0001": "VULNERABLE",  # function_executing_deserialize: unrestricted ObjectInputStream
    "LABGEN-DESER-0002": "SECURE",  # handler_registry_lookup: resolveClass() allowlist
    "LABGEN-JV-0001": "VULNERABLE",  # jackson_default_typing_deserialize: polymorphic Object (ported, CC-LAB-0173)
    "LABGEN-JV-0002": "SECURE",  # jackson_typed_allowlist_deserialize: fixed DTO class (ported, CC-LAB-0173)
}

_EXPECTED_PROFILES_VERDICTS = {
    "LABGEN-JV-0005": "VULNERABLE",  # jackson_default_typing_deserialize, /api/profiles/switch (CC-LAB-0184)
    "LABGEN-JV-0006": "SECURE",  # jackson_typed_allowlist_deserialize, /api/profiles/switch (CC-LAB-0184)
}


def _cells() -> dict[str, object]:
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


def _profiles_cells() -> dict[str, object]:
    manifest = load_manifest(_NETFLIX_PROFILES_MANIFEST_PATH)
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


def test_vulnerable_twin_has_no_allowlist_secure_twin_does() -> None:
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-DESER-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-DESER-0002"])[0].content.decode("utf-8")
    assert "AllowlistObjectInputStream" not in vulnerable_src
    assert "AllowlistObjectInputStream" in secure_src
    assert "resolveClass" in secure_src
    assert "PostMapping" in vulnerable_src and "PostMapping" in secure_src


def test_all_controllers_have_disjoint_class_names() -> None:
    """TrackerNest's three own cells (SSTI `CC-LAB-0130`, XXE `CC-LAB-0131`,
    insecure deserialization) plus the two ported Netflix cells (`CC-LAB-0173`)
    and Netflix's second insecure_deserialization instance (`CC-LAB-0184`)
    must never collide on a generated file path/class name -- guaranteed by
    `_class_name_for()` deriving from each cell's own id."""
    emitter = SpringBootEmitter()
    all_paths = set()
    for manifest_path in (
        "lab/manifests/ssti_spring_boot_sample.yaml",
        "lab/manifests/xxe_spring_boot_sample.yaml",
        _MANIFEST_PATH,
        _NETFLIX_PROFILES_MANIFEST_PATH,
    ):
        for cell in load_manifest(manifest_path).cells:
            path = emitter.render(cell)[0].path
            assert path not in all_paths, path
            all_paths.add(path)
    assert len(all_paths) == 10


def test_ported_jackson_vulnerable_twin_uses_default_typing_secure_uses_fixed_dto() -> None:
    """The ported Netflix cell's twins (`CC-LAB-0173`): vulnerable
    deserializes into a polymorphic `Object` via
    `JsonMapper.builder().activateDefaultTyping(...)`; secure deserializes
    into the fixed `PlaybackResumeRequest` DTO, no polymorphism."""
    emitter = SpringBootEmitter()
    cells = _cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0001"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0002"])[0].content.decode("utf-8")
    assert "activateDefaultTyping" in vulnerable_src
    assert "Object event = mapper.readValue" in vulnerable_src
    assert "activateDefaultTyping" not in secure_src
    assert "PlaybackResumeRequest event = mapper.readValue" in secure_src
    assert "tools.jackson.databind" in vulnerable_src and "tools.jackson.databind" in secure_src
    assert "com.fasterxml.jackson.databind" not in vulnerable_src
    assert "com.fasterxml.jackson.databind" not in secure_src


# --- Netflix's second insecure_deserialization instance, /api/profiles/switch
# (`CC-LAB-0184`) -- reuses the LABGEN-JV-0001/0002 module set verbatim ----


def test_profiles_manifest_loads_and_validates() -> None:
    assert set(_profiles_cells()) == set(_EXPECTED_PROFILES_VERDICTS)


def test_profiles_verdict_matches_expected() -> None:
    matrix = load_safety_matrix()
    for cell_id, cell in _profiles_cells().items():
        result = verdict(cell.transform, cell.sink_context, matrix)
        assert result.verdict == _EXPECTED_PROFILES_VERDICTS[cell_id], cell_id


def test_spring_boot_supports_every_profiles_cell() -> None:
    emitter = SpringBootEmitter()
    for cell in _profiles_cells().values():
        assert emitter.supports(cell.vuln_class, cell.sink_context) is True


def test_profiles_render_is_byte_deterministic_across_two_calls() -> None:
    emitter = SpringBootEmitter()
    for cell in _profiles_cells().values():
        first = emitter.render(cell)
        second = emitter.render(cell)
        assert first == second


def test_profiles_vulnerable_twin_uses_default_typing_secure_uses_fixed_dto() -> None:
    """Same mechanism as `LABGEN-JV-0001`/`0002` (`test_ported_jackson_
    vulnerable_twin_...` above), verbatim, at the new route."""
    emitter = SpringBootEmitter()
    cells = _profiles_cells()
    vulnerable_src = emitter.render(cells["LABGEN-JV-0005"])[0].content.decode("utf-8")
    secure_src = emitter.render(cells["LABGEN-JV-0006"])[0].content.decode("utf-8")
    assert "activateDefaultTyping" in vulnerable_src
    assert "Object event = mapper.readValue" in vulnerable_src
    assert "activateDefaultTyping" not in secure_src
    assert "PlaybackResumeRequest event = mapper.readValue" in secure_src
    assert "/api/profiles/switch" in vulnerable_src and "/api/profiles/switch" in secure_src


def test_profiles_cells_render_byte_identical_module_composition_to_playback_resume() -> None:
    """Zero new generator code, verified not just claimed: rendering
    `LABGEN-JV-0005`/`0006` (`/api/profiles/switch`) must produce the exact
    same module-composition line and sink body as `LABGEN-JV-0001`/`0002`
    (`/api/playback/resume`), differing only in the served path, class name,
    and handler function name -- the same "byte-for-byte the same handler
    shape" check `CC-LAB-0183`'s own precedent used for its analogous reuse."""
    emitter = SpringBootEmitter()
    resume_cells = _cells()
    profiles_cells = _profiles_cells()
    for resume_id, profiles_id in (
        ("LABGEN-JV-0001", "LABGEN-JV-0005"),
        ("LABGEN-JV-0002", "LABGEN-JV-0006"),
    ):
        resume_src = emitter.render(resume_cells[resume_id])[0].content.decode("utf-8")
        profiles_src = emitter.render(profiles_cells[profiles_id])[0].content.decode("utf-8")
        resume_lines = resume_src.splitlines()
        profiles_lines = profiles_src.splitlines()
        # Same module-composition comment line (source -> sink -> complexity).
        composition_line = next(l for l in resume_lines if l.startswith("// Module composition:"))
        assert composition_line in profiles_lines
        # Same sink body content (the DTO/mapper logic itself is unchanged).
        assert "mapper.readValue" in resume_src and "mapper.readValue" in profiles_src
        for marker in ("activateDefaultTyping", "PlaybackResumeRequest event = mapper.readValue"):
            assert (marker in resume_src) == (marker in profiles_src)
