"""Tests for the parameter location/encoding axis (CR-LAB-0001 §3.4, lane
L-P2.4): `fuzzlab.labgen.schema.ParamSpec` (a `Cell`-level field, not a
`SinkContext` field -- see `ParamSpec`'s docstring for why) and the matching
`fuzzlab.labgen.oracle_wrapper` gap-fill (cookie/JSON marking + encoding for
SSTImap's marker mechanism).

Every oracle-side assertion uses an injected fake runner, same convention as
`tests/test_labgen_oracle_wrapper.py`; no real subprocess or binary is
needed.
"""

import base64
import shutil

import pytest

from fuzzlab.labgen import schema
from fuzzlab.labgen.oracle_wrapper import (
    Encoding,
    OracleRunResult,
    ParamLocation,
    ServerSideTemplateInjectionOracleRequest,
    Verdict,
    run_server_side_template_injection_oracle,
)


def _ok_run(argv, stdout="", stderr="", returncode=0):
    return OracleRunResult(argv=argv, returncode=returncode, stdout=stdout, stderr=stderr,
                            timed_out=False, duration_s=0.01)


class FakeRunner:
    """Scripted, dependency-injected runner (same convention as
    tests/test_labgen_oracle_wrapper.py's FakeRunner)."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def __call__(self, argv, timeout_s):
        self.calls.append((list(argv), timeout_s))
        if not self._results:
            raise AssertionError("FakeRunner called more times than results were queued")
        return self._results.pop(0)


# --- schema.py: ParamSpec / Cell.param --------------------------------------

def _valid_manifest_dict(param=None):
    cell = {
        "cell_id": "T-0001",
        "class": "sqli",
        "stack_profile": "php_current",
        "route": {"method": "GET", "path": "/x"},
        "sink_context": {
            "family": "sql_numeric_literal",
            "required_neutralizations": ["sql_syntax_break"],
        },
        "transform": [],
    }
    if param is not None:
        cell["param"] = param
    return {
        "manifest_version": 1,
        "safety_matrix_version": 1,
        "cells": [cell],
    }


def test_cell_param_defaults_to_query_raw_when_omitted():
    """Every existing cell (today's entire corpus) omits `param` entirely --
    it must keep meaning query/raw, not fail to load."""
    manifest = schema.Manifest.from_dict(_valid_manifest_dict(), validate=False)
    cell = manifest.cells[0]
    assert cell.param == schema.ParamSpec(location="query", encoding="raw")


@pytest.mark.parametrize("location", list(schema.PARAM_LOCATIONS))
@pytest.mark.parametrize("encoding", list(schema.PARAM_ENCODINGS))
def test_every_declared_location_and_encoding_combination_validates_and_round_trips(location, encoding):
    d = _valid_manifest_dict(param={"location": location, "encoding": encoding})
    schema.validate_manifest(d)
    manifest = schema.Manifest.from_dict(d, validate=False)
    cell = manifest.cells[0]
    assert cell.param.location == location
    assert cell.param.encoding == encoding
    assert cell.param.to_dict() == {"location": location, "encoding": encoding}


def test_non_query_non_raw_cell_renders_correctly_end_to_end():
    """The exact case the task calls out: a cookie-located, base64-encoded
    parameter cell round-trips through the full manifest load/validate path
    (the render step for this generator-input IR)."""
    d = _valid_manifest_dict(param={"location": "cookie", "encoding": "base64"})
    schema.validate_manifest(d)
    manifest = schema.Manifest.from_dict(d, validate=False)
    cell = manifest.cells[0]
    assert cell.param.location == "cookie"
    assert cell.param.encoding == "base64"
    # Not a verdict input: two cells differing only in `param` still derive
    # the same sink_context/transform pair unaffected.
    assert cell.sink_context == schema.SinkContext.from_dict(
        {"family": "sql_numeric_literal", "required_neutralizations": ["sql_syntax_break"]}
    )


def test_invalid_param_location_rejected_by_json_schema():
    d = _valid_manifest_dict(param={"location": "form_field_that_does_not_exist"})
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(d)


def test_invalid_param_encoding_rejected_by_json_schema():
    d = _valid_manifest_dict(param={"encoding": "rot13"})
    with pytest.raises(schema.ManifestError):
        schema.validate_manifest(d)


def test_param_spec_constructed_directly_validates_location_and_encoding():
    with pytest.raises(schema.ManifestError):
        schema.ParamSpec(location="not-a-location")
    with pytest.raises(schema.ManifestError):
        schema.ParamSpec(encoding="not-an-encoding")


def test_param_axis_is_orthogonal_to_verdict_derivation():
    """Two cells identical except for `param` must still be classified
    identically by fuzzlab.labgen.verdict -- the whole point of putting this
    axis on Cell rather than SinkContext."""
    from fuzzlab.labgen.verdict import load_safety_matrix, verdict as derive_verdict

    matrix = load_safety_matrix("lab/safety_matrix.yaml")
    raw = _valid_manifest_dict()
    encoded = _valid_manifest_dict(param={"location": "header", "encoding": "double_url_encoded"})
    cell_raw = schema.Manifest.from_dict(raw, validate=False).cells[0]
    cell_encoded = schema.Manifest.from_dict(encoded, validate=False).cells[0]
    assert cell_raw.param != cell_encoded.param
    v_raw = derive_verdict(cell_raw.transform, cell_raw.sink_context, matrix)
    v_encoded = derive_verdict(cell_encoded.transform, cell_encoded.sink_context, matrix)
    assert v_raw == v_encoded


# --- oracle_wrapper.py: cookie/JSON marking + encoding for SSTImap ----------

def test_sstimap_argv_scopes_to_cookie_and_marks_the_declared_cookie_key(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="session_theme",
        param_location=ParamLocation.COOKIE,
        cookie="session_id=abc123; session_theme=dark",
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    assert argv[argv.index("-P") + 1] == "C"
    cookie_flags = [argv[i + 1] for i, a in enumerate(argv) if a == "-C"]
    assert "session_id=abc123" in cookie_flags
    assert "session_theme=*" in cookie_flags  # marked, default marker
    assert verdict.confirmed_secure


def test_sstimap_argv_scopes_to_json_and_marks_the_declared_json_key(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="username",
        param_location=ParamLocation.JSON, method="POST",
        data='{"username": "test", "keep_me": "unchanged"}',
    )
    runner = FakeRunner([_ok_run(
        [], stdout="SSTImap identified the following injection point:\n\n  JSON parameter: username"
    )])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    # JSON has no dedicated -P category in SSTImap; it shares BODY's flag.
    assert argv[argv.index("-P") + 1] == "B"
    import json as _json
    marked = _json.loads(argv[argv.index("-d") + 1])
    assert marked["username"] == "*"
    assert marked["keep_me"] == "unchanged"  # untouched -- never swept
    assert verdict.confirmed_vulnerable


@pytest.mark.parametrize("encoding,expect_wire_marker", [
    (Encoding.URL_ENCODED, "%2A"),
    (Encoding.DOUBLE_URL_ENCODED, "%252A"),
    (Encoding.BASE64, base64.b64encode(b"*").decode("ascii")),
])
def test_sstimap_non_raw_encoding_is_applied_to_the_marker_on_the_wire(monkeypatch, encoding, expect_wire_marker):
    """The oracle wrapper must encode the marker itself (never send the raw
    marker when a non-raw encoding is declared) -- this is the "decode/
    re-encode correctly" gap the task calls out."""
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="X-Theme",
        param_location=ParamLocation.HEADER,
        headers={"X-Theme": "unused", "X-Other": "keep"},
        encoding=encoding,
    )
    runner = FakeRunner([_ok_run([], stdout="appear to be not injectable")])
    run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    header_flags = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert f"X-Theme: {expect_wire_marker}" in header_flags
    assert "X-Other: keep" in header_flags  # untouched -- never swept
    # -M must be told to look for the *encoded* marker, not the raw one, or
    # SSTImap would never find the injection point it just wrote.
    assert argv[argv.index("-M") + 1] == expect_wire_marker


def test_encoded_cookie_located_cell_still_confirms_vulnerable_end_to_end(monkeypatch):
    """The full L-P2.4 scenario: a non-query location (cookie) combined with
    a non-raw encoding (base64), and the oracle confirmation still succeeds
    against a fake runner."""
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sstimap")
    request = ServerSideTemplateInjectionOracleRequest(
        target_url="http://127.0.0.1:8089/", param_name="pref",
        param_location=ParamLocation.COOKIE,
        cookie="pref=unused",
        encoding=Encoding.BASE64,
    )
    expected_marker = base64.b64encode(b"*").decode("ascii")
    runner = FakeRunner([_ok_run(
        [], stdout="SSTImap identified the following injection point:\n\n  Cookie parameter: pref"
    )])
    verdict = run_server_side_template_injection_oracle(request, runner=runner)
    argv, _ = runner.calls[0]
    cookie_flags = [argv[i + 1] for i, a in enumerate(argv) if a == "-C"]
    assert f"pref={expected_marker}" in cookie_flags
    assert verdict.confirmed_vulnerable
