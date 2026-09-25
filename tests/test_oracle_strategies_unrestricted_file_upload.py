"""UnrestrictedFileUploadContentTypeTrustStrategy (CC-AUD-0023/CC-FUZZ-0040):
the deliberately-deferred detection follow-on `CC-LAB-0186` flagged for
`unrestricted_file_upload` (CWE-434) -- this project's first real
`multipart/form-data` two-probe differential over Twitch's own
`no_extension_check`/`extension_allowlist_mime_check` twins (`TWCH-0009`).
Mirrors `test_oracle_strategies_mass_assignment.py`'s own vulnerable/
secure-twin fake-sender pattern.
"""

from __future__ import annotations

from fuzzlab.audit.rules import load_rules, matches
from fuzzlab.oracle.probe import Candidate, Probe
from fuzzlab.oracle.strategies import (
    _MINIMAL_PNG_BYTES,
    UnrestrictedFileUploadContentTypeTrustStrategy,
)


def _cand():
    return Candidate(url="http://h/channels/emotes/upload", param="file",
                     method="POST", location="body", vuln_class="unrestricted_file_upload",
                     category="unrestricted-file-upload", sink_context="fs_web_root_write")


def _multipart_bytes(value: str) -> bytes:
    """Recover the raw multipart body the strategy built (it was latin-1
    round-tripped into `value` for the `Sender`'s own `str`-only interface --
    see `_multipart_body`'s own docstring)."""
    return value.encode("latin-1")


class _NoExtensionCheckVulnerableSender:
    """Simulates `NoExtensionCheckSink`: writes the upload verbatim and
    serves it back with a `Content-Type` from `mime.TypeByExtension` on the
    caller-supplied filename -- a `.svg` upload is served as
    `image/svg+xml` regardless of what the real bytes are; a `.png` upload
    is served as `image/png` the same way (since the extension happens to
    match reality for the control probe too)."""

    _EXT_TO_TYPE = {"svg": "image/svg+xml", "png": "image/png"}

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        raw = _multipart_bytes(value)
        filename = raw.split(b'filename="', 1)[1].split(b'"', 1)[0].decode("ascii")
        body = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        ext = filename.rsplit(".", 1)[-1]
        served_type = self._EXT_TO_TYPE.get(ext, "application/octet-stream")
        return Probe(200, body.decode("utf-8", "replace"),
                     headers={"Content-Type": served_type})


class _ExtensionAllowlistMimeCheckSecureSender:
    """Simulates `ExtensionAllowlistMimeCheckSink`: rejects any extension
    outside the image allowlist, then rejects real non-image bytes even on
    an allowlisted extension, and always serves the SNIFFED type."""

    _ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        raw = _multipart_bytes(value)
        filename = raw.split(b'filename="', 1)[1].split(b'"', 1)[0].decode("ascii")
        body = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        ext = filename.rsplit(".", 1)[-1]
        if ext not in self._ALLOWED_EXT:
            return Probe(415, "unsupported file extension")
        if not body.startswith(b"\x89PNG\r\n\x1a\n"):
            return Probe(415, "uploaded content is not a real image")
        return Probe(200, body.decode("latin-1"), headers={"Content-Type": "image/png"})


class _AlwaysHtmlPermissiveSender:
    """A false-positive-avoidance case: every upload, including a genuinely
    real PNG, is served back as `text/html` regardless of content -- a
    generically broken/permissive endpoint, not specifically the
    extension-trust vulnerability shape. Probe B's own real-image leg must
    reject this before it can confirm."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        raw = _multipart_bytes(value)
        body = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        return Probe(200, body.decode("latin-1"), headers={"Content-Type": "text/html"})


class _RejectsEverythingSender:
    """A false-negative-avoidance case: rejects both probes outright."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        return Probe(415, "rejected")


class _OctetStreamDownloadSender:
    """A false-positive-avoidance case: serves everything as
    `application/octet-stream` -- unusual, but harmless (forces a download,
    never executes) -- must not count as a script-executable type."""

    def send(self, url, param, value, timing=False, method="POST", location="body",
              content_type=None):
        raw = _multipart_bytes(value)
        body = raw.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        return Probe(200, body.decode("latin-1"), headers={"Content-Type": "application/octet-stream"})


def test_confirms_the_vulnerable_no_extension_check_twin():
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    verdict = strategy.confirm(_cand(), _NoExtensionCheckVulnerableSender())
    assert verdict is not None and verdict.confirmed
    assert verdict.vuln_class == "unrestricted_file_upload"
    assert verdict.mechanism == "extension-content-type-trust-differential"
    assert verdict.evidence["served_content_type"] == "image/svg+xml"
    assert verdict.evidence["control_content_type"] == "image/png"


def test_fails_closed_on_the_secure_extension_allowlist_mime_check_twin():
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    assert strategy.confirm(_cand(), _ExtensionAllowlistMimeCheckSecureSender()) is None


def test_fails_closed_on_an_always_html_permissive_target():
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    assert strategy.confirm(_cand(), _AlwaysHtmlPermissiveSender()) is None


def test_fails_closed_when_everything_is_rejected():
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    assert strategy.confirm(_cand(), _RejectsEverythingSender()) is None


def test_fails_closed_on_a_harmless_octet_stream_download_target():
    strategy = UnrestrictedFileUploadContentTypeTrustStrategy()
    assert strategy.confirm(_cand(), _OctetStreamDownloadSender()) is None


def test_minimal_png_bytes_have_a_real_png_signature():
    assert _MINIMAL_PNG_BYTES.startswith(b"\x89PNG\r\n\x1a\n")


def test_registered_in_default_strategies():
    from fuzzlab.oracle.strategies import default_strategies
    kinds = [type(s) for s in default_strategies()]
    assert UnrestrictedFileUploadContentTypeTrustStrategy in kinds


def test_r_unrestricted_file_upload_rule_matches_the_fs_web_root_write_point():
    class _Point:
        location = "body"
        method = "POST"
        param = "file"
        sink_context = "fs_web_root_write"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-UNRESTRICTED-FILE-UPLOAD")
    assert matches(rule, _Point())


def test_r_unrestricted_file_upload_rule_does_not_match_a_query_point():
    class _Point:
        location = "query"
        method = "GET"
        param = "file"
        sink_context = "fs_web_root_write"

    rules = load_rules()
    rule = next(r for r in rules if r.id == "R-UNRESTRICTED-FILE-UPLOAD")
    assert not matches(rule, _Point())


def test_vuln_class_is_reachable_from_its_category():
    from fuzzlab.core.runmode import to_category

    assert to_category("unrestricted_file_upload") == "unrestricted-file-upload"
