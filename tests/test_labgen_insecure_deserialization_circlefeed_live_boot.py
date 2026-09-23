"""Live-boot conformance check for `php_laravel`'s account-settings
insecure-deserialization cell (`CC-LAB-0220`, CircleFeed -- category 2's
Facebook pick, fourth and final designed cell).

Real, on-host integration tests, same discipline as every other
`test_labgen_*_live_boot.py` module and, per `PA-0034`, a real, executed
adversarial payload rather than a source-level "unserialize() is present"
glance -- porting `CC-LAB-0097`'s (PicTrail inbox, Python pickle) proof
structure into PHP terms:

1. **Both directions of the differential**: a real, crafted PHP
   `unserialize()` payload -- a serialized `App\\Support\\MarkerWriteGadget`
   instance -- whose `__wakeup()` magic method writes a real, checkable
   marker file genuinely executes on the vulnerable twin, proven by the
   marker file's own existence after the request, not merely by the
   response claiming success. The identical bytes reach the secure twin's
   `json_decode()` instead, which cannot parse PHP's serialize() format at
   all (it is not JSON), so the marker file is never created and the
   secure twin reports a real parse failure (HTTP 400).
2. **The secure twin's own positive path, proven separately**: a
   legitimate JSON array payload must still succeed on the secure twin
   (HTTP 200, `parsed_type: "array"`) -- proving `json_decode_type_check`
   is a real, working deserializer, not a blanket rejection that would
   trivially "block" the unserialize payload too.
3. **Ground truth cross-check** (`CF-0004`, extending the same directory
   `CC-LAB-0216`/`CC-LAB-0217`/`CC-LAB-0218` established).

The `pref` cookie is sent as a raw `Cookie` request header (never through
an HTTP client's own cookie jar, which could re-encode or drop it) --
percent-encoded so PHP's own automatic cookie-value `urldecode()` (which
turns a literal, un-encoded `+` into a space) cannot corrupt the base64
payload's own `+`/`/`/`=` characters in transit.

Skip-guarded (PA-0005) on `live_boot_available()`. Marked `@pytest.mark.slow`.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse

import pytest

from fuzzlab.labels.contract import load as load_ground_truth
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

_GROUND_TRUTH_DIR = "lab/ground-truth-circlefeed"
_MANIFEST_PATH = "lab/manifests/insecure_deserialization_circlefeed_sample.yaml"


def _cells():
    manifest = load_manifest(_MANIFEST_PATH)
    return {c.cell_id: c for c in manifest.cells}


# --- crafted payloads -------------------------------------------------------


def _serialized_marker_gadget(marker_path: str) -> str:
    """A hand-built PHP `serialize()`-format string for one
    `App\\Support\\MarkerWriteGadget` instance (see the skeleton class of
    the same name) -- never actually calling PHP's own `serialize()`
    (there is no PHP object in this Python process to serialize), which is
    the point: this is exactly what an attacker who only knows the target
    class's public property names would hand-craft, the same "a real,
    crafted payload" discipline `CC-LAB-0097`'s own pickle proof used.

    PHP's serialized-object format: `O:<len>:"<class>":<n>:{<props>}`,
    each property as `s:<len>:"<name>";s:<len>:"<value>";`.
    """
    class_name = "App\\Support\\MarkerWriteGadget"
    props = {"markerPath": marker_path, "markerContents": "pwned"}
    body = "".join(
        f's:{len(k)}:"{k}";s:{len(v)}:"{v}";' for k, v in props.items()
    )
    serialized = f'O:{len(class_name)}:"{class_name}":{len(props)}:{{{body}}}'
    return base64.b64encode(serialized.encode("utf-8")).decode("ascii")


def _json_array_payload() -> str:
    return base64.b64encode(json.dumps(["hello"]).encode("utf-8")).decode("ascii")


def _cookie_header(value: str) -> dict[str, str]:
    """Percent-encode the cookie value before sending it as a raw `Cookie`
    header -- PHP's own automatic cookie-value `urldecode()` turns a
    literal, un-encoded `+` into a space, which would silently corrupt a
    base64 payload's own `+` characters (this is not hypothetical: the
    marker-gadget payload above genuinely contains `+`-shaped base64
    output on some inputs, and every JSON payload's base64 encoding can
    too), so this must be encoded on the way out."""
    return {"Cookie": f"pref={urllib.parse.quote(value, safe='')}"}


# --- tests -------------------------------------------------------------


@pytest.mark.slow
def test_vulnerable_twin_really_executes_the_unserialized_payload(tmp_path) -> None:
    """A real, crafted `unserialize()` payload must genuinely execute its
    `__wakeup()` hook inside the booted app process -- proven by the
    marker file it writes actually appearing on disk."""
    marker_path = str(tmp_path / "pwned.txt")
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-CF-0007"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        resp = harness.get(url)
        # Sanity: with no cookie at all, base64_decode('') fails cleanly --
        # confirms the route is reachable and doesn't error before we send
        # the real payload below.
        assert resp.status in (400, 200), resp.body

        payload = _serialized_marker_gadget(marker_path)
        resp = harness.request("GET", url, headers=_cookie_header(payload))

    assert resp.status == 200, resp.body
    body = json.loads(resp.body)
    assert body["ok"] is True
    assert body["parsed_type"] == "App\\Support\\MarkerWriteGadget"
    with open(marker_path, encoding="utf-8") as fh:
        assert fh.read() == "pwned", "the vulnerable twin must genuinely execute the __wakeup() hook"


@pytest.mark.slow
def test_secure_twin_never_executes_the_same_payload(tmp_path) -> None:
    """The identical unserialize() bytes against the secure twin must
    never reach `unserialize()` at all -- `json_decode()` cannot parse
    PHP's serialize() format, so the marker file must never be created,
    and the response must report a real parse failure."""
    marker_path = str(tmp_path / "pwned.txt")
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-CF-0008"]
    assert emitter.supports(cell.vuln_class, cell.sink_context)

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        payload = _serialized_marker_gadget(marker_path)
        resp = harness.request("GET", url, headers=_cookie_header(payload))

    assert resp.status == 400, resp.body
    body = json.loads(resp.body)
    assert body["ok"] is False
    assert not os.path.exists(marker_path), (
        "the secure twin must never execute the unserialize payload -- the marker file must not exist"
    )


@pytest.mark.slow
def test_secure_twin_still_accepts_a_legitimate_json_payload() -> None:
    """The secure twin's `json_decode()` path must still work for a real,
    legitimate JSON-array payload -- proving it's a genuine working
    deserializer, not a blanket rejection that would "block" the
    unserialize payload above only by accident."""
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-CF-0008"]

    with LiveBootHarness(emitter, [cell]) as harness:
        url = served_url_for(cell)
        resp = harness.request("GET", url, headers=_cookie_header(_json_array_payload()))

    assert resp.status == 200, resp.body
    body = json.loads(resp.body)
    assert body == {"ok": True, "parsed_type": "array"}


@pytest.mark.slow
def test_ground_truth_case_cf_0004_matches_the_real_served_page(tmp_path) -> None:
    """`CF-0004` names the vulnerable cell's own served URL as a real,
    exploitable insecure deserialization. Loaded independently (never
    re-deriving the URL from `LaravelEmitter`'s own `_PAGE_PROFILES`
    internals) and confirmed against a real booted request at exactly
    that URL, with the same adversarial payload the differential tests
    above use."""
    ground_truth = load_ground_truth(_GROUND_TRUTH_DIR)
    case = ground_truth.case_by_id("CF-0004")
    assert case is not None, "CF-0004 must exist in the loaded ground truth"
    assert case.expected_vulnerable is True
    assert case.vuln_class == "insecure_deserialization"
    assert case.sink_context == "deserialization"
    assert case.location == "cookie"
    assert case.param == "pref"

    marker_path = str(tmp_path / "pwned.txt")
    emitter = LaravelEmitter()
    cell = _cells()["LABGEN-CF-0007"]
    assert served_url_for(cell) == case.url

    with LiveBootHarness(emitter, [cell]) as harness:
        payload = _serialized_marker_gadget(marker_path)
        resp = harness.request(case.method, case.url, headers=_cookie_header(payload))

    assert resp.status == 200, resp.body
    with open(marker_path, encoding="utf-8") as fh:
        assert fh.read() == "pwned", (
            "the ground truth's own expected_vulnerable=true claim must hold at the exact "
            "URL/method/param it names"
        )
