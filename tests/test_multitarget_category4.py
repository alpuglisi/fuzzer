"""Phase E: wire category 4's Netflix and Twitch apps into
`fuzzlab.harness.multitarget` for real (`CC-LAB-0176`/`FR-LAB-99`), per
`docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §6. Both apps are booted
for real (`GoLiveBootHarness`, `SpringBootLiveBootHarness`) and run through
`run_targets` in one call, using the real HTTP `RequestsProbeSender` this
project already has (`fuzzlab.tools.probesender`) -- never a fake sender,
matching category 1's own "genuinely testable in this sandbox" Phase E bar.
A real, started `OobListener` is also passed through (`CC-FUZZ-0027` closed
the `run_targets()` passthrough gap and added the project's first `ssrf`
audit rule + oracle strategies).

**What this now proves, and what remains honestly open (recorded here, not
routed around).** Twitch now has ten real cells (webhook-signature,
SSRF, access-control/IDOR, JWT `alg:none` confusion, predictable session
tokens, channel-profile mass assignment, a second access-control/IDOR
instance at `/channels/subscribers`, a second SSRF instance at
`/clips/download`, an unrestricted-file-upload cell at `/channels/
emotes/upload`, and a price-integrity-bypass cell at `/subscriptions/
purchase` -- `CC-LAB-0178`/`CC-LAB-0180`/`CC-LAB-0181`/`CC-LAB-0182`/
`CC-LAB-0183`/`CC-LAB-0185`/`CC-LAB-0186`/`CC-LAB-0189`, the "coherent
page/route set" depth work), and nine of the ten now confirm for real
(only webhook-signature does not -- its CWE-347 timing side channel is
empirically infeasible for this project's wall-clock HTTP measurement
model). The price-integrity-bypass cell (`TWCH-0010`, `CC-LAB-0189`)
needed zero new detection code: `PriceIntegrityBypassStrategy` (already
built for `spring_boot`'s Netflix cell, `CC-FUZZ-0037`) confirms the new
vulnerable twin and correctly fails closed on its new secure twin as-is,
verified against a real booted `go_net_http` app -- the first proof this
strategy generalizes across stacks in the direction `spring_boot` ->
`go_net_http`. The unrestricted-file-upload cell's own detection follow-on
(`TWCH-0009`, `CC-AUD-0023`/`CC-FUZZ-0036`) is new, genuinely new
detection logic (not a zero-new-code generalization like the two below):
`UnrestrictedFileUploadContentTypeTrustStrategy` sends a real
`multipart/form-data` two-probe differential -- an inert-marker `probe.svg`
upload (extension-plausible, bytes NOT a real image) must be accepted and
served back with a script-executable `Content-Type` derived from the
extension; a real-PNG `control.png` upload must independently be accepted
and correctly served as `image/png`, the false-positive defense that rules
out a legitimate SVG-accepting endpoint or a generically-permissive/broken
target -- and sees the vulnerable `no_extension_check` twin
(`LABGEN-GO-0017`) do exactly that, while correctly failing closed on the
secure `extension_allowlist_mime_check` twin (`LABGEN-GO-0018`, which
rejects the non-allowlisted upload outright). The second
access-control/IDOR instance (`TWCH-0007`, `CC-LAB-0183`) needed zero new
detection code: `AccessControlIdorStrategy` (already built for `TWCH-0003`,
`CC-FUZZ-0029`) is keyed on `vuln_class` + sink shape, not per-route, and
confirmed the new vulnerable twin (and correctly failed closed on its new
secure twin) as-is, verified against a real booted app -- proving the
existing detection genuinely generalizes to a second instance of the same
shape. The second SSRF instance (`TWCH-0008`, `CC-LAB-0185`) needed the
same zero-new-detection-code proof: `SsrfInBandMarkerStrategy`/
`SsrfOobStrategy` (already built for `TWCH-0002`, `CC-FUZZ-0027`) are
likewise keyed on `vuln_class` + sink shape, not per-route, and confirmed
the new vulnerable twin (and correctly failed closed on its new secure
twin) as-is, verified against a real booted app with a real `OobListener`.
The predictable-session-token case (`TWCH-0005`, `CC-FUZZ-0034`):
`PredictableTokenSourceStrategy` sees the vulnerable twin
(`LABGEN-GO-0009`) issue two consecutive tokens that both parse as
decimal integers with a small, non-negative delta (the primary false-
positive defense is the hex-vs-decimal parse gate, not delta-window
tightness -- a real `crypto/rand` hex token essentially never parses as
all-decimal), and correctly does not confirm the secure twin
(`LABGEN-GO-0010`, whose 64-hex-character tokens never parse as decimal
at all). The SSRF case (`TWCH-0002`):
`SsrfInBandMarkerStrategy` sees the vulnerable twin (`LABGEN-GO-0003`)
echo the OOB marker back in its own response body (`io.Copy(w,
resp.Body)`), and correctly does not confirm the secure twin
(`LABGEN-GO-0004`, blocked by its scheme/IP allowlist before any fetch). The
access-control/IDOR case (`TWCH-0003`, `CC-FUZZ-0029`):
`AccessControlIdorStrategy` sees the vulnerable twin (`LABGEN-GO-0005`)
accept and echo back any `channel_id`, and correctly does not confirm the
secure twin (`LABGEN-GO-0006`, blocked by its identity-match check). The
JWT `alg:none` confusion case (`TWCH-0004`, `CC-FUZZ-0033`):
`JwtAlgNoneConfusionStrategy` sees the vulnerable twin (`LABGEN-GO-0007`)
accept an unsigned `alg:none` token and echo its forged claims back (while
still correctly rejecting a garbage-signature `HS256`-claimed control
probe -- the two-probe differential this strategy needs to rule out a
generically-permissive endpoint), and correctly does not confirm the
secure twin (`LABGEN-GO-0008`, which rejects the same `alg:none` token
outright).

Netflix's `NFLX-0001` (insecure-deserialization) is now also a real,
confirmed finding (`CC-FUZZ-0030`): the whole-body-JSON case
`CC-FUZZ-0028` made content-type-aware now succeeds end to end through
this exact generic pipeline (not just the dedicated Phase D Tier1/2 test) --
`InsecureDeserializationTypeConfusionStrategy` sees the vulnerable twin
(`LABGEN-JV-0001`) accept and successfully deserialize an attacker-named
JDK class via Jackson's `WRAPPER_ARRAY` polymorphic-type format, and
correctly does not confirm the secure twin (`LABGEN-JV-0002`, no
polymorphic typing configured at all).

`NFLX-0002` (XXE) now also has a real rule/strategy pair
(`R-XXE`/`XxeInBandMarkerStrategy`, `CC-FUZZ-0031`, verified live against
TrackerNest's own XXE twins -- `tests/test_labgen_spring_boot_xxe_live_boot.py`
and `tests/test_labgen_spring_boot_trackernest_multitarget.py`).
`test_both_apps_run_through_multitarget_for_real` below still boots only
`LABGEN-JV-0001` (the insecure-deserialization vulnerable twin) via
`SpringBootLiveBootHarness`'s one-cell-per-boot constraint, so `NFLX-0002`
and `NFLX-0003` are structural false negatives *in that one test* -- not
because detection is missing, but because that test's single-cell boot
doesn't serve them. `test_netflix_multi_cell_boot_confirms_all_positives`
below closes that gap the way `tests/test_labgen_spring_boot_trackernest_
multitarget.py` already does for TrackerNest: a hand-rolled multi-cell
boot (bypassing `SpringBootLiveBootHarness`'s single-cell restriction,
assembling `LABGEN-JV-0001`, `LABGEN-JV-0003`, and `LABGEN-JV-0005`
together -- three distinct routes, `/api/playback/resume`,
`/api/content/import`, and `/api/profiles/switch`, so no same-route
collision), proving all three of Netflix's own positives confirm together
in one real boot.

`NFLX-0003` (`CC-LAB-0184`, `/api/profiles/switch`) is Netflix's third
real page: a second `insecure_deserialization` instance reusing
`LABGEN-JV-0001`/`0002`'s own module set verbatim -- zero new generator
code, mirroring `CC-LAB-0183`'s own reuse-at-a-new-route pattern.
`InsecureDeserializationTypeConfusionStrategy` (`CC-FUZZ-0030`, already
built for `NFLX-0001`) needed zero new detection code to confirm the new
vulnerable twin and correctly fail closed on its new secure twin,
verified against a real booted app both by a dedicated live-boot strategy
test (`tests/test_labgen_spring_boot_deserialization_netflix_profiles_
live_boot.py`) and by `test_netflix_multi_cell_boot_confirms_all_
positives` below -- Netflix's own real, scored recall in that multi-cell
boot moves from 2/2 to 3/3, proving the existing detection generalizes to
a second instance of the same shape, the same generalization proof
`CC-LAB-0183` made for Twitch's `access_control` detection.

`NFLX-0004` (`CC-LAB-0187`, `/api/account/billing`) is Netflix's fourth
real page, and genuinely new breadth rather than a depth increment:
Netflix's first `access_control`/IDOR (broken object-level authorization)
page, an account-billing-details lookup keyed by an attacker-visible
`account_id` query param. Reuses `lab/safety_matrix.yaml`'s existing
`db_row_by_id_lookup` sink family and `no_ownership_check`/
`identity_match_before_fetch` ops (`CC-LAB-0063`) -- no new safety-matrix
entry needed -- but this is this mechanism's first instantiation for the
`spring_boot` stack (a new source module and two new sink modules, since
this stack's shape has no separate transform stage). Detection needed
zero new code: `AccessControlIdorStrategy` (`CC-FUZZ-0029`, already built
for Twitch's `go_net_http` cells, `TWCH-0003`/`TWCH-0007`) confirmed the
new vulnerable twin and correctly failed closed on its new secure twin,
verified against a real booted app both by a dedicated live-boot strategy
test (`tests/test_labgen_spring_boot_account_billing_live_boot.py`) and by
`test_netflix_multi_cell_boot_confirms_all_positives` below -- Netflix's
own real, scored recall in that multi-cell boot moves from 3/3 to 4/4,
the first proof this strategy generalizes across stacks
(`go_net_http` -> `spring_boot`), not just across routes on the same
stack.

`NFLX-0005` (`CC-LAB-0188`, `/api/subscription/change-plan`) is Netflix's
fifth real page, again genuinely new breadth: Netflix's first
`price_integrity_bypass` page (CWE-807), and this concern's first
instantiation on `spring_boot` at all (the only prior real implementation
project-wide is `php_laravel`'s Booking.com checkout charge,
`CC-LAB-0212`). Unlike `NFLX-0004`'s detection, this one needed genuinely
new detection logic: `PriceIntegrityBypassStrategy`/`R-PRICE-INTEGRITY`
(`CC-FUZZ-0037`/`CC-AUD-0025`) -- a two-probe differential over the JSON
body's own `monthly_charge` field, confirming only when the server's own
reported charge tracks two different, deliberately implausible
client-submitted amounts rather than staying fixed regardless of input --
confirmed the new vulnerable twin and correctly failed closed on its new
secure twin, verified against a real booted app both by a dedicated
live-boot strategy test
(`tests/test_oracle_strategies_price_integrity_live_boot.py`) and by
`test_netflix_multi_cell_boot_confirms_all_positives` below -- Netflix's
own real, scored recall in that multi-cell boot moves from 4/4 to 5/5.
One gap remains open:

1. **No audit `Rule`/oracle strategy exists yet for `webhook_signature`**
   (`ssrf`/`access_control`/`insecure_deserialization`/`xxe` now all have
   one) -- `fuzzlab.core.runmode._VULN_TO_CATEGORY` doesn't map it, and it
   needs a genuinely new timing-statistics oracle (a single-request model
   cannot observe a comparison-timing side channel), not just a rule.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from fuzzlab.core.store import Store
from fuzzlab.harness.multitarget import TargetSpec, run_targets, transfer_summary
from fuzzlab.labels import contract
from fuzzlab.labgen.conformance.go_live_boot import GoLiveBootHarness, go_boot_available
from fuzzlab.labgen.conformance.live_boot_spring_boot import (
    SKELETON_DIR,
    SpringBootLiveBootHarness,
    spring_boot_boot_available,
)
from fuzzlab.labgen.emitters.go_net_http import GoEmitter
from fuzzlab.labgen.emitters.spring_boot import SpringBootEmitter
from fuzzlab.labgen.schema import load_manifest
from fuzzlab.oracle.oob import OobListener
from fuzzlab.tools.probesender import RequestsProbeSender

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not (go_boot_available() and spring_boot_boot_available()),
        reason="requires both the go toolchain (PA-0035) and java+mvn+Maven Central (PA-0005)",
    ),
]


def _twitch_cells():
    webhook = load_manifest("lab/manifests/webhook_signature_go_sample.yaml").cells
    ssrf = load_manifest("lab/manifests/ssrf_go_sample.yaml").cells
    access_control = load_manifest("lab/manifests/access_control_go_sample.yaml").cells
    jwt = load_manifest("lab/manifests/jwt_alg_confusion_go_sample.yaml").cells
    weak_token = load_manifest("lab/manifests/weak_token_entropy_go_sample.yaml").cells
    mass_assignment = load_manifest("lab/manifests/mass_assignment_go_sample.yaml").cells
    # CC-LAB-0183: second access_control/db_row_by_id_lookup instance
    # (/channels/subscribers), reusing CC-LAB-0178's modules verbatim.
    access_control_subscribers = load_manifest(
        "lab/manifests/access_control_subscribers_go_sample.yaml"
    ).cells
    # CC-LAB-0185: second ssrf/server_side_http_fetch instance
    # (/clips/download), reusing CC-LAB-0172's modules verbatim.
    ssrf_clips_download = load_manifest(
        "lab/manifests/ssrf_clips_download_go_sample.yaml"
    ).cells
    # CC-LAB-0186: this stack's first unrestricted_file_upload/
    # fs_web_root_write instance (/channels/emotes/upload). Its own
    # deliberately-deferred detection follow-on (CC-AUD-0023/CC-FUZZ-0036,
    # `R-UNRESTRICTED-FILE-UPLOAD`/`UnrestrictedFileUploadContentTypeTrust
    # Strategy`) has since landed, so TWCH-0009 now confirms for real too.
    unrestricted_file_upload = load_manifest(
        "lab/manifests/unrestricted_file_upload_go_sample.yaml"
    ).cells
    # CC-LAB-0189: this stack's first price_integrity_bypass/
    # payment_charge_amount instance (/subscriptions/purchase). Needed zero
    # new detection code: PriceIntegrityBypassStrategy (already built for
    # spring_boot's Netflix cell, CC-FUZZ-0037) confirms it verbatim.
    price_integrity = load_manifest(
        "lab/manifests/price_integrity_twitch_subscription_sample.yaml"
    ).cells
    # CC-LAB-0190: this project's first path_traversal/fs_path_read
    # instance on any stack (/clips/export). No detection (audit rule/
    # oracle strategy) exists yet for this concern -- included here so the
    # pipeline sees the new vulnerable/secure twins for real, but this
    # cell's own positive stays an (expected, tracked) false negative
    # until that follow-on lands, per this dispatch's own lab-then-
    # detection split.
    path_traversal = load_manifest("lab/manifests/path_traversal_go_sample.yaml").cells
    return (
        webhook + ssrf + access_control + jwt + weak_token + mass_assignment
        + access_control_subscribers + ssrf_clips_download + unrestricted_file_upload
        + price_integrity + path_traversal
    )


def _netflix_cell():
    cells = load_manifest("lab/manifests/insecure_deserialization_spring_boot_sample.yaml").cells
    return next(c for c in cells if c.cell_id == "LABGEN-JV-0001")


def test_both_apps_run_through_multitarget_for_real(tmp_path) -> None:
    go_emitter = GoEmitter()
    spring_emitter = SpringBootEmitter()
    listener = OobListener()
    listener.start()

    try:
        with GoLiveBootHarness(go_emitter, _twitch_cells()) as go_harness, \
                SpringBootLiveBootHarness(spring_emitter, _netflix_cell()) as spring_harness:
            twitch_gt = contract.load("lab/ground-truth-twitch-clone")
            netflix_gt = contract.load("lab/ground-truth-netflix-clone")
            specs = [
                TargetSpec("twitch-clone", go_harness.base_url, ground_truth=twitch_gt,
                           points_source="ground-truth"),
                TargetSpec("netflix-clone", spring_harness.base_url, ground_truth=netflix_gt,
                           points_source="ground-truth"),
            ]
            with Store(tmp_path / "u.db") as store:
                outcomes = run_targets(
                    specs, store, sender_for=lambda spec: RequestsProbeSender(timeout=10.0),
                    oob=listener,
                )
    finally:
        listener.stop()

    by_name = {o.name: o for o in outcomes}
    assert set(by_name) == {"twitch-clone", "netflix-clone"}
    # Both are scored (ground truth was supplied to both) -- the toolkit-side
    # wiring this phase proves, independent of what else was detected.
    assert by_name["twitch-clone"].scored
    assert by_name["netflix-clone"].scored
    # Real run against a real boot: distinct run IDs, no exception raised.
    assert by_name["twitch-clone"].run_id != by_name["netflix-clone"].run_id

    # Twitch: SSRF (TWCH-0002), access-control/IDOR (TWCH-0003), JWT
    # alg:none confusion (TWCH-0004), predictable session tokens
    # (TWCH-0005), mass assignment (TWCH-0006, CC-LAB-0182 +
    # CC-AUD-0022/CC-FUZZ-0035), the second access-control/IDOR instance at
    # /channels/subscribers (TWCH-0007, CC-LAB-0183), and the second SSRF
    # instance at /clips/download (TWCH-0008, CC-LAB-0185) are all now
    # real, confirmed findings. TWCH-0007 and TWCH-0008 each needed zero
    # new detection code -- `AccessControlIdorStrategy` (already built for
    # TWCH-0003) and `SsrfInBandMarkerStrategy`/`SsrfOobStrategy` (already
    # built for TWCH-0002) are each keyed on vuln_class + sink shape, not
    # per-route, and confirm their respective new vulnerable twins (and
    # correctly fail closed on the new secure twins) exactly as-is,
    # verified for real against this same real booted app, using the real
    # `OobListener` passed above. webhook-signature (TWCH-0001) still has
    # no rule/strategy (a CWE-347 timing side channel, empirically
    # infeasible for this project's wall-clock HTTP measurement model).
    # The 9th page's unrestricted-file-upload cell (TWCH-0009, CC-LAB-0186)
    # now ALSO confirms for real: its own deliberately-deferred detection
    # follow-on landed (`R-UNRESTRICTED-FILE-UPLOAD`/`UnrestrictedFileUpload
    # ContentTypeTrustStrategy`, CC-AUD-0023/CC-FUZZ-0036) -- a real
    # multipart/form-data two-probe differential (an inert-marker `probe.svg`
    # upload must be accepted and served back with a script-executable
    # Content-Type derived from the extension; a real-PNG `control.png`
    # upload must independently be accepted and correctly served as
    # `image/png`, ruling out a generically-permissive/broken endpoint or a
    # merely-harmless-but-unusual response type) that sees the vulnerable
    # `no_extension_check` twin (`LABGEN-GO-0017`) serve an uploaded
    # `probe.svg` back as `image/svg+xml` regardless of its real, non-image
    # bytes, and correctly fails closed on the secure
    # `extension_allowlist_mime_check` twin (`LABGEN-GO-0018`, which rejects
    # the non-allowlisted upload outright). The 10th page's
    # price-integrity-bypass cell (TWCH-0010, CC-LAB-0189) ALSO confirms for
    # real, needing zero new detection code: `PriceIntegrityBypassStrategy`
    # (already built for `spring_boot`'s Netflix cell, `CC-FUZZ-0037`) sees
    # the vulnerable `client_trusted_amount` twin (`LABGEN-GO-0019`) track
    # both of its two deliberately different, implausible submitted amounts
    # exactly, and correctly fails closed on the secure
    # `server_recomputed_amount` twin (`LABGEN-GO-0020`, which rejects the
    # unrecognized `plan_tier="standard"` probe outright with HTTP 400) --
    # the first proof this strategy generalizes across stacks in the
    # direction `spring_boot` -> `go_net_http` (complementing
    # `CC-LAB-0187`'s own proof of `AccessControlIdorStrategy` generalizing
    # the other way). The 11th page's path-traversal cell (TWCH-0011,
    # CC-LAB-0190) does NOT confirm here -- no audit rule/oracle strategy
    # exists yet for `path_traversal`/`fs_path_read` (a deliberately
    # deferred follow-on, this dispatch's own lab-then-detection split),
    # so it is a real, expected, tracked false negative. Ground-truth
    # cardinality moves from 10 to 11 positives (PA-0042: this hardcoded
    # fraction was re-derived, not left stale, when TWCH-0011 was added);
    # tp stays 9 (webhook-signature and path-traversal both remain
    # undetected, for different reasons -- one an empirically-infeasible
    # timing side channel, the other a genuinely unbuilt detection
    # mechanism), so recall moves from 9/10 to 9/11.
    twitch_report = by_name["twitch-clone"].report
    assert twitch_report.tp == 9 and twitch_report.fp == 0
    assert round(twitch_report.recall, 4) == round(9 / 11, 4)

    # Netflix: insecure-deserialization (NFLX-0001) is now a real, confirmed
    # finding; XXE (NFLX-0002, which does have a rule/strategy, R-XXE/
    # XxeInBandMarkerStrategy, CC-FUZZ-0031), the second
    # insecure-deserialization instance (NFLX-0003, CC-LAB-0184), the
    # first access_control/IDOR instance (NFLX-0004, CC-LAB-0187), and the
    # first price_integrity_bypass instance (NFLX-0005, CC-LAB-0188) are
    # simply not booted in this single-cell test -- one of its now-five
    # positives, not all (only NFLX-0001's own vulnerable twin,
    # LABGEN-JV-0001, is booted here) -- see
    # test_netflix_multi_cell_boot_confirms_all_positives below for the
    # multi-cell boot that confirms all five together.
    netflix_report = by_name["netflix-clone"].report
    assert netflix_report.tp == 1 and netflix_report.fp == 0
    assert round(netflix_report.recall, 4) == round(1 / 5, 4)

    summary = transfer_summary(outcomes)
    assert summary["targets"] == 2
    # PA-0042: re-derived, not left stale, from the ground-truth-cardinality
    # change TWCH-0011/CC-LAB-0190 made (Twitch's own recall moved from
    # 9/10 to 9/11 above).
    assert round(summary["macro_recall"], 4) == round(((9 / 11) + (1 / 5)) / 2, 4)
    # Both targets now show recall > 0 -- this project's own >= 2 "generalizes"
    # definition (transfer_summary's docstring) is met for the first time.
    assert summary["generalizes"] is True


# --- Netflix multi-cell boot: all of its own positives, one app (CC-FUZZ-0032,
# extended by CC-LAB-0184 to include the second insecure_deserialization
# instance at /api/profiles/switch) ---

_NETFLIX_MULTI_MANIFESTS = (
    "lab/manifests/insecure_deserialization_spring_boot_sample.yaml",
    "lab/manifests/xxe_netflix_sample.yaml",
    "lab/manifests/insecure_deserialization_netflix_profiles_sample.yaml",
    # CC-LAB-0187: fourth real page, first access_control/IDOR instance
    # (/api/account/billing) -- a fourth, distinct route, no collision.
    "lab/manifests/access_control_netflix_billing_sample.yaml",
    # CC-LAB-0188/CC-FUZZ-0037: fifth real page, first price_integrity_bypass
    # instance (/api/subscription/change-plan) -- a fifth, distinct route,
    # no collision.
    "lab/manifests/price_integrity_netflix_subscription_sample.yaml",
)
_NETFLIX_MULTI_CELL_IDS = {
    "LABGEN-JV-0001", "LABGEN-JV-0003", "LABGEN-JV-0005", "LABGEN-JV-0007",
    "LABGEN-JV-0009",
}
_BUILD_TIMEOUT_S = 240.0
_BOOT_TIMEOUT_S = 30.0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port: int, timeout_s: float = _BOOT_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.25)
    raise AssertionError(f"java -jar never started listening on 127.0.0.1:{port}: {last_exc}")


def test_netflix_multi_cell_boot_confirms_all_positives(tmp_path_factory, tmp_path) -> None:
    """Hand-rolled multi-cell boot (bypassing `SpringBootLiveBootHarness`'s
    single-cell restriction), mirroring `tests/test_labgen_spring_boot_
    trackernest_multitarget.py`'s own established pattern: assembles all
    five of Netflix's own vulnerable twins -- `LABGEN-JV-0001`
    (insecure-deserialization, `/api/playback/resume`), `LABGEN-JV-0003`
    (XXE, `/api/content/import`), `LABGEN-JV-0005`
    (insecure-deserialization, `/api/profiles/switch`, `CC-LAB-0184`),
    `LABGEN-JV-0007` (access_control/IDOR, `/api/account/billing`,
    `CC-LAB-0187`), and `LABGEN-JV-0009` (price_integrity_bypass,
    `/api/subscription/change-plan`, `CC-LAB-0188`) -- into one real
    booted app (five distinct routes, no collision), then runs the real
    generic `run_targets` pipeline against it. Originally closed the
    follow-on `CC-FUZZ-0032` flagged (both of Netflix's positives
    confirming together in one real boot); extended by `CC-LAB-0184` to
    prove the third positive confirms alongside the other two with zero
    new detection code -- the same generalization proof `CC-LAB-0183`
    made for Twitch's `access_control` detection, moving Netflix's own
    scored recall in this boot from 2/2 to 3/3. Extended again by
    `CC-LAB-0187` to add the fourth positive, `NFLX-0004`:
    `AccessControlIdorStrategy` (`CC-FUZZ-0029`, already built for
    Twitch's `go_net_http` cells) needed zero new detection code to
    confirm it too, moving Netflix's own scored recall in this boot from
    3/3 to 4/4. Extended again by `CC-FUZZ-0037` to add the fifth
    positive, `NFLX-0005`: this is `price_integrity_bypass`'s first-ever
    rule/strategy pair in the project, `R-PRICE-INTEGRITY`/
    `PriceIntegrityBypassStrategy`, genuinely new detection logic (not a
    zero-new-code generalization like the two before it), moving
    Netflix's own scored recall in this boot from 4/4 to 5/5.
    """
    root = tmp_path_factory.mktemp("netflix_multitarget")
    shutil.copytree(SKELETON_DIR, root, dirs_exist_ok=True)

    emitter = SpringBootEmitter()
    cells = [c for m in _NETFLIX_MULTI_MANIFESTS for c in load_manifest(m).cells
             if c.cell_id in _NETFLIX_MULTI_CELL_IDS]
    assert {c.cell_id for c in cells} == _NETFLIX_MULTI_CELL_IDS
    for cell in cells:
        for f in emitter.render(cell):
            dest = root / f.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(f.content)

    package_result = subprocess.run(
        ["mvn", "-q", "-B", "package", "-DskipTests"],
        cwd=root, capture_output=True, text=True, timeout=_BUILD_TIMEOUT_S,
    )
    assert package_result.returncode == 0, (
        f"mvn package failed:\nstdout={package_result.stdout}\nstderr={package_result.stderr}"
    )

    port = _free_port()
    jar_path = root / "target" / "trackernest.jar"
    proc = subprocess.Popen(
        ["java", "-jar", str(jar_path), f"--server.port={port}"],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    listener = OobListener()
    listener.start()
    try:
        _wait_until_listening(port)
        base_url = f"http://127.0.0.1:{port}"

        netflix_gt = contract.load("lab/ground-truth-netflix-clone")
        spec = TargetSpec("netflix-clone-multi", base_url, ground_truth=netflix_gt,
                          points_source="ground-truth")
        with Store(tmp_path / "u.db") as store:
            outcomes = run_targets([spec], store, sender_for=lambda s: RequestsProbeSender(timeout=10.0),
                                   oob=listener)
        outcome = outcomes[0]
        assert outcome.scored is True and outcome.report is not None
        # All five of Netflix's own positives confirm in this one real boot
        # (NFLX-0001..NFLX-0005) -- CC-LAB-0184 moved this from 2/2 to 3/3,
        # CC-LAB-0187 moved it from 3/3 to 4/4 (both with zero new detection
        # code), and CC-FUZZ-0037 moves it from 4/4 to 5/5 with this entry's
        # own genuinely new PriceIntegrityBypassStrategy.
        assert outcome.report.tp == 5 and outcome.report.fp == 0
        assert outcome.report.recall == 1.0
    finally:
        listener.stop()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
