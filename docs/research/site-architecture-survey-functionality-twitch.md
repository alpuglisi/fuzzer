# Twitch — functionality research + Go-specific CWE shortlist

Produced for `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §9.5 step 2-3
(category 4 pilot, Media/streaming, Twitch pick). Architecture facts (a
deliberate, publicly chronicled migration from a Rails monolith to a
Go-centric microservices API edge) are carried over unchanged from
`docs/research/site-architecture-survey.md`'s already-confirmed Category 4
entry — not re-researched here.

## 1. Twitch functionality/pages + Go-API-edge implications

**Architecture, confirmed at the primary-source level.** Twitch's own
engineering blog ("Breaking the Monolith at Twitch," a two-part series)
documents the new API edge as written in Go, replacing the original Rails
monolith; the transcode pipeline is C/C++ and Go. *(Confidence: primary
source — Twitch's own engineering blog — confirmed, carried over from the
survey.)*

**EventSub webhooks, confirmed at the primary-source level (new this
document, closing the functionality-research gap for this pick).**
Twitch's own developer documentation (`dev.twitch.tv/docs/eventsub/
handling-webhook-events`) specifies the exact real signature scheme a
subscriber (any third-party service integrating with Twitch — extensions,
bot platforms, channel-point integrations) must implement: Twitch computes
an HMAC-SHA256 over the concatenation of the `Twitch-Eventsub-Message-Id`
header, the `Twitch-Eventsub-Message-Timestamp` header, and the raw
request body (in that exact order), keyed with the subscriber's own
webhook secret, and sends the hex digest as
`Twitch-Eventsub-Message-Signature: sha256=<hex>`. The subscriber must
recompute the same HMAC and compare it against the header — Twitch's own
docs additionally specify a 10-minute replay window checked against
`Twitch-Eventsub-Message-Timestamp`. *(Confidence: primary source —
Twitch's own developer documentation — confirmed.)*

**Page/flow set this implies:**

- **Live channel/stream page** — the core live-viewing surface (player,
  chat, stream metadata) — realistic host for the app's baseline pages,
  though not itself the CWE-bearing page for this pick.
- **Channel-points/extensions/subscription webhook receiver** — the
  concrete, real integration surface EventSub exists for: a channel's own
  backend (or a third-party extension backend) registers a webhook URL
  with Twitch and receives `channel.subscribe`, `channel.follow`, or
  `channel.channel_points_custom_reward_redemption.add` events at that
  URL. This is exactly the kind of small, self-contained receiver
  endpoint a Go API-edge-style service would realistically own.
- **VOD/clips** — on-demand playback of recorded streams; lower priority
  for this app's page set (no primary-sourced Twitch-specific detail
  found for this flow beyond what is generically true of any streaming
  VOD catalog — flagged as unresearched rather than invented).

**Vulnerability-placement implication (synthesis, not a sourced claim):** a
Go-written EventSub-webhook-receiver handler is a small, realistic,
self-contained cell — a single HTTP handler reading the three named
headers plus the raw body and either correctly recomputing/comparing the
HMAC or skipping/weakening that check, exactly the shape this project's
existing `webhook-signature` corpus category already models for
node/php/python.

## 2. Go-specific CWE shortlist

Cross-checked against every `docs/research/corpus-examples/*/*/manifest.yaml`
CWE (~140 IDs across node/php/python) and `lab/safety_matrix.yaml`. No
`go` stack exists anywhere in the corpus today.

| CWE | Why Go-specific | Realistic page/flow | Corpus status |
|---|---|---|---|
| **CWE-347** (Improper Verification of Cryptographic Signature) | Go idiom split: Go's standard library provides `crypto/hmac.Equal` (constant-time) specifically because Go's native `==`/`bytes.Equal` on a byte slice or string is data-dependent-time comparison — a genuine, well-documented Go footgun (Twitch's own docs above name the exact HMAC-SHA256-over-`id`+`timestamp`+`body` scheme; `securego/gosec`, the standard Go security linter, ships a dedicated rule class for weak/insecure comparison). A realistic mistake: comparing the computed digest to the header value with `==`/`strings.Compare` instead of `hmac.Equal`, or comparing the *hex-encoded* digest without normalizing case, or (most severe) skipping verification and trusting `Twitch-Eventsub-Message-Type` alone. | The EventSub webhook-receiver handler identified in §1 — a Go `net/http.HandlerFunc` reading the three signed headers and the raw body, computing the expected HMAC, and comparing it against `Twitch-Eventsub-Message-Signature`. | **Genuinely new stack instance.** `CWE-347` already exists as the `cwe_shared` anchor for all three existing `webhook-signature` stacks (node/php/python, per `docs/research/corpus-examples/webhook-signature/*/manifest.yaml`) but has zero Go instances — same "new-stack instance of an existing, project-preferred class" shape `docs/LAB_MULTI_CATEGORY_SECOND_TARGETS_PLAN.md` §4 already names webhook-signature as one of the classes worth expanding, and category 1's own pilot precedent (`ruby_rails` Phase A: new-stack instance of an existing class; `node_express`: a new CWE on an existing stack) for what a pilot's first cross-stack cell should look like. |
| **CWE-918** (SSRF, tainted URL host) | Go-idiomatic real-world pattern: building an `http.Client`/`http.Get` request from a user- or webhook-payload-supplied URL/host without an allowlist — documented this session via real Go-ecosystem CVEs (Gitea's own SSRF advisory for its webhook/migration allowlist; the general "webhook producers are SSRF by default" pattern, since a webhook *subscriber* fetching a payload-referenced media/thumbnail URL is a realistic Go-net/http shape). | A "fetch clip thumbnail"/"validate the extension's configured callback URL" flow reachable from the same webhook-receiver surface. | **Already an existing corpus category** (`ssrf`, node/php/python present) — a Go instance would be a new-stack instance of an existing category, same shape as the CWE-347 pick, but weaker fit for this pilot's single-cell Phase A (SSRF needs an outbound-fetch sink standing up a callback target, more moving parts for a first live-boot proof than a pure request/response HMAC check). Recorded as the Phase B follow-up for this stack, not built in Phase A. |

**Pick for this pilot's Phase A build:** **CWE-347** (naive/non-constant-
time or skipped HMAC comparison in the EventSub webhook-receiver handler)
— self-contained (one request in, one boolean check, no second network
hop), directly grounded in Twitch's own documented real signature scheme,
and fills a real, project-preferred gap (`webhook-signature` has zero Go
instances). CWE-918 is recorded above as the Phase B follow-up.

## 3. Sourcing and confidence notes

- Primary (Twitch's own engineering blog): "Breaking the Monolith at
  Twitch" (two-part series) — the Go-API-edge architecture claim, carried
  over from the survey, confirmed.
- Primary (Twitch's own developer documentation,
  `dev.twitch.tv/docs/eventsub/handling-webhook-events`): the exact
  HMAC-SHA256 header/body concatenation scheme and the 10-minute replay
  window — confirmed, checked this session.
- Secondary (third-party integration guides — Hookdeck's Twitch-webhooks
  guide, Courier's Node/Express EventSub walkthrough): used only to
  corroborate that the primary doc's scheme is the one third-party
  integrators actually implement, not as the basis for any claim above.
- CVE/CWE claims: MITRE's CWE definitions
  (`cwe.mitre.org/data/definitions/347.html`, `.../918.html`) checked
  directly; Gitea's own GitHub security advisory
  (`GHSA-2r5c-gw76-rh3w`) for the real Go-ecosystem SSRF-via-webhook-
  allowlist precedent; `securego/gosec`'s own documented rule set for the
  general "Go's `==` is not constant-time" footgun. All checked this
  session, not recalled from training data.
- Not confirmed: no primary Twitch source found describing VOD/clips
  page-level functionality in comparable detail to EventSub — flagged as
  unresearched (§1) rather than invented, matching this project's own
  discipline for gaps found (e.g. `-functionality-walmart.md`'s BFF-
  aggregation-granularity gap).
