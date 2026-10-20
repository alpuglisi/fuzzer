# DRAFT — CC-CORE-0067: text bodies through the one storage-redaction boundary, and the sinks that bypass it (BUG-0527; audit defect 26)

- **Status:** draft for the pre-change review gate (`docs/components/README.md`),
  **revision 4**. Nothing in `fuzzlab/` is changed yet. Work item `AU-REDACT`, base
  `8100959`. Revision 4 answers review round 3 (§0.1); revision 3's answers to round 2
  stand (§0.2).
- **Numbers.**

  | Number | What it covers | State |
  |---|---|---|
  | CC-CORE-0067 | the owner (this entry) | used |
  | CC-PROXY-0028 | framed proxy bodies stay fail-closed, judged in every reading; `_prepare` redacts once (§3.7) | used |
  | CC-CRAWL-0051 | the spider's page text and title; the capture's docstring (§3.8a) | used, narrowed (S2) |
  | CC-AUD-0057 | the auditor's findings; the importer's parameter examples (§3.8c/d) | used |
  | BUG-0527, PA-0527, FR-CORE-506, SP-55, the SP-35 extension | the bug, the rule, the requirement, the shared-primitive rows | used |
  | migration v25, CC-UI-0067 | `flow.body_note` and its display | **released** (S1) |

- **Tests:** `tests/test_text_body_redaction.py` (uncommitted) and the real pages it
  reads, `tests/data/body_redaction/` (rendered in-process; the login page's token
  replaced by a canary). Counts: §6.3.
- **Prototypes and probes** (scratchpad, not in the repository):
  `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-redact/`.
  - `proto3.py`: the owner, revision 4 (`proto3_rev3.py` keeps revision 3).
  - `framing4.py`: the proxy's framing, revision 4 (`framing3_rev3.py` keeps revision 3).
  - `proto3_plugin.py`: patches both, and the spider, auditor and importer changes of
    §3.8, into every producer (the non-vacuity run). `REVERT=<name>` re-creates one
    defect at a time (`run_reverts.sh`).
  - `regex_guard.py`: the whole-body regex guard of §3.4, run on both revisions.
  - `cost4.py`, `calib.py`, `realcheck.py`, `framing4_measure.py`, `fullpath_mem.py`,
    `prepare_reuse.py`, `errcheck.py`, `juice_all.py`: the measurements below.
  - The reviewers' own probes were run unedited.

## 0. Review rounds

### 0.1 Round 3 → revision 4

| Key | Change | Where |
|---|---|---|
| **B1** | Every whole-body scan is linear by construction. The `<script>`/`<style>` raw-text index is one opener/closer `finditer` with charged `find`s (an unclosed opener runs to the end). JWTs are found by one greedy `eyJ[A-Za-z0-9_-]*` token scan plus charged segment checks. The skeleton reads at most 1 MiB and is counted. The tag lexer reads attribute values with charged `find`s (an unterminated quote makes the tag open, never an uncharged regex scan to the end of the body). New rule and guard (T12c): no regex with a nested or lazy quantifier, or an unbounded run that a failed attempt re-scans, runs over a whole body; prototyped and proven on revision 3's `_RAWTEXT` and `_JWT`. T12 gets one shape per whole-body scan at 1–8 MiB under a 20 s smoke alarm (PA-0135(1)), each proven on the revision-3 code (PA-0135(3)). | M5, §3.2, §3.4, T12 |
| **B2** | A framed body is judged in every plausible reading: chunked when a TE value holds `chunked` and the body parses so, and identity, each then undoing TE compression codings and the CE value. Byte-exact when every reading that decodes is clean. Framing bytes (suffix, trailers, chunk extensions, gzip FNAME/FCOMMENT/FEXTRA) are judged by the text pass, never the name scan. The seven desync probes and a precompressed `auth.js` stay byte-exact. | M4b, §3.7, T31, T45 |
| **B3** | Unparseable declared JSON takes the text pass in data grammar, as a failed `json?` sniff does (the runner's cut JSON). | §3.1, T46 |
| **B4** | After an auth-scheme word (`Bearer`, `Basic`, `Digest`, `Token`, `Negotiate`, …) bound to a sensitive name, the value takes the next token; a `Bearer <b64token>` is an unbound credential shape anywhere. | §3.2, T47 |
| **B5** | A `#` that starts an ES2022 private field (after `.`, `{`, `;`, `,`, `(` or a line start, in js or inline script) is not URL context: `#token="…"`, `this.#accessToken = "…"` bind by B1. A `#` inside a URL (`/cb#token=`) keeps the URL grammar. | §3.2, T19 |
| **B6** | T28 binds each redactor call to its column by position; a multi-column synthetic offender (`record_form`'s `sig`); a "pinned residual → named strict xfail" category; SQL columns only, stated; PA-0527(4) claims only that. | §4.3, §9 |
| **B7** | The `proxy-codecs` extra drafted for ARCHITECTURE and listed; the recurrence review names BUG-0101/PA-0102(3); AU-SPIDER in T24, T39, §3.8b, R14. | §3.5, §9, §8 |
| **ADOPT** | `brotli>=1.2` and a codec `TypeError` → "coding not supported here"; PGP private key blocks and PuTTY `.ppk`; a bare DSN by the owner's bare-userinfo shape; `_URLV` stops at `?`; tests for the chunk cap and br/zstd bombs; the dechunk copy capped at 8 MiB; no BOM added on re-encoding; a UTF-8 BOM read as latin-1 stripped before sniffing; unquoted values in text fragments stated; a sniffed-JSON leaf's unbalanced value binds to the leaf's end; numbers keep their written text; `default` is a keyword; the auditor's `target_blank` href redacted before its cut, fragments included; `_prepare` redacts once. | §3, §3.7, §3.8c, §8, T33b, T34–T37, T43, T49 |
| **RESIDUALS** | S1's header effects on omitted flows (FTS, Repeater) stated; R13 quantified with D12 as its reason. | §8 |

### 0.2 Round 2 → revision 3 (unchanged)

S1 framed bodies fail-closed (no decoded copy, no `body_note`); S2 spider URLs to
AU-SPIDER; M1 the closing-quote rule; M2 sniffed JSON as ordered pairs; M3 markup rules
wherever markup occurs; M4 unbound credential shapes; M5 fail closed (tag search, wide
encodings, mismatched forms, multipart parts, YAML blocks, `.properties`); M6 one
budget; M7 page text and titles; M8 the auditor's cuts and keys; M9 the test fixes;
M10 the column registry; ADOPT (benign over-redaction stated, real error pages, R1/R3).

---

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7)

### M1. Callers of the body boundary that keep a text-body secret today (`8100959`)

Every producer that redacts through `redact_body` keeps HTML (20/20 canaries), XML,
`.env` and JS secrets: disco `make_record` (SP-35), proxy history (raw message and
stored body, identity and gzip), `HttpClient._record` and `Runner._evidence`. The
spider's `record_request` never records a text body. More kinds kept: NDJSON, SSE,
YAML, SVG script, a CSS comment, a TRACE echo, JSON inside a JS string, a form ending
in `&`, a URL query inside a text line.

### M1a. Truncated JSON (the AU-OUTCOME reviewer's case, and B3)

- `{"access_token": "abc123secret", "user": {"id": 1` under `text/plain`,
  `application/octet-stream` or no type is kept as received
  (`core/redaction.py:357-363`; T20).
- Under a **declared** `application/json`, an unparseable body is kept unless the name
  scan fires: `{"url":"postgres://app:SECRET@db/x","n":[1,2` is stored with its
  password (B3). The contract runner produces exactly this when it cuts at
  `max_body_bytes` (T46).

### M2. Shapes real frameworks emit, and real pages that must not change

- Django's admin login page (rendered in-process): the hidden `csrfmiddlewaretoken`;
  the prototype changes exactly that token's span (T14). Laravel's `_token` from
  source; Rails and ASP.NET from documentation.
- Django 404, 500 and debug 404, Flask 404 and 500 (rendered in-process): all
  byte-identical (C2).

### M3. Spider page text

bs4 `get_text(" ", strip=True)` keeps `<textarea>` content and joins a page into one
line; Chromium 141's `innerText` excludes textarea, hidden input, script and noscript;
`page.title()` is stored as the title.

### M4. Proxy framing today (`8100959`)

A multi-member gzip or a deflate stream with trailing bytes is stored byte-exact with
the later secret recoverable (T21); a bomb is stored as received (T22); trailers, chunk
extensions and gzip header fields are never judged (T32); duplicate `Content-Encoding`
is decoded once; br, zstd and unknown codings are not decoded and are kept or omitted by
`mentions_sensitive_name` over the compressed bytes, which fires on 245–250 of 254 real
compressed bodies.

### M4b. Desync probes (B2; reviewer B's `desync3.py`)

| Probe | Today | Revision 3 | Revision 4 |
|---|---|---|---|
| CL.TE, clean suffix | byte-exact | byte-exact | byte-exact |
| TE.CL, request smuggled in a chunk | byte-exact | byte-exact | byte-exact |
| TE.TE (`chunked` + `Transfer-encoding: cow`) | byte-exact | **marker** | byte-exact |
| `xchunked` | byte-exact | **marker** | byte-exact |
| `chunked, identity` | byte-exact | **marker** | byte-exact |
| CL.TE suffix `GET /api/keys` | byte-exact | **marker** (name scan) | byte-exact |
| CL.TE suffix `Host: auth.lab` | byte-exact | **marker** (name scan) | byte-exact |
| a precompressed `auth.js` (gzip FNAME) | byte-exact | **marker** (name scan) | byte-exact |

Fail-closed cases measured on revision 4 (`framing4_measure.py`): TE.TE with
`password=` in the chunk, a `Transfer-Encoding: gzip, chunked` body with `password=`
inside the transfer gzip, a second member, deflate trailing bytes, a trailer
`X-Token:`, a chunk extension `;token=`, a gzip FNAME `password=…`, a zstd skippable
frame, duplicate CE and an unknown coding are all typed markers.

### M5. Cost (B1)

Measured on an idle host (no other test run; CPU 95-100 % idle), one run each, times and
traced peaks in separate runs (`cost4.py`). Every crafted shape from reviewer A's
`cost.py`/`cost_r3.py` (A, A3), reviewer B's `cost3.py` (B3) and this lane's (L), each
at 1 MiB and at 8 MiB:

| Shape | 1 MiB ms | 8 MiB ms | 8 MiB ops | 8 MiB peak | Result at 8 MiB |
|---|---|---|---|---|---|
| A `lex_tag` `=` ×60k per tag | 14 | 121 | 72,897 | 16.0 MiB | redacted |
| A `lex_tag` `=` ×4k per tag | 15 | 125 | 93,308 | 17.1 MiB | redacted |
| A `_in_bind_attr` walk, 120 `/` | 58 | 299 | 112,769 | 26.5 MiB | omitted: hits |
| A `type=hidden`, no `<` | 28 | 131 | 500,282 | 24.0 MiB | omitted: budget |
| A `type=hidden`, tag 60k back | 31 | 144 | 500,035 | 24.2 MiB | omitted: budget |
| A `token=1&` on one line | 102 | 226 | 112,769 | 21.4 MiB | omitted: hits |
| A `token:[1,…]` in JS | 35 | 163 | 76,665 | 16.6 MiB | redacted |
| A `name="csrf"` after 8 `<` | 421 | 444 | 500,001 | 27.1 MiB | omitted: budget |
| A benign HTML | 18 | 142 | 32,768 | 16.0 MiB | unchanged |
| **A3 `eyJ` run, no dot** (392 s at 1 MiB on rev 3) | 26 | 199 | 65,536 | 16.0 MiB | unchanged |
| **A3 base64-JSON state attribute** (~9 s/MiB on rev 3) | 23 | 226 | 94,505 | 16.0 MiB | unchanged |
| **A3 unclosed `<script>` + CSRF input** | 71 | 458 | 500,001 | 24.1 MiB | omitted: budget |
| **A3 unprovable + identifier-like tags (skeleton)** (1.1 s on rev 3) | 149 | 261 | 98,314 | 24.0 MiB | omitted: tag not delimited |
| A3 PEM `BEGIN` ×N, `END` at the end | 43 | 79 | 524,276 | 16.0 MiB | omitted: budget |
| **B3 unclosed `<script>x` + binding** (64 s at 352 KiB on rev 3) | 81 | 405 | 500,001 | 24.1 MiB | omitted: budget |
| B3 `eyJ` run (`text/plain`) | 22 | 200 | 65,536 | 16.0 MiB | unchanged |
| **B3 unclosed `<style` + binding** | 55 | 256 | 500,001 | 24.1 MiB | omitted: budget |
| L `<input name=csrf value=1>` | 275 | 337 | 332,769 | 30.7 MiB | omitted: hits |
| L hidden inputs | 258 | 405 | 332,769 | 32.8 MiB | omitted: hits |
| L sniffed-JSON leaves | 351 | **774** | 151,835 | 100.0 MiB | omitted: hits |
| L unterminated attribute quotes + hits | 318 | 297 | 352,769 | 28.2 MiB | omitted: hits |
| L `a:b@c(` (one DSN look back per `@`) | 134 | 236 | 72,725 | 16.0 MiB | omitted: `@` cap |
| L `Bearer` tokens | 16 | 28 | 52,769 | 18.3 MiB | omitted: shape cap |
| L `//` runs, no `@` | 39 | 328 | 32,768 | 16.0 MiB | unchanged |

**The bound: 1 s per redaction call on a body of at most 8 MiB on this host. Met: the
worst is 774 ms (8 MiB of sniffed-JSON leaves); every other shape is at most 458 ms.**
Memory: at most 33 MiB traced on every text shape; 100 MiB on 8 MiB of sniffed JSON,
where today's redactor peaks at 110 MiB (declared) and 176 MiB (sniffed, parsed twice)
on the same body.

**Found and fixed during this measurement** (the first run's benign 8 MiB page took
615 ms, against 142 ms on revision 3): the bare-DSN regex's lookbehind start was tried
at every position (313 ms on 8 MiB) and `\bBearer` defeated the literal-prefix scan
(124 ms). Both are now literal-led: a `Bearer` scan with its left boundary checked in
code, and one bounded look back (at most 322 characters, charged, skipped when no `:`
precedes) per `@`, the `@` count capped at the hit cap. Credential-shape replacements
are capped at 20,000 too (8 MiB of `Bearer` tokens held 73 MiB of spans).

**The 14 real bodies:** 0.9 ms (4 KiB) to 298 ms (`trace_viewer`, 2.5 MiB) and 267 ms
(`pyright-internal.js`, 3 MiB); at most 24,476 ops and 4,995 hits; none omitted.

**The framed bodies** (`framing4_measure.py`, revision 4): 3,276–120,000 empty gzip
members stop at the member cap in about 3 ms (1,025 members, 256 KiB fed); a member
decoding to exactly the cap followed by a 1 GiB bomb member stops at cap + 1 bytes
produced; 100,000 and 1,000,000 one-byte chunks stop at the chunk cap in under 50 ms;
1 GiB gzip, deflate, br and zstd bombs stop at the decoded cap in 5–36 ms with traced
peaks of 12, 12, 16 and 8 MiB.

**The full path** (`fullpath_mem.py`, revision 3; revision 4 changes no allocation):
at most 56 MiB traced per 8 MiB body against 48 MiB today. `HistoryWriter` redacting
once (`prepare_reuse.py`, B7/ADOPT): 577 ms on the crafted 8 MiB body (two calls:
1,106 ms), the stored raw response byte-identical between the two.

### M6. Consumers and over-redaction (revision 4)

- **Reviewer A's probes:** `probe1_r3.py` 45 ok; the 12 leaks left are stated
  residuals (R1 call arguments, CSV, markdown, JSON name/value pairs, concatenation;
  R2 unicode escape, percent-encoded name, `srcdoc`, `data:` URI; R3 `state`; R7 an
  unquoted script identifier). `jsmine_r3.py`: 311 scripts, 0 omitted, calls 4 → 4.
- **Reviewer B's probes:** `shapes3.py` leaks only R1 (JSON name/value pair, CSV) and
  R2 (a no-break space inside a name); every PGP, PuTTY, DSN, `Authorization`, truncated
  declared JSON and private-field shape is redacted. `jsonvalid3.py`: no body broken.
  `desync3.py`: M4b.
- **Juice Shop's 18 bundles:** 0 omitted; mined calls 5 → 5; 6 bundles carry a
  placeholder.
- **The 14 real bodies:** none omitted; 13 carry a replacement (M8). Revision 4 adds two
  benign replacements on Playwright's report (`o.credentials="include"`, B5's B1
  fall-through on `?o.credentials=`); a bare-DSN false match on CSS (`margin-right:0}@media`)
  was found and closed (the user part is a user name, the password has no `{};`).
- **Real error pages and the real login page:** byte-identical; only the token changes.

### M7. The auditor's findings

Seven rules leak today. `target_identifier` is a path plus a name for 25 of the 26
rules; **`Unsafe target blank` stores the link's href cut at 120 characters**
(`fetcher.py:816`), so a query or fragment value can reach it (T49).

### M8. What S1 does to compressed text in proxy history

13 of the 14 real bodies and 6 of the 18 Juice bundles carry at least one replacement,
so, served compressed, each is stored as a marker (R13). Accepted by the coordinator:
never persisting a credential (D12) outranks readable compressed history.

---

## 2. The defect and its root cause (full RCA in BUG-0527 at merge)

**The pass-through.** `core.redaction.redact_body` returns every body whose kind it
cannot parse as received: the final `return body`, a `json?` sniff that fails to parse,
and an unparseable declared JSON body with no sensitive name (M1, M1a).

**The same class, around the boundary.**
- The proxy's framed judgement decodes one member, reads one `Content-Encoding`, and
  never judges the bytes it keeps byte-exact around the payload (M4).
- The spider's page text and title, the auditor's findings and the importer's
  parameter examples store target content without reaching the boundary (§4.2).
- The sniffed-JSON redactor round-trips through a dict, merging repeated keys and
  rewriting `1e400` as `Infinity`.

**Root cause.**
- The boundary's dispatch has a pass-through default, and the framed judgement judges
  only the bytes it decodes.
- PA-0101(1) ("fail closed") was applied to unparseable bodies of *known* kinds only.
- PA-0085(2), PA-0091(1) and PA-0101(2) planted secrets in the kinds the redactor
  parses, not in the kinds producers persist.
- PA-0100 and PA-0514(1) told new producers to "use the strongest existing redactor".
- PA-0100's guard enumerates producers by SQL table only.

**Recurrence review.**
- Prior bugs BUG-0084, 0090, 0099, 0100, 0101, 0455, 0514, 0521; prior PAs PA-0085,
  0091, 0100, 0101, **0102(3)**, 0455, 0514, 0521.
- **Failure mode: too narrow, and not enforced by an enumeration** for PA-0085, 0091,
  0100, 0101 and 0514: each was scoped to its own bug's kinds or producers.
- **BUG-0101 / PA-0102(3), the event-loop class:** "blocking work never runs on an
  event loop" was scoped to I/O. The redactor's CPU work runs synchronously on disco's
  capture loop and the proxy's history flush (R9); revision 2's cost claim was off by
  about 100× (the coordinator's F-entry) because no complexity claim on that path was
  tested on counters (PA-0135) and no guard covered whole-body regexes. Revision 4
  bounds the work (B1, T12, T12c); moving it off the loops is audit defects 22 and 25.

---

## 3. Design

### 3.1 The owner's dispatch: no pass-through default (`core/redaction.py`)

1. **Over 8 MiB:** `OMIT_TOO_LARGE`, as today.
2. **Wide encodings.** A UTF-16/32 BOM, a declared `charset=utf-16`/`utf-32`, or a
   NUL-heavy sniff: decoded with the exact byte order (the BOM, the declared order, or
   the NUL parity), redacted by the rules below and re-encoded in the same order, **the
   BOM written back only if the body had one** (ADOPT). Undecodable: omitted.
3. **Declared binary** (closed list, R4): stored as received. A NUL in a declared text
   body is omitted.
4. **Declared JSON:** today's redactor; string leaves holding markup, a JWT, a PEM
   block or `@` take the text pass. **Unparseable: the text pass in data grammar (B3)**,
   as a failed `json?` sniff, so a cut body keeps its shape and loses its credentials.
5. **Declared form:** today's redactor when the body matches the form shape; otherwise
   the text pass in data grammar.
6. **Declared multipart:** each part by its own `Content-Type` through this dispatch;
   a body that does not split on its boundary takes the text pass.
7. **Any other body:**
   1. **Sniffed JSON that parses:** ordered pairs; numbers and constants keep their
      written text (`1e400`, ADOPT); a sensitive key's whole value replaced; every
      string leaf through the text pass in **leaf mode**: an unterminated string or
      container after a sensitive word binds to the leaf's end instead of omitting the
      body (ADOPT). Valid JSON, nothing dropped, merged or reordered.
   2. **A sniffed form:** `redact_query`, then the text pass in data grammar.
   3. **Otherwise:** the text pass in the grammar of §3.2.
8. **`redactable_type(content_type)`:** false only for the declared binary list.

### 3.2 The text pass

**The text.** Read as latin-1 (one byte per character, lossless; the rules are ASCII):
a non-ASCII 8 MiB page costs 56 MiB through `make_record`, not 108.5 MiB. The JSON paths
re-decode UTF-8.

**The scan.** One C-level scan of the ASCII-lower-cased body with a trie of the
sensitive words. Each hit is expanded to its full name and checked with
`is_sensitive_name` (SP-17), memoised.

**Grammar:**

| Grammar | Selected by | Unquoted value |
|---|---|---|
| html | a type containing `html` or `xhtml`, or the WHATWG signatures after any BOM (**a UTF-8 BOM read as latin-1, `ï»¿`, is stripped first**, ADOPT) | in markup: a token; in `<script>`/`<style>` raw text: numeric only |
| xml | `*/xml`, `*+xml`, `<?xml` | a token |
| js | the JavaScript types | numeric only |
| data | sniffed JSON leaves, sniffed and mismatched forms, `text/css` | a token |
| text | any other text, `message/http`, unknown types | to the end of the line, not past an `&` that starts another `name=`; a YAML block or `.properties` continuation extends it |
| words | spider page text and titles | one token |

**Markup anywhere.** The html bindings B2 and B3 run in any grammar on a body holding
`<input`, `<meta`, `<textarea` or `<param`, reading `\"`-escaped quotes as quotes.
**Unquoted attribute values in such a fragment are not bound** (they pair only in html
markup proper; stated, ADOPT).

**The raw-text index (B1).** `<script>`/`<style>` spans come from one `finditer` of
`<(/?)(script|style)\b` with a charged `find` for each opener's `>`; an opener whose `>`
or closer never comes runs to the end of the body. Revision 3's lazy
`<…>(.*?)</…>` regex took 64 s on 352 KiB of unclosed openers.

**The tag lexer (B1).** An attribute name is matched at its position; its value is read
with one charged `find` for the closing quote (`"`, `'`, `\"`, `\'`) or a bounded
unquoted-token match. **An unterminated quote makes the tag open** (the binding then
fails closed, U2); no regex scans to the end of the body per attribute.

**Bindings** (each charged):
- **B1 `name <op> value`**, as in revision 3 (a line break after the operator binds
  only a quoted value or container, or a more-indented YAML block in text grammar).
- **B2 (html), B3 (html), B4 (xml)**, as in revision 3.
- **Query context:** a name after `?`, `&`, `&amp;`, `#`, `%3F`, `%26`, `%23`, or a `;`
  after a URL path character, takes the URL value grammar, which now stops at `?` too
  (`;jsessionid=X?item=1` keeps `?item=1`, ADOPT).
  - **B5:** in js and inline script, a `#` after `.`, `{`, `}`, `;`, `,`, `(`,
    whitespace or a line start starts an ES2022 private field, not a fragment: B1 binds
    `#token="…"`, `#apiKey='…'`, `this.#accessToken = "…"`. A `#` inside a URL
    (`"/cb#token=" + t`) keeps the URL grammar and its M1 empty value.
- **B4 (auth schemes):** when a bound unquoted value is an auth-scheme word (`Bearer`,
  `Basic`, `Digest`, `Token`, `Negotiate`, `NTLM`, `ApiKey`, `Bot`, `HOBA`, `Mutual`,
  `AWS4-HMAC-SHA256`), the value takes the next token of the grammar (a markup token
  in html, so `</pre>` is kept; a word in page text). Text grammar already took the
  line.

**Unbound shapes, anywhere** (each a linear scan, B1):
- **JWT/JWS/JWE:** one `finditer` of `eyJ[A-Za-z0-9_-]*` (greedy; it never fails once
  started, so no position is scanned twice); a run of at least 8 characters followed by
  two to four more `.`-joined base64url segments (the second at least 5 long) is
  replaced. Revision 3's `_JWT` regex re-scanned the run from every `eyJ` (392 s on
  1 MiB; about 9 s/MiB on a realistic base64 JSON state attribute).
- **Private keys:** `-----BEGIN … PRIVATE KEY-----`, **`… PRIVATE KEY BLOCK-----` (PGP)**
  and `SECRET` blocks to their `END` line; a **PuTTY** `.ppk`'s `Private-Lines: N` lines
  (ADOPT).
- **`Bearer <b64token>`** (case-sensitive `Bearer`, at least 8 token characters; a
  literal-led scan, the left word boundary checked in code): covers a bare `Bearer`
  credential in an attribute, a debug cell or page text (B4).
- **URL userinfo** (`//user:pass@` → `//***@`) and a **bare DSN** (`root:pw@tcp(db)/app`
  → `***@tcp(db)/app`) by the owner's two userinfo shapes (PA-0003): the in-text forms
  of `_URL_USERINFO` and `_BARE_USERINFO` stop where RFC 3986 userinfo cannot continue,
  the bare form's user part is a user name and its password has no `{};` (CSS
  `margin-right:0}@media` is not a DSN), and address schemes are excluded
  (`mailto:alice@x`). The bare form is found from each `@` (a literal-led scan) by one
  bounded look back of at most 322 characters, charged and skipped when no `:` precedes
  it; the number of `@` examined is capped at the hit cap.
- **Credential-shape replacements are capped at 20,000** (U3's cap), so a body of
  nothing but tokens cannot hold an unbounded span list.

**Value grammar.** As in revision 3 (quoted, the M1 closing quote, prose in code,
containers, idempotent, in place, byte-identical when nothing changes), with `default`
added to the declaration keywords (`export default token = "…"` is B1, not prose, ADOPT).

### 3.3 Fail closed

The marker and U1–U7 are as in revision 3, with these changes:
- **U1** does not apply inside a sniffed-JSON leaf (leaf mode, §3.1).
- **U2** includes an attribute whose quote never closes (B1).

### 3.4 One budget, and linear scans by construction (M6, B1)

- **One counter, `ops`, capped at 500,000;** hits capped at 20,000. Every Python step
  charges 1; every C-level span (`find`/`rfind`, a regex over a value, the tag search,
  the raw-text index, the token scans) charges `1 + chars // 256`. A tag or a quoted
  value may run to the end of the body, charged; a 7 MiB `__VIEWSTATE` is redacted in
  place.
- **The skeleton** (an omitted html/xml body's element names) reads at most
  `TEXT_SKELETON_SCAN = 1 MiB` and emits at most 16 KiB; `stats["skeleton_scanned"]`
  counts it. Revision 3 scanned the whole body uncharged (1.1 s on 8 MiB).
- **Rule (PA-0527(5), B1): every scan over a whole body is linear by construction.** A
  regex run over a whole body (`finditer`, `search`, `findall` or `sub` without a
  bounding window) has no nested repeat, no lazy repeat, and no unbounded repeat
  followed by a required element when the pattern's first character can occur inside
  that repeat (a failed attempt would re-scan the run from every start). Patterns run
  only inside a window are listed as windowed and called with `pos, endpos`.
- **T12c (guard, phase 2):** every module-level pattern of the text pass is registered
  `WHOLE_BODY` or `WINDOWED`; an AST check finds every `finditer`/`search`/`findall`/
  `sub` call and requires a `WINDOWED` pattern to pass `pos` and `endpos`; each
  `WHOLE_BODY` pattern is parsed (`re._parser`) and checked against the rule. **Proven
  now, in `regex_guard.py`:** it flags revision 3's `_RAWTEXT` (lazy repeat; re-scanned
  run) and `_JWT` (nested repeat; re-scanned run) and the synthetic offenders
  `(a+)+b`, `<s>(.*?)</s>`, `eyJ[A-Za-z0-9_-]{5,}\.`, `x[^>]*>`, `(?:ab|a)*c`; it passes
  every revision-4 whole-body pattern (`_CAND`, `_TYPE`, `_MARKUP`, `_RAW_TAG`,
  `_JWT_HEAD`, `_PEM`, `_USERINFO_FAST`, `_BEARER`, `_PPK`, `_AT`, the skeleton's). The
  rule says nothing about a linear but slow start (a lookbehind tried at every
  position); §M5's base-cost check on 8 MiB of benign HTML catches that, and caught
  two (§M5).
- **T12 (now):** one shape per whole-body scan at 1–8 MiB (the raw-text index twice,
  the JWT scan twice, the skeleton, the PEM scan, the `@` look backs, the `Bearer`
  scan), under a 20 s smoke alarm (`SIGALRM`, which interrupts a running regex scan;
  PA-0135(1)) that raises a `BaseException` so the redactor's totality guard cannot
  swallow it, within the operations cap plus one whole-body span (the budget is checked
  after each charge), the skeleton within its scan bound.
- **T12b (phase 2):** every loop in the text pass charges the budget (AST).
- **The bound:** 1 s per redaction call on a body up to 8 MiB on this host (§M5).

### 3.5 API, dependencies and LOC

- **`core/redaction.py`:** the dispatch, the text pass, the linear scans, leaf mode,
  `redactable_type`, `redact_page_text`, `redact_record_text`, **`redact_record_url`**
  (`redact_for_record("url", redact_url_identifiers(u))`: query values, identifier-like
  query values, query-shaped fragments, userinfo, matrix parameters; the path kept), the
  `WHOLE_BODY`/`WINDOWED` pattern registry, the constants and counters. `redact_body`
  gains keyword-only `stats=`. About +500 / −20.
- **`proxy/redact.py`:** `judge_framed` (§3.7) replaces `_framed_payload`,
  `_decompress` and `_framed_body_unsafe`; `FramingStats`. About +200 / −50.
- **`proxy/history.py`:** `_prepare` redacts the raw message once and takes the stored
  body from it when the stored body is that message's body (ADOPT; measured 1,106 →
  577 ms on the crafted 8 MiB body, byte-identical output). About +10.
- **`pyproject.toml`:** a new extra, `proxy-codecs = ["brotli>=1.2,<2",
  "zstandard>=0.22,<1"]` (PA-0005; `brotli` 1.2 is the API used,
  `Decompressor.process(…, output_buffer_limit=)`). Imported lazily; absent, or a
  `TypeError` from an older API, gives "coding not supported here".
- **ARCHITECTURE text (CLAUDE.md step 6, B7),** for the dependency list:
  > `proxy-codecs` (optional): `brotli>=1.2` and `zstandard>=0.22`, imported lazily by
  > `fuzzlab/proxy/redact.py` to judge br- and zstd-coded bodies before storing them
  > (CC-PROXY-0028). Without it such a body is stored as an omission marker; nothing
  > else needs it.
- **`tools/spider.py`** about +8; **`tools/fetcher.py`** about +35 (the cut sites, the
  `target_blank` href); **`tools/store_adapter.py`** about +4; **`disco/capture.py`**
  docstring.
- **A committed probe,** `scripts/measure_body_redaction.py` (about 180): the M5 tables.

### 3.6 Not changed

Declared form, JSON and multipart output for bodies without markup leaves;
`is_sensitive_name`, `looks_like_identifier`; `redact_url`; header redaction; trace
scrubbing; `redact_captured_body`'s contract; the capture's truncation order;
`form_record`'s entry rule.

### 3.6a Repeated names (the AU-REQID hand-off)

In this change's path: the text pass and the sniffed JSON pairs path (T18). Hand-off
R10: `redact_captured_body`'s form dict and the declared-JSON redactor's dict.

### 3.7 Framed proxy bodies: fail-closed, judged in every reading (CC-PROXY-0028; S1, B2)

`judge_framed(msg, body, *, stats=None) -> bytes` returns `body` (byte-exact) or a typed
marker. **No decoded copy is ever stored.**

**Readings.**
- **Transfer readings:** *chunked*, when any `Transfer-Encoding` value (read with
  `get_all`) holds `chunked` and the body parses as chunked; and *identity*, always. A
  reading that does not parse or decode is not plausible and is dropped.
- **Each reading** then undoes the TE compression codings (`gzip`, `x-gzip`, `deflate`,
  `br`, `zstd` listed in TE) and the `Content-Encoding` value's codings, in reverse.
  Duplicate `Content-Encoding` headers or an unknown CE coding: a typed omission.
- **Stored byte-exact** when at least one reading decodes and every decoded reading is
  clean: `redact_body(payload)` unchanged, and every framing byte clean.
- **Framing bytes** (chunk extensions, trailers and anything after the last chunk, gzip
  FEXTRA/FNAME/FCOMMENT) are judged by the text pass in text grammar, **never the name
  scan**: `GET /api/keys`, `Host: auth.lab` and an FNAME `auth.js` are clean;
  `X-Token: …`, `;token=…` and an FNAME `password=…` are not.
- **Fail closed whatever the reading:** a cap (members, chunks, the decoded cap, the
  framing budget), a secret, a zstd skippable frame. No reading decodes: "undecodable"
  (or the decoder's reason). Under a declared binary type (R4), an omission that is not
  a secret keeps the body as received, as today.

**Decoding bounds** (as revision 3): members fed by offset in pieces of 256 B doubling
to 64 KiB (never re-copying the rest); at most 1,024 members and 65,536 chunks; the
decoded cap 8 MiB, summed, with `max_length = max(1, cap - total + 1)`; **the dechunk
copy is capped at the decoded cap** (ADOPT; revision 3 passed `1 << 62`); br through
`output_buffer_limit`, zstd through `read(cap + 1)` with an 8 MiB window; a framing
budget of 200,000 steps. Counters: `ops`, `members`, `chunks`, `fed`, `produced`,
`max_out_call`, `readings`.

**The marker** keeps revision 3's form and coding label (`[a-z0-9-]{1,32}` tokens, else
`other`); on a marker, TE and CE are dropped and `Content-Length` is set.

**`_prepare` redacts once** (ADOPT): when the stored body is the raw message's body,
the raw message is redacted and the stored body taken from it.

**Expected values that change:** the three proxy tests listed in revision 3 (typed
markers instead of `OMIT_UNSAFE`).

### 3.8 The sibling sinks (PA-0002)

**(a) Spider page text and title** (CC-CRAWL-0051): `_parse_html` takes text from the
boundary-redacted HTML; `mark_visited` passes title and text through
`redact_page_text` (words grammar, B4 included).

**(b) Spider page URLs and the form signature: AU-SPIDER (S2).** Pinned by the strict
xfails T39 and T24.

**(c) The auditor's findings** (CC-AUD-0057, `tools/fetcher.py`).
- Every cut that quotes target content redacts first: `_quote(text, n)` for field and
  form HTML, `_quote_value(name, value, n)` for example values, and, for **`Unsafe
  target blank`, `redact_record_url(href)[:120]` (ADOPT)**: query values,
  identifier-like values and query-shaped fragments such as an implicit-flow
  `#access_token=` (T49).
- `log_finding`: `html_context` through `redact_record_text`; `page_url` through
  `redact_record_url` (the path kept: `to_path(page_url)` is the importer's join);
  `target_identifier` through `redact_record_url` when it carries a query or fragment
  value. Free-text identifier blanking runs on `html_context` only.

**(d) The importer's parameter examples:** a sensitively named parameter's example is
stored as `""`.

### 3.9 Not in this change

Decoded, redacted copies of framed bodies (the later proxy framing item); spider page
URLs and the form signature (AU-SPIDER); known-secret literal scrubbing (R1's
follow-up); JSON inside a declared-JSON string without markup (R6).

---

## 4. Sinks swept

### 4.1 Every caller of the owner

| Caller | Writes | Leaks today | Disposition |
|---|---|---|---|
| `core/http.py::HttpClient._record` | `flow`, `body` | **yes** | the owner |
| `disco/capture.py::make_record` (SP-35) | `capture.jsonl` | **yes** | the owner |
| `disco/runner.py::Runner._evidence` | evidence files | **yes** (cut JSON, B3) | the owner; AU-OUTCOME's file not edited |
| `proxy/redact.py` → `HistoryWriter._prepare` | `flow`, `body`, `flow_fts` | **yes** | the owner + CC-PROXY-0028 |
| `redact_captured_body` → `spider.record_request` | `discovered_requests` | no | unchanged (C1) |
| `disco/synth.py::parse_body` | — | — | markers keep the prefix |

### 4.2 Every stored text field that takes page or response content (yes/no)

As in revision 3, with two changes: #3 and #5 (spider URLs, form signature) are
**AU-SPIDER** (T39, T24), and #10b, `findings.target_identifier`, is **yes for `Unsafe
target blank`** (the href; T49).

| # | Sink | Writer | Content without the redactor? | Disposition |
|---|---|---|---|---|
| 1 | `discovered_pages.content` | `_parse_html` → `mark_visited` | **yes** | §3.8a, T23, T38, T47 |
| 2 | `discovered_pages.title` | same; the browser's `page.title()` | **yes** | §3.8a, T38 |
| 3 | `discovered_pages.url` / `found_from` | `mark_visited` | **yes** | **AU-SPIDER, T39** |
| 4 | `discovered_forms` URLs, `entries`, `controls` | `record_form` | no | R12 |
| 5 | `discovered_forms.sig` | `record_form` | **yes** | **AU-SPIDER, T24** |
| 6–9 | `discovered_requests`, `revealed_forms`, `script_segments`, `selector_verdicts`, `crawl_stats` | spider | no | — |
| 10 | `findings.page_url` / `html_context` | `log_finding` | **yes** | §3.8c, T25, T41 |
| 10b | `findings.target_identifier` | `log_finding` | **yes** for `Unsafe target blank`; no for the other 25 rules | §3.8c, T49, T40 |
| 11 | `parameter.example` | `_import_page_url` / `_import_route_query` | **yes** | §3.8d, T26 |
| 12–13 | `page.url`, `endpoint.url`, `form.entries` | `store_adapter` | no | — |
| 14 | `candidate.evidence` (`base_value`, `sink_context`) | `audit/engine.py`, `import_audit` | **yes, inherited** | fixed by #10, #11 |
| 15–21 | `evaluation.evidence`, `actions.jsonl`, `explore.json`, inventory/contract, EDE report, `trace_event`, `dg_*` | various | no | — |
| 16 | `finding.evidence` | `oracle/oracle.py` | no for the sites read | R12 |
| 22 | `repeater_tab.raw_request`, `session_state.login_url`, `run_plugin.config` | proxy, store | operator input | NFR-CORE-secrets "Not yet enforced" |
| 23–25 | blind-SQLi CSV, ML tables, `saved_views`, notes | various | no | — |
| 26 | log output | `core/obs`, `logging` | not swept | R12 |

### 4.3 The column registry (M10, B6; PA-0527(4))

**T28 `test_every_stored_column_is_registered_and_content_columns_are_redacted`**
(phase 2; about 100 literal write sites over 45 tables measured):
- **Sites.** An AST walk of every string constant and f-string in `fuzzlab/` (outside
  `labgen/`) that writes SQL (`INSERT [OR …] INTO t (cols) VALUES (…)`,
  `UPDATE t SET c = ?, …`), extracting each (table, column) **with its position** in
  the column list and the `VALUES`/`SET` placeholder list. A dynamic site (a table or
  column list built at run time) is registered by (module, function) with its columns.
- **The registry,** `tests/data/stored_columns.json`, puts each (table, column) in one
  of three categories:
  - `{"content": "<redactor>"}`: the writer redacts this column with that redactor;
  - `{"not_content": "<reason>"}`;
  - **`{"pinned": "<test id>"}`**: a known residual pinned by a named strict-xfail test
    (B6): `discovered_pages.url`, `discovered_pages.found_from` → T39,
    `discovered_forms.sig` → T24. The test checks that the named test exists and is
    `xfail(strict=True)`.
- **Binding by position (B6).** For a content column, the test finds the argument
  tuple of the `execute` call at that site and the expression at the column's position;
  that expression must be a call to the named redactor, or a name assigned from one in
  the same function. A redactor call on another column of the same statement does not
  count.
- **Proven on synthetic offenders:** an unregistered `INSERT INTO pages (content)`;
  a column registered as content whose writer never calls its redactor; and a
  **multi-column offender modelled on `record_form`**: `INSERT INTO discovered_forms
  (page_url, action_url, sig) VALUES (?,?,?)` with `redact_url(page)`,
  `redact_url(action)` and a `sig` built from the raw URL. It fails on `sig` although
  the statement calls `redact_url` twice.
- **Scope, stated plainly:** SQL columns only. File writers (the runner's evidence
  files, `capture.jsonl`, `script_segments.json`, the blind-SQLi CSV) are not in T28;
  they are covered by their producers' tests (T1, T4, T5, T46; `script_segments` by its
  own identifier rule) and listed in §4.2.
- **On `8100959` it fails for its stated reason:** `log_finding`, `mark_visited` and
  `_import_page_url` write content columns without their redactors.

---

## 5. Consumers of persisted content, and the effect

Unchanged from revision 3 except:
- **`import_audit`:** `page_url` keeps its path (`redact_record_url`), so
  `to_path(page_url)` and the endpoint join hold; a `target_blank` finding's
  `target_identifier` is the redacted href (its dedup key changes only where a query or
  fragment value was redacted).
- **Repeater and FTS on omitted framed flows:** see R15.

| Consumer | Effect |
|---|---|
| disco link harvest, spider link extraction | none |
| `synth.parse_body` (`synth.py:296-311`; sniffed `{`/`[` under `none`/`text`/`other` at `:302-306`) | a sniffed JSON body stays valid JSON with every key and its numbers as written |
| `synth` data values (`synth.py:429`) | a redacted leaf drops out; identifier-like leaves are kept |
| `synth._mine_js` | calls unchanged (311 scripts: 4 → 4; Juice: 5 → 5) |
| `ede.replayable` (`ede.py:89-92`, declared JSON only); replay and observation (`:236`, `:292`) | a redacted leaf replays as `__REDACTED__`; a cut declared-JSON answer is now redacted text (B3), not parsed either way |
| probes from `parameter.example` (`harness/auto.py:433-446`) | a sensitive-named parameter: `value_shapes` falls back to `shapes_by_name`, `redirect_seed` is None |
| proxy UI and Repeater | text bodies show `__REDACTED__`; framed bodies that would change are markers (M8); clean desync probes are byte-exact (B2) |
| `ml/flow_anomaly` | redacted and omitted flows change length |

---

## 6. Tests (PA-0034(2): each with the revert it must fail against)

### 6.1 Written now (`tests/test_text_body_redaction.py`)

"Old" is `8100959`. Proofs marked *proved* were run against the prototype with the
named `REVERT` (§6.3).

| Test | Old: fails because | Must fail against |
|---|---|---|
| T1–T4 producers [6, 12, 6, 6] | the pass-through | the `return body` default; T2 gzip a decoded copy |
| T5, T6, T7, T20 [1, 1, 1, 3] | as revision 3 | as revision 3 |
| T9 types [72] + declared binary [11] | 66 the pass-through; 6 JSON/multipart and the 11 binary are controls | any pass-through branch |
| T12 crafted bodies [11] | the canary kept | a budget that counts but does not stop (*proved*, `nocap`: 3 fail) |
| **T12 whole-body scans [8]** (B1) | the canary kept | revision 3's `_RAWTEXT` (*proved*, `rawtext_regex`), `_JWT` (*proved*, `jwt_regex`), an unbounded skeleton (*proved*, `skeleton_unbounded`) |
| T14 real login page | the token kept | a splice or false binding |
| T15 framing proof | the gzip HTML judged clean | a decoded copy; the raw coding in the marker |
| T18 repeated names [6] | 3 fail (merged JSON keys; canaries); 3 form controls | end-of-line grammar; a dict round trip |
| T19 scripts (with B5 private fields and `export default`) | the bound literals kept | "any unquoted token" (*proved*); `#` read as a fragment (*proved*, `privatefield`) |
| T21, T22, T29, T30 | as revision 3 | as revision 3 (`maxlen0`, `recopy` *proved*) |
| T31 [2] (B2) | duplicate CE decoded once; transfer gzip never undone (the canary stored) | reading the first header only; a chunked reading that stops before the transfer gzip |
| T32 framing bytes [3] | trailer, extension, FNAME stored | judging the payload only |
| T33 br, zstd [2]; **T33b bombs [2]** | the dirty body / the bomb stored as received | the name scan over compressed bytes; an uncapped decoder |
| **T43 chunk cap** | 65,537 chunks stored | an uncapped chunk loop |
| **T45 desync probes [7] + `auth.js` [1]** (B2, controls) | pass (byte-exact today) | revision 3's framing (*proved*, `rev3framing`: 6 fail) |
| T34 sniffed JSON [11 × 2] | 10 fail (leaf canaries, merged keys, `1e400` → `Infinity`, the unbalanced leaf); 12 controls | the text pass over a parseable body (*proved*); a dict round trip; a body omitted for an unbalanced leaf (revision 3) |
| T35 markup anywhere [12] (UTF-8 BOM case added) | the pass-through | markup rules keyed on the declared type; an unstripped latin-1 BOM |
| T36 unbound shapes [11] (PGP, PuTTY, bare DSN, `?` ends a value added) | the pass-through | name bindings only |
| T37 fail-closed shapes [9] (no-BOM re-encoding asserted) | the pass-through, the form and multipart parsers | binding nothing on an exhausted search (*proved*); adding a BOM |
| **T46 unparseable declared JSON [3: userinfo, JWT, bare DSN] + runner cut JSON [1]** (B3) | kept as received (no sensitive word, so today's name scan keeps it) | the name-scan rule for unparseable JSON (*proved*, `jsonomit`) |
| **T47 auth schemes [4] + page text [1]** (B4) | the pass-through; page text stored as given | replacing the scheme word only (*proved*, `schemeword`) |
| T23, T38 spider text | stored as given | `get_text` over the received HTML; redacting in `_parse_html` only |
| T25, T41, T26 | as revision 3 | as revision 3 (`cutfirst` *proved*) |
| **T49 `target_blank` href** | the fragment token and identifier stored | the href cut without redaction |
| T40 dedup and join (control) | passes | identifier blanking on `page_url`/`target_identifier` (*proved*, `idblank`) |
| T24, T39 | xfail (strict), naming AU-SPIDER | — |
| C1 [6], C2, C2 error pages [5], C3 | pass (controls) | as revision 3 |

### 6.2 Phase 2 (with the implementation)

T12b (every loop charges the budget, AST), **T12c (the whole-body regex rule, §3.4)**,
T28 (the column registry, §4.3), T41b (every auditor cut goes through `_quote*`, AST),
T42 (the userinfo owner and its in-text forms agree, PA-0003), T17 (the capture test
with an HTML response), the three changed proxy expectations. Verification:
`scripts/verify_change.py --base 8100959`.

### 6.3 Counts, the non-vacuity run and the revert proofs

`tests/test_text_body_redaction.py`: **255 cases.**

| Run | Failed | Passed | Xfailed |
|---|---|---|---|
| `8100959` (today's code) | 199 | 54 | 2 |
| `8100959` + `proto3_plugin.py` (revision 4's prototypes in every producer, the spider, the auditor and the importer) | 0 | 253 | 2 |

- **The 199 failures** are each an `AssertionError` on the test's own canary or marker
  assertion (no import, attribute or type error). Revision 4 adds 38 cases: **30 fail on
  `8100959`** for the reasons in §6.1 (T12's 8 scan shapes: the canary kept; T33b's 2
  bombs and T43's 65,537 chunks: stored as received; T34's 2 new bodies under 2 types:
  `1e400` → `Infinity` and the unbalanced leaf's canary; T35's BOM page; T36's 4 new
  shapes; T46's 4: kept as received; T47's 5; T49: the fragment token and the
  identifier) and **8 pass** (T45's controls). Two changed cases fail for their new
  reasons too: T19 (the private-field and `default` canaries) and T31's second case
  (the canary inside the transfer gzip).
- **The 54 passes on `8100959`** are the stated controls: T9's 11 declared binary types
  and 6 JSON/multipart types, T18's 3 form shapes, T34's 12 validity cases, **T45's 7
  desync probes and the precompressed `auth.js`** (byte-exact today and in revision 4;
  they fail against revision 3's framing), T40, C1 (6), C2, C2's 5 error pages, C3.
- **The 2 xfails** are T24 and T39 (strict; AU-SPIDER).
- **Revert proofs** (`run_reverts.sh`, `run_reverts2.sh`; `REVERT=<name>` re-creates
  one defect in the prototypes; each named test fails):

  | Revert | Fails |
  |---|---|
  | `rawtext_regex` (revision 3's lazy raw-text regex) | T12 `unclosed-script-openers`, `unclosed-style-openers`: over the 20 s alarm |
  | `jwt_regex` (revision 3's `_JWT`) | T12 `eyJ-run`, `base64-json-state`: over the 20 s alarm |
  | `skeleton_unbounded` | T12 `skeleton-identifier-tags`: over its scan count |
  | `nocap` | T12 crafted: 3 shapes |
  | `rev3framing` (revision 3's framing) | T45: TE.TE, `xchunked`, `chunked, identity`, the two CL.TE suffixes, `auth.js` (6) |
  | `jsonomit` (the name-scan rule for unparseable JSON) | T46: all 4 |
  | `schemeword` (only the scheme word replaced) | T47: `html-pre-basic`, the page text |
  | `privatefield` (`#` always a fragment) | T19 |
  | `anyunquoted` | T19 |
  | `maxlen0` | T30 |
  | `recopy` | T29 |
  | `jsontext` (the text pass over parseable JSON) | T34: the escaped-JSON body (2) |
  | `bindnothing` | T37 `tag-search-exhausted` |
  | `cutfirst` | T41 |
  | `idblank` | T40 |

- **The smoke alarm is not an `Exception`.** The first `rawtext_regex` and `jwt_regex`
  runs passed in 80 s and 149 s: the alarm's `TimeoutError` was caught by the
  redactor's totality guard (`except Exception` → `OMIT_FAILED`), so the test saw no
  canary. The alarm now raises a `BaseException` subclass and T12 also asserts the body
  is not `OMIT_FAILED`; both proofs then failed as stated.

---

## 7. Requirement text (edited in place at implementation)

### FR-CORE-506 (new)

- **Coverage.** `redact_body` redacts every body a producer may persist, with no
  pass-through default (§3.1), unparseable declared JSON included (text pass).
- **Bindings.** Every value bound to a sensitive name (B1–B4, query context, auth
  schemes, private fields) and every JWT, private-key block (PEM, PGP, PuTTY), `Bearer`
  credential, URL userinfo and bare DSN, in html, xml, js, data, text or words grammar.
- **In place.** No sibling entry dropped, merged or reordered; sniffed JSON stays valid
  with its numbers as written; a clean body is byte-identical; idempotent.
- **Fail closed (U1–U7).**
- **Bounded and linear.** One operations budget (500,000) and a hit cap (20,000); every
  whole-body scan linear by construction; 1 s per 8 MiB body on the reference host;
  counters exposed (`stats=`).
- **`redact_page_text`, `redact_record_text`, `redact_record_url`** for stored page
  text, quoted target text and stored URLs.

### Other edits

- **FR-CORE-25:** a cross-reference. **NFR-CORE-secrets,** "Enforced by": text bodies
  T1–T5, T9, T12, T20, T34–T37, T46, T47; framed bodies T15, T21, T22, T29–T33, T43,
  T45; the spider DB T23, T38; the auditor DB and importer T25, T26, T41, T49; stored
  columns T28; whole-body scans T12, T12c.
- **FR-PROXY-11 (CC-PROXY-0028):** a chunked or compressed body is decoded only to
  judge it, in every plausible reading, with bounds; its framing bytes are judged by the
  text pass; it is stored byte-exact when every decoded reading is clean, else as a
  typed omission; br and zstd need the `proxy-codecs` extra.
- **04-crawler (CC-CRAWL-0051):** FR-CRAWL-18 (every body kind) and the spider DB
  contract (content and title redacted; URLs and `sig` pinned for AU-SPIDER).
- **05-auditor (CC-AUD-0057):** `html_context` through `redact_record_text`, every cut
  after redaction; `page_url` and a URL-shaped `target_identifier` through
  `redact_record_url`; the importer stores no example for a sensitive name.

---

## 8. Residuals (stated)

**R1. A secret with no name bound to it, or bound outside a recognised binding.** Call
arguments (`setItem`, `setRequestHeader`, an event handler's argument, a Nuxt 2 IIFE);
serialised payloads (Nuxt 3 devalue, JSON name/value pairs); tables (debug cells,
CSV, markdown); prose with no operator (`Your token is X`); concatenation; htpasswd and
netrc; vendor-prefixed tokens (`ghp_…`, `sk_live_…`); an identifier-like path segment.
Follow-up: scrub the exchange's known secret values as literals.

**R2. Encoded or broken names:** a percent-encoded name, a JS unicode escape, `srcdoc`,
a `data:` URI, a character reference outside a `name=`-like attribute, a no-break
space inside a name (`pass\xa0word:`).

**R3. Name predicate gaps (SP-17):** `state`, `client_id`, `APP_KEY`, `STRIPE_KEY`,
`PUSHER_APP_KEY`.

**R4. Out-of-policy binary formats.**

**R5. Nested template and regex literals in scripts** (over-omission possible).

**R6. JSON inside a declared-JSON string** without markup, a JWT, PEM or `@`.

**R7. Scripts:** an unquoted, non-numeric literal-like token bound to a sensitive name
is kept.

**R8.** A body omitted as unprovable loses its content in that copy.

**R9. Hot-path cost.** At most 1 s per 8 MiB redaction call (§M5); it runs on disco's
capture loop and the proxy's history flush (the BUG-0101 / PA-0102(3) class); audit
defects 22 and 25 move it.

**R10. Hand-off to AU-REQID:** two dict round trips merge repeated names.

**R11. The content-type table is enumerated and generated,** not taken from a capture.

**R12. Not swept or kept by contract:** the oracle's `finding.evidence` beyond a grep,
free-text log output, identifier-like hidden values under non-sensitive names in
`discovered_forms.entries`; T28 covers SQL columns only (§4.3).

**R13. Compressed text in proxy history (S1, M8; accepted, D12).** A framed text body
that redaction would change is stored as a typed marker, not a redacted copy:
**13 of the 14 real bodies and 6 of the 18 Juice Shop bundles** would be stored as
markers when served compressed. Decoded, redacted storage comes in the later proxy
framing item. A brotli metadata meta-block (content a decoder skips) is not judged; no
common encoder emits one.

**R14. Spider URLs (S2):** `discovered_pages.url`, `found_from` and
`discovered_forms.sig` keep a sensitive query value until **AU-SPIDER** (T39, T24).

**R15. S1's header effects on an omitted framed flow.** Its stored head drops
`Transfer-Encoding` and `Content-Encoding` and gains a `Content-Length`, so an FTS
search on those headers misses it; a Repeater tab seeded from an omitted framed request
replays a different request (the marker, unframed). Clean desync probes are byte-exact
(B2), so this applies only to omitted flows.

**R16. Unquoted attribute values in a markup fragment outside html** (`text/plain`,
untyped, a JSON leaf) are not bound; quoted ones are.

**Benign over-redaction (stated).** `Status code: 404` in prose; a CSS `code:hover`;
`x.token = 5`; quoted literals bound to `code`, `credentials`, `signature`; containers
bound to `keys`, `tokens`, `nonce`; `o.credentials="include"` after a `?` (B5's
fall-through). None omits a real page.

---

## 9. Bookkeeping drafted for merge (text handed to the coordinator)

### BUG-0527

**Scope:** (1) the text-body pass-through; (2) truncated sniffed JSON and unparseable
declared JSON (M1a, B3); (3) the framed judgement (M4, M4b); (4) the sinks that bypass
the boundary (§4.2), the spider's URLs and signature pinned for AU-SPIDER; (5) the
sniffed-JSON dict round trip; (6) the redactor's whole-body scans that were not linear
(B1), found in review before any implementation.

**RCA:** §2. Five Whys ends at "a pass-through default, a framed judgement that judged
only the bytes it decoded, producer guards keyed on three SQL tables, and no rule that
a whole-body scan be linear, none enforced by an enumeration".

**Recurrence and prior-PA failure analysis:** §2 (PA-0085, 0091, 0100, 0101, 0514 too
narrow; PA-0102(3) scoped to I/O).

### PA-0527, proposed

> Strengthens PA-0101(1), PA-0085(2), PA-0100 and PA-0102(3), after BUG-0527.
> 1. A redactor or safety filter has **no pass-through default**; an unknown kind and a
>    failed parse take the most general rule.
> 2. Its tests plant each secret shape in **every kind the producers persist**, and run
>    the dispatch over known, malformed and generated kinds.
> 3. **A sniffed reading never exempts** an input from a rule another reading would
>    apply; **every byte kept byte-exact is judged in every plausible reading**.
> 4. **Every stored SQL column is registered** as content (with the redactor bound to
>    it by position), not content (with a reason), or pinned (with a named strict-xfail
>    test). File writers are covered by their producers' tests, not by this registry.
> 5. **A scan over a whole body is linear by construction:** no regex run over a whole
>    body has a nested or lazy repeat, or an unbounded repeat a failed attempt re-scans;
>    a complexity claim is tested on counters with a generous absolute alarm (PA-0135).
>
> - Enforced by: tests/test_text_body_redaction.py::test_no_media_type_passes_a_bound_secret_through_unless_declared_binary, tests/test_text_body_redaction.py::test_a_parseable_sniffed_json_body_stays_valid_json_with_every_entry, tests/test_text_body_redaction.py::test_framing_bytes_that_hold_a_secret_are_omitted, tests/test_text_body_redaction.py::test_every_stored_column_is_registered_and_content_columns_are_redacted, tests/test_text_body_redaction.py::test_every_whole_body_pattern_is_linear_by_construction

(Clause 4's test, T28, checks SQL columns only, as clause 4 now says; clause 5's guard
is T12c. Both are written with the implementation; if either is not delivered, its
part of the line becomes "none — <reason>" and the coordinator is told.)

### SP-55, proposed

| Field | Text |
|---|---|
| Mechanism | the one storage-redaction boundary for every body kind, stored page text, quoted target text and stored URLs |
| Owner | `fuzzlab/core/redaction.py::redact_body` (with `redactable_type`, `redact_page_text`, `redact_record_text`, `redact_record_url`) |
| Guards | T9, T12, T12b, T12c, T28, `test_storage_redaction.py::test_every_traffic_producer_goes_through_the_redaction_boundary`, `test_shared_primitives.py::test_every_owner_is_defined_once` |
| From | PA-0100, PA-0101, PA-0527 (CC-CORE-0067) |

### Other merge text

- **SP-35:** add T1 to its guards. **Framed bodies:** `proxy/redact.py::judge_framed`
  is the one judge (guards T15, T29–T33, T43, T45).
- **ARCHITECTURE:** the `proxy-codecs` text of §3.5.
- **ERROR_LOG, CHANGELOG:** at merge.
- **`claude_juicelab_failures.md`:** the coordinator records revision 2's cost claim.
  For the coordinator's call, from this round: (1) this lane started one 0.3 s pytest
  (`-k unparseable_declared_json`, 3 cases) while another lane's `verify_change` was
  running, against the "refuse unless idle" instruction: the idle check and the run were
  chained in one command, so the check's output did not stop the run; every later run
  was a separate call after a clean check. (2) T12's first smoke alarm could be
  swallowed by the redactor's totality guard, so the first two quadratic proofs passed
  (§6.3); caught by the proof run itself, fixed before reporting.

---

## 10. Change-control fields

### CC-CORE-0067 — Text bodies (HTML, XML, script, plain text) through the one storage-redaction boundary (BUG-0527) (2026-10-20)

**Change:** §3.1–3.6; FR-CORE-506 new; FR-CORE-25 and NFR-CORE-secrets edited; SP-55
new. **Reason:** audit defect 26; BUG-0527.

**Impact:** CORE the owner; PROXY CC-PROXY-0028; CRAWL CC-CRAWL-0051; AUD CC-AUD-0057;
ML `flow_anomaly` lengths. `redact_body` gains `stats=`; new markers under the existing
prefix; no schema change. No AU-OUTCOME or AU-REQID file is edited; AU-OUTCOME's
runner evidence changes through the owner (PA-0152); AU-REQID's `harness/auto.py` reads
`""` examples for sensitive names; R10 handed to AU-REQID.

**Risk: medium.** *Mitigated:* byte-identical when clean (T14, C2); linear and bounded
(T12, T12c); no real body omitted (M6). *Accepted:* R1–R16.

**Deliverables:**
- [ ] owner — todo
- [x] the tests of §6.1 — written, uncommitted
- [ ] phase-2 tests (T12b, T12c, T28, T41b, T42, T17) and the three proxy expectations — todo
- [ ] `scripts/measure_body_redaction.py` — todo
- [ ] requirement edits (§7) — todo
- [ ] `pyproject.toml` `proxy-codecs` extra and the ARCHITECTURE dependency text — todo
- [ ] merge-time text (§9) — handed to the coordinator
- [ ] `scripts/verify_change.py --base 8100959`, green, counts quoted — todo

**Effectiveness:** pending.

### CC-PROXY-0028 — Framed bodies stay fail-closed: judged in every reading, every byte judged, bounded decoding, typed omissions (BUG-0527) (2026-10-20)

**Change:** §3.7 in `proxy/redact.py`; `_prepare` redacts once (`proxy/history.py`);
the `proxy-codecs` extra.

**Impact:** a framed body is byte-exact when every reading is clean, a typed marker
otherwise (R13, R15); clean desync probes byte-exact (T45); three test expectations
change.

**Risk: medium.** *Mitigated:* bounded decoding with counters (T22, T29, T30, T33b,
T43); every reading and framing byte judged (T21, T31, T32, T45). *Accepted:* R13, R15.

**Deliverables:** code, T15, T21, T22, T29–T33b, T43, T45, the FR-PROXY-11 edit — todo.

**Effectiveness:** pending.

### CC-CRAWL-0051 — The spider stores page text and titles redacted; the capture's docstring and requirement (BUG-0527) (2026-10-20)

**Change:** §3.8a; the capture docstring; FR-CRAWL-18 and the spider DB contract.
**Impact:** content and title redacted; links unchanged; URLs and `sig` pinned for
AU-SPIDER. **Risk: low.** **Deliverables:** code, T23, T38, T47's page text, the
requirement edits — todo. **Effectiveness:** pending.

### CC-AUD-0057 — The auditor's findings and the importer's parameter examples are redacted at the write (BUG-0527) (2026-10-20)

**Change:** §3.8c (`_quote`, `_quote_value`, the `target_blank` href,
`log_finding`) and §3.8d. **Impact:** findings context loses bound values and
identifier-like runs; `page_url` and URL-shaped targets lose query and fragment values;
the dedup key of non-URL targets and the importer's join unchanged; sensitive-named
examples become `""`. **Risk: low.** **Deliverables:** code, T25, T26, T40, T41, T41b,
T49, the requirement notes — todo. **Effectiveness:** pending.

---

## 11. For the coordinator

- **One review round is left under the cap.** Nothing here needs a decision before it.
- **T12's smoke alarm** uses `SIGALRM` (it interrupts a running regex scan; the harness
  runs tests on each worker's main thread). If the harness ever runs tests off the main
  thread, T12's alarm must move to a subprocess with a timeout.
