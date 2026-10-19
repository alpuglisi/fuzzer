# DRAFT AU-REQID14: every sender places a query value through one owner

- Item: `AU-REQID14`, audit defect 14 only. Owner-supplied audit at 6552276, F-096.
- Status: **revision 2**, for the last re-review round under the cap. Nothing here is
  implemented. Revision 1 drew DISAGREE from both reviewers. §12 maps each must-fix (M1–M7)
  and each adopted item to its change here.
- Base: `8100959`. Branch `worktree-agent-aef1371774d69f3f5`.
- Numbers: CC-FUZZ-0106, CC-CORE-0068, BUG-0531 / PA-0531, FR-FUZZ-64 (this item's
  alone; AU-REQID8 takes a new FR ID).
  - Reserved for AU-REQID8, not used here: BUG-0530, PA-0530, CC-AUD-0056, FR-AUD-31,
    SP-57.
  - CORE requirement: FR-CORE-501, amended in place (Q1).
- Merge order: AU-OUTCOME (`oracle/strategies.py`, `oracle/*`) merges first. Its result is
  merged into this branch **before** the `oracle/strategies.py` and `oracle/browser.py`
  parts are implemented.
  - `oracle/oracle.py` is **not changed** by this item.
- Parked: defect 8 (`DRAFT-AU-REQID8.md`), and POST-action query points (a later item).

## 0. Summary

**The defect.** Each sender builds a probe's query its own way:

| Sender | What it does to the query |
|---|---|
| The anonymous senders | append a second pair |
| The authenticated seam | rebuilds the query through a `dict`: duplicate siblings are lost, `%20` becomes `+`, empty parts are dropped, `%E9` becomes `%EF%BF%BD` |
| The M6 browser | appends, for the observe navigation and for the GET store step |
| The M6 browser, for a crawled DOM query point | loads it without the link-set siblings that the HTTP senders send |

So one point sends a different request depending on the sender. The conformance check
that should keep the senders in step cannot see any of this: it reads the query as a
`dict`, and its probe URL has no query.

**The fix:**
- **One owner** in `core/urls.py`, SP-42's extension beside `place_path_param`:
  - **`QueryEntries`**: an ordered list of raw parts;
  - **`place_query_param`**: a standalone URL's first occurrence, placed in place, every
    other part kept with its raw text;
  - **`bind_query`**: bound entries, by the binder's rule, which replaces every occurrence
    of the name.
- **Every HTTP sender and the M6 executor place through these.** `DomXssStrategy` hands the
  executor the candidate's entries.
- **The conformance check reads the raw request.** HTTP senders are compared byte for byte;
  Chromium is compared under a measured relation.
- **An AST guard keeps new query builders out.**

**Two rules until AU-REQID8, stated wherever placement is specified.** A *standalone* URL
addresses the first occurrence of the name. *Bound* entries (a link set, a form) replace
every occurrence of the name, exactly as the oracle's binder does today. The binder does
not change. AU-REQID8 makes the occurrence part of a point and switches both rules at once,
in `bind_query`.

## 1. Measured (MULTI_AGENT_ORCHESTRATION §7; CLAUDE.md §8)

The measurement test file is committed: `tests/test_query_placement.py`.
- Every sender sends to a loopback echo server started in the test (`require_loopback`).
  The server records the raw request target.
- Real Chromium 141.0.7390.37 (Playwright build 1194) is used for M6.
- With `FUZZLAB_REQUIRE_BROWSER=1` on `8100959`:

| Run | Result |
|---|---|
| `--runxfail` | **58 failed, 19 passed** |
| with the strict-xfail pins | 19 passed, 58 xfailed |

### 1.1 What each sender put on the wire

The point is a standalone GET query point, so the first occurrence is addressed. HTTP
senders are judged byte for byte against `_prepared(contract)`: the query that requests
itself puts on the wire for the contract's query.

| Case: query before / param | Contract | Anonymous family: `RequestsProbeSender`, greybox `RequestsCorrelatingSender`, blind-sqli `RequestsSender` | Seam family: `SeamProbeSender` anonymous and with an identity, blind-sqli `SeamSender` | M6, Chromium |
|---|---|---|---|---|
| audit: `id=1&tag=a&tag=b` / id | `id=M&tag=a&tag=b` | `id=1&tag=a&tag=b&id=M` | `id=M&tag=b` | appends |
| dup-sibling: `tag=a&id=1&tag=b` / tag | `tag=M&id=1&tag=b` | appends | `tag=M&id=1` | appends |
| raw-text: `a=%7E&flag&id=1&b=x+y` / id | `a=%7E&flag&id=M&b=x+y` | appends | `a=~&flag=&id=M&b=x+y` | appends |
| blank: `id=&x=1` / id | `id=M&x=1` | appends | holds | appends |
| encoded-name: `a%5B%5D=1&a%5B%5D=2` / `a[]` | `a%5B%5D=M&a%5B%5D=2` | appends | `a%5B%5D=M` | appends |
| **pct20-sibling**: `id=1&t=x%20y` / id | `id=M&t=x%20y` | `id=1&t=x%20y&id=M` | `id=M&t=x+y` | `id=1&t=x%20y&id=M` |
| **empty-parts**: `a=1&&id=1&` / id | `a=1&&id=M&` | `a=1&&id=1&&id=M` | `a=1&id=M` | `a=1&&id=1&&id=M` |
| **pctE9-sibling**: `id=1&e=%E9` / id | `id=M&e=%E9` | `id=1&e=%E9&id=M` | `id=M&e=%EF%BF%BD` | `id=1&e=%E9&id=M` |

- **45 of 48 sender × case combinations fail.** The three that hold are the seam family's
  blank-value case.
- **All 8 M6 cases fail.** The new cases (bold) each fail for their stated reason, and
  every wire above was recorded at the server. The stated reasons are: the append, the
  `%20` → `+` rewrite, the dropped empty parts, and the `%E9` → `%EF%BF%BD` replacement.
- **The anonymous and the seam sender differ byte for byte.** Both go through requests,
  so the test demands equal bytes.

**The hard payload.** On a query-less URL (every ground-truth point), the payload
``'"<>&=#+% é/~`` arrives as exactly `id=` + `quote_plus(v, safe="")` from all 6 HTTP
senders and from Chromium. That is today's bytes, and the fix keeps them.

**A plausible wrong fix fails the cases.** The fix "decode all, drop empties, replace,
re-encode" fails raw-text, pct20, empty-parts and pctE9
(`test_the_cases_catch_the_decode_all_reencode_fix`).

**The bound path.** The binder (`_FormBoundSender`, `FormEntries.replace`) sends
`id=1&tag=M&tag=M` for point `tag` over `id=1&tag=a&tag=b`. That is the binder's rule,
and it stays until AU-REQID8. The test is pinned with AU-REQID8 named.

**The M6 GET store step** (`browserexec.py:539`) carried `id=1&tag=a&tag=b&id=M`: it
appends.

**An M6 DOM point with siblings.** A candidate with `base_entries` `op=search&q=1`, run
through `DomXssStrategy` and real Chromium, made six loads. Every one was `/p?q=<payload>`
alone. `DomXssStrategy` hands the executor no entries.

**PRG follow-up** (`302 Location: #top`):
- `RequestsProbeSender`'s bound branch hands `_follow` the placed URL (`:946`, `:967`), so
  the follow-up re-sends the payload: `['/p?id=M&tag=a', '/p?id=M&tag=a']`.
- Its standalone branch and both seam branches keep the probe's own URL, and hold.
- An empty `Location` is not followed, and holds.

**The existing check is blind.** `tests/test_sender_conformance.py::_Wire` turns the query
into a `dict`, and its probe URL is `http://h/a.php`, with no query (cf. PA-0311(2)).

### 1.2 The clients' own rewriting: the platform fact the relation rests on

Pinned by `test_platform_clients_rewrite_only_escapes_they_disagree_on`, a real-process and
real-Chromium test. It fails, and never skips, under `FUZZLAB_REQUIRE_BROWSER=1`.
- **18 verbatim queries** are covered: the reviewers' set plus this lane's.
- Measured 2026-10-19 with requests 2.34.2 and Chromium 141.0.7390.37.
- It also asserts that `_prepared` models requests exactly.

**What each client does:**

| Client | Decodes | Escapes | Keeps raw | Hex case |
|---|---|---|---|---|
| requests | escapes of unreserved bytes (`%7E` → `~`) | raw `"`, `<`, `>`, `\`, `^`, backtick, `[`, `]`, `{`, `\|`, `}` and non-ASCII | `'` | upper-cases (`%e9` → `%E9`) |
| Chromium | nothing (keeps every escape as given) | raw `'`, `"`, `<`, `>` and non-ASCII | `\`, `^`, backtick, `[`, `]`, `{`, `\|`, `}` | keeps as given |

**Neither client** changes:
- a pair boundary or an empty part (`&&`, a trailing `&`);
- an `=`, or its absence (`flag`);
- `+` vs `%20`;
- `;` vs `%3B`, `/` vs `%2F`, `?` vs `%3F`;
- an escape of `& = + % # , @ !`;
- `%E9`, which is never turned into `%EF%BF%BD`.

**The relation built on this** is `canonical_pairs`. It compares bytes (`unquote_to_bytes`)
with hex upper-cased. It decodes only the escapes measured to move: the unreserved set,
`' " < > [ \ ] ^` and backtick, `{ | }`, and bytes ≥ 0x80. It is used **only for Chromium
against requests**. HTTP senders are compared byte for byte (F1).

`test_the_equivalence_still_tells_apart_what_a_server_reads_apart` proves it is not
vacuous. These all compare different under it:
- a duplicate, or a lost sibling;
- `flag` vs `flag=`;
- `+` vs `%2B`, and `+` vs `%20`;
- `&` vs `%26`, and `;` vs `%3B`;
- `/` vs `%2F`;
- `%E9` vs `%EF%BF%BD`;
- an empty part;
- order.

### 1.3 Effect on tests, the oracle budget and scored results

- **Tests and budget: none in count.** Placement changes what a probe carries, never how
  many probes or tests a run makes. No point builder, key or binder changes.
- **Scored ground truth: no change on the wire** (`gt_exposure.py`):
  - 157 injection-point rows, and **0** with a query in the URL. M1's accepted residual
    has no exposure.
  - 179 built points (`points_from_ground_truth`, browser and writes on), of which 8 are
    bound: 7 JSON leaves and 1 path account value. **None is at query or fragment.**
  - 5 DOM points, **none bound**. The M6 sibling change (M2) moves no ground-truth load.
  - A query-less URL gets today's bytes (the hard-payload row).
- **Crawl runs change on the wire. This is intended.** Each change below is measured
  through the fixture above:
  - a URL that already carries a query: the standalone path;
  - every crawled DOM query point with a link set, which M6 now loads with its siblings;
  - the GET store step.
- **Not measured: a live before/after on a development lab.** It needs the owner's
  authorisation to run against a target (D11), so it is a residual (§9, residual 4).

## 2. Root cause (Five Whys)

1. **Why did a first-value server never see the anonymous payload?** `requests` appended a
   second `id` (`params=`).
2. **Why did the authenticated path lose `tag=a` and rewrite untouched pairs?**
   `tools/authhttp.with_query_param` rebuilds the query through `dict(parse_qsl(...))`.
3. **Why do they differ?** Each sender builds the query itself: the two probe senders,
   greybox, blind-sqli and the M6 executor. Nothing owns "place a value in a query". SP-42
   owns only the path segment. The M6 strategy builds its browser request without the
   entries the HTTP binder uses.
4. **Why did PA-0115's conformance check not catch it?** It checks placement per
   *location*, not per occurrence. Its wire collapses the query into a `dict`, and its
   probe URL has no query.
5. **Root cause.** Query placement is not a shared primitive. The check meant to keep the
   senders in step observes through a channel that cannot carry the violation.

## 3. Design

### 3.1 The owner: `core/urls.py`, SP-42 extended (CC-CORE-0068)

**`QueryEntries`**
- `QueryEntries.parse(raw_query)`:
  - The query comes from `urlsplit`, never `urlparse`, which would split off `;params`.
  - It is split on `&` only, because both clients keep `;` as data (§1.2).
  - Each part keeps its raw text, its order, its `=` presence, and whether it is empty.
  - **An empty query has zero parts.** `?` alone and `&&` are distinct: zero parts versus
    three empty ones.
  - Each part's name is decoded as a server reads it, for matching only:
    `unquote_plus(name, errors="surrogateescape")`. `n%E9` (→ `n\udce9`) and
    `n%EF%BF%BD` (→ `n�`) therefore never count as one name (tested).
- `.replace_first(name, value)` puts `encode_query_value(value)` into the first part whose
  decoded name equals `name`.
  - That part's raw name text is kept, and every other part keeps its raw text.
  - An absent name appends one `encode_query_value(name)=encode_query_value(value)` part.
- `.to_query()` joins the parts' text with `&`.

**`encode_query_value(text)`** is the one encoder, `quote_plus(text, safe="")`: what
`urlencode` does today. A query-less URL's bytes are therefore unchanged (§1.1, the hard
payload).

**`place_query_param(url, name, value) -> str`** is the **standalone rule**. It parses the
URL's own query, applies `replace_first`, and keeps the rest of the URL verbatim. An empty
`?` or `#` is dropped, as `urlunsplit` does.

**`bind_query(url, entries, name, value) -> str`** is the **bound rule**, the one shared
bind-then-place function. It returns
`with_query(url, FormEntries(entries).replace(name, value))`: the binder's rule, which
replaces every occurrence and appends when the name is absent.
- It is idempotent on entries the oracle's binder has already bound: every occurrence
  already holds `value`. So the HTTP senders' bound branch can call it too, and it adds
  nothing.
- It is called by both the senders' bound branch and the M6 executor. AU-REQID8 switches
  both by changing this one function.

**`with_query(url, entries) -> str`** is moved from `tools/authhttp.py` with the same
bytes. The URL's query becomes `urlencode(list(entries))`: a form's or a stored link set's
decoded entries, serialised as a browser serialises a form (PA-0111).

**`place_route_query_param(url, name, value) -> str`** applies the standalone rule inside an
SPA hash route's query (`/#/route?…`), keeping that route's `%20` encoding
(`quote_via=quote`). A non-route fragment is replaced by the pair (`#q=v+w`), as today.
`browserexec._with_fragment` stays a thin wrapper over it (M7: `tests/test_json_points.py`
imports it by name).

**What is removed:** `tools/authhttp.with_query_param` and `with_query`.
`with_query` is defined once, in the owner (`test_shared_primitives::test_every_owner_is_defined_once`).

**Not in this item** (AU-REQID8 brings them): `FormEntries.replace_at` and any occurrence
other than the first.

### 3.2 The placement contract (FR-FUZZ-64)

Every query value a sender or the M6 executor places goes through §3.1. Until AU-REQID8, a
repeated name follows **two rules**:

| Request | Rule |
|---|---|
| Standalone: no entries; the URL's own query | the first occurrence of the name gets the payload, in place. Every other part keeps its position, its `=` (or its absence) and its raw text, up to the HTTP client's own rewriting (§1.2). An absent name is appended once |
| Bound: entries from a link set, a form, or a sender's caller | every occurrence of the name gets the payload (the binder's rule), and the query is the entries, urlencoded |

**Rules for every sender:**
- No sender adds a second pair for a name the query already has. That would be a deliberate
  duplicate-parameter probe. **None exists in fuzzlab today**, and if one is added it is its
  own mechanism.
- The payload is encoded by the one encoder.
- Form bodies are unchanged (the binder's rule, urlencoded).

### 3.3 Every sender through the owner (CC-FUZZ-0106)

| Site @8100959 | Change |
|---|---|
| `tools/probesender.RequestsProbeSender.send` | final `else` (`:964`): `wire = place_query_param(url, param, value)`, with no `params=`. **F2:** the `else` keeps covering `fragment` and unknown locations, exactly as today, so the BUG-0115 strict xfail (`test_sender_conformance.py:523-531`) does not XPASS. Bound query (`:946`): `wire = bind_query(url, entries, param, value)`. **M6:** the request goes to `wire`, and `url` (the probe's own URL) is what `_follow` gets (`:967`) |
| `tools/probesender.SeamProbeSender._send_on` (every session route) | final `else` (`:822`): `place_query_param` (F2 as above); bound query (`:793`): `bind_query`. Its `_follow` already receives the unplaced `url` (measured) |
| `greybox/run.RequestsCorrelatingSender.send_correlated` | standalone (`:196`): `place_query_param`; bound query (`:192`): `bind_query`, never `params=list(entries)`, which appends to a URL's own query |
| `tools/blind_sqli_fuzzer.RequestsSender.get` / `SeamSender.get` | `place_query_param` (`:58`, `:82`) |
| `tools/browserexec.PlaywrightBrowserExecutor` | the observe navigation (`:552`) and the GET store step (`:539`): `bind_query(url, request.entries, param, value)` when `entries` is given, else `place_query_param`. `_with_query` (`:25-29`) is removed. `_with_fragment` (`:32-48`) becomes a thin wrapper over `place_route_query_param` |
| `oracle/browser.ExecRequest` | gains `entries: tuple \| None = None`, the bound sibling entries of a query point. No `occurrence` |
| `oracle/strategies.DomXssStrategy._observe` | passes `entries=candidate.base_entries` when `candidate.location == "query"`. One line, after AU-OUTCOME merges |
| `harness/auto.header_points_from_store` (`:510`) | `with_query(page_url, …)`, never `"?" + urlencode(...)`. Same bytes |
| `harness/pipeline._baseline`, `oracle/oracle._FormBoundSender` | **unchanged**: the binder's rule (M1) |

**`ExecRequest.entries` consumers** (PA-0152; found by searching `ExecRequest(` and
`.run(` over `fuzzlab/` and `tests/`):
- **Writer:** `DomXssStrategy._observe`.
- **Readers:**
  - `PlaywrightBrowserExecutor.run`;
  - `FakeBrowserExecutor.run`, which ignores it;
  - the M6 visit trace, which records no siblings (residual 3).
- **`StoredXssStrategy`** builds `ExecRequest` without entries and is unchanged.
- **Test files that build `ExecRequest`**, all unaffected by a defaulted field:
  `test_navigation_aborts`, `test_m6_payload_quoting`, `test_confirm_trace`,
  `test_m6_navigation_failures`, `test_put_patch`, `test_destructive_urls`,
  `test_query_placement`, `test_sender_conformance`, `test_unplaceable_confirmation`,
  `test_browser_scope`, `test_json_points` and `test_forms_phase2`.

### 3.4 How conformance is proven

**The fast, offline check** is in `tests/test_sender_conformance.py`:
- `_Wire` stops collapsing. A requests-style send and the seam's fake transport both record
  `requests.Request(method, url, params=…).prepare().url`: requests' own merge, which the
  seam's real transport also applies (F1).
- New `test_every_sender_places_a_query_occurrence_in_place` covers the §1.1 cases and the
  bound rule. It runs over:
  - every concrete sender in `PLACEMENT_FACTORIES` (found by AST; a new one must
    register);
  - greybox, standalone and bound;
  - both blind-sqli senders.

  It compares **byte for byte**.
- New `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` is its
  synthetic offenders: an appender and a `dict` rebuilder both fail (PA-0034(2)).

**End to end** is `tests/test_query_placement.py`:
- all 8 cases for each sender, on the echo server;
- M6 in real Chromium for the observe navigation (8 cases), the GET store step, and a DOM
  point with siblings;
- the PRG rows;
- the hard payload.

**M6 against HTTP.** New `test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike`
sends a bound point with a repeated name through M6 (`ExecRequest.entries`) and through
`_FormBoundSender` over `RequestsProbeSender`. Both go through `bind_query`, and the two
wires must be equal under `canonical_pairs`.

### 3.5 The guard (M3)

**`test_every_query_builder_goes_through_the_one_owner`** is an AST check over `fuzzlab/`,
excluding the owner `core/urls.py`. A finding is keyed by (module, enclosing function,
shape), with a count, so it survives line moves. It flags:

- **S1, `params=` on a send:** a keyword `params` on a call named `request`, `get`,
  `post`, `put`, `patch`, `delete`, `head`, `options`, `fetch` (Playwright) or `Request`
  (`requests.Request`).
- **S2, a subscript store into `params`:** a subscript whose slice holds the constant
  `"params"`, including `kwargs["data" if … else "params"] = …`.
- **S3, a parse into a dict:** `dict(parse_qsl(...))`, `dict(parse_qs(...))`, or any
  `parse_qs(...)`.
- **S4, string building onto a query:** a `+` or `%` BinOp, a `+=`, an f-string, or
  `.format`. It must contain a `?`/`&` string constant (keyword arguments excluded:
  `quote(s, safe="&")` is no query; an IfExp operand such as `("&" if … else "?")`
  included), and a call to `urlencode`/`quote`/`quote_plus` or a `.query`.
- **S5, a join on a query separator:** `"&".join(...)` or `"?".join(...)`.
- **S6, `._replace(query=...)`.**
- **S7, a tuple rebuild:** tuple-form `urlunsplit`/`urlunparse` whose query or fragment
  slot is neither `""` nor the unchanged `.query`/`.fragment`. So `strip_url` and
  `_no_query` do not match, and `browserexec:29`/`:48` do.

**Allow-list.** Each allowed site is listed with its reason (§4.2), and
**`test_the_query_builder_allow_list_has_no_stale_entry`** fails on an entry the scan no
longer finds.

**Proof on synthetic offenders.** `test_the_query_builder_guard_catches_synthetic_offenders`
uses 21 synthetic offenders, one per shape:
- `kwargs["params"]` and its IfExp form;
- an f-string;
- `"&".join`, `.format` and `%`;
- an IfExp operand;
- `params=` on `put`, `patch`, `delete`, `head`, `options`, `requests.Request`, Playwright
  `fetch` and `get`;
- `urlunsplit` with a rebuilt query and with a rebuilt fragment, and `urlunparse`;
- `parse_qs`, `dict(parse_qsl)`, `._replace(query=)`.

It also uses 5 near-misses that must not match:
- `urlunsplit(…, "", "")`, and `urlunsplit` with the query and fragment unchanged;
- `quote(s, safe="&=")`;
- a model's `{"params": w}`;
- `d.get("params")`.

**Prototype.** A prototype of this guard, run on 8100959, flags exactly the fix sites of
§3.3 and the 41 allow-list entries of §4.2, with zero misses on the offenders and zero
false positives on the near-misses:
- guard:
  `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/aureqid/guard_proto.py`
- offenders:
  `/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/aureqid/guard_offenders.py`

## 4. The sweep (PA-0002, by mechanism; it agrees with the guard)

### 4.1 Fixed by this item (the guard's findings that go away)

| Module · function | Shape | Fix |
|---|---|---|
| `tools/authhttp.py` · `with_query_param` | S3, S6 | removed (owner) |
| `tools/authhttp.py` · `with_query` | S6 | moved to the owner |
| `tools/probesender.py` · `RequestsProbeSender.send` | S2 (`:964`) | `place_query_param` / `bind_query`; `url` kept for `_follow` |
| `greybox/run.py` · `RequestsCorrelatingSender.send_correlated` | S2 (`:192`, `:196`) | `place_query_param` / `bind_query` |
| `tools/blind_sqli_fuzzer.py` · `RequestsSender.get` | S1 (`:58`) | `place_query_param` (and `SeamSender.get`'s `with_query_param` at `:82`) |
| `tools/browserexec.py` · `_with_query` | S4, S7 (`:28-29`) | removed: `place_query_param` / `bind_query` |
| `tools/browserexec.py` · `_with_fragment` | S7 (`:48`) | thin wrapper over `place_route_query_param` |
| `harness/auto.py` · `header_points_from_store` | S4 (`:510`) | `with_query` (same bytes) |
| `tools/probesender.py` `:822` (seam), `:946` (bound) | calls to the removed helpers | `place_query_param` / `bind_query` |

### 4.2 Allow-listed (41 entries, each with its reason; none may go stale)

| Module · function (count) | Shape | Reason |
|---|---|---|
| `core/redaction.py` · `redact_query`, `_redact_query_identifiers` (S5); `redact_url`, `redact_url_identifiers` (S6) | 4 | storage redaction of a recorded URL, never sent. **AU-REDACT's file** |
| `core/trace.py` · `_blank_identifiers` | S5 | trace redaction, never sent |
| `disco/fingerprint.py` · `normalise_route` | S5 | a route key of parameter names, never sent |
| `disco/runner.py` · `Runner.prepare` (S4 ×2) | 2 | **hand-off to AU-OUTCOME** (their file): the contract runner appends query pairs (`:262`) |
| `disco/synth.py` · `parse_body` | S3 | **defect 9's item**: a schema from captured bodies, never sent |
| `harness/auto.py` · `header_point_estimate` | S4 | a SQLite `file:` URI (`?mode=ro`), not HTTP |
| `lab_fixtures/external.py` · `_bwapp_install`, `_ecommerce_login` | S1 ×2 | lab provisioning with constant parameters, not probing |
| `labgen/conformance/django_live_boot.py` · `DjangoLiveBootHarness.get` (S1), `.request` (S4 ×2) | 3 | a harness client of generated cells on query-less paths |
| `labgen/conformance/live_boot.py` · `LiveBootHarness.fetch`, `.get` (S1), `.request` (S4 ×2) | 4 | same |
| `labgen/conformance/live_boot_spring_boot.py` · `SpringBootLiveBootHarness.get` (S1), `.request` (S4 ×2) | 3 | same |
| `labgen/conformance/rails_live_boot.py` · `RailsLiveBootHarness.fetch`, `.get` (S1), `.request` (S4 ×2) | 4 | same |
| `labgen/conformance/tier2.py` · `LiveBootTier2Oracle._fetch` | S1 | same |
| `labgen/identifier_sqli_oracle.py` · `_build_url` | S4 | its input is a mapping, so a duplicate cannot be expressed; generated cells declare none |
| `labgen/oracle_wrapper.py` · `_mark_query_param` | S6 | **LAB hand-off** with evidence (below) |
| `proxy/server.py` · `target_from_request` (S4 ×2) | 2 | the proxy forwards the client's own query verbatim |
| `tools/spa.py` · `visit_key` (S4 ×2) | 2 | the crawler's dedup key, never sent |
| `tools/spa.py` · `query_url` | S5 | **CRAWL hand-off**: the SPA query-seed builder (`:1812-1821`) appends to an existing route query and does not encode its values. It sends fillers, not probes |
| `tools/spider.py` · `LocalSpider._isolated_submit` (S4, S1) | 2 | a GET form submission: the action's query is replaced by the entries, as a browser does (PA-0111) |
| `tools/store_adapter.py` · `_store_request` | S4 | a stored endpoint key keeps the request's query verbatim (`:859`), never sent as built |
| `tools/store_adapter.py` · `import_disco` | S3 | **AU-REQID8** (the importer): a captured form body's repeated name collapses (`:274`) |
| `web/app.py` · `create_app.repeater_from_finding_prg`, `create_app.repeater_from_flow_prg`; `web/projectroutes.py` · `_form` | S3 ×3 | the operator's own UI form posts, not traffic to a target |

**LAB hand-off evidence** (measured):
`_mark_query_param("http://h/p?id=1&tag=a&tag=b&flag&s=x%20y", "tag", "*")` returns
`…?id=1&tag=%2A&tag=%2A&flag=&s=x+y`. That is three things:
- every occurrence is marked;
- `flag` becomes `flag=`;
- `%20` becomes `+`.

Marking every occurrence may be right for a tool's injection marker (sqlmap's `*`). The
re-encoding of untouched pairs is the part to fix. That needs a LAB number, so it is not
pinned here.

**Not builders, so the guard does not match them:** `session/detect.py` (set comparison),
`session/browserlogin.strip_url` and `session/state._no_query` (`""` slots),
`tools/observe.py`, `ml/flow_anomaly.py`, `tools/fetcher.py:517` (names), and the
`{"params": …}` model and history dicts (`ml/persist.py`, `ml/ranker.py`,
`proxy/history.py`, `tools/observe.py`, `web/sitetree.py`).

**Found while sweeping M6, flagged and not fixed here.** Both probe senders' **path** branch
also hands `_follow` the placed URL. Measured: a path point `/t/{id}/view` answered
`302 Location: #top` re-requests `/t/zqmark/view` from both senders. A path URL has no
payload-free form, so whether that follow-up should be skipped is an FR-FUZZ-49 (PRG)
design question, not query placement. It is a defect for the coordinator to register.

## 5. Tests, each with the revert it must fail against (PA-0034(2))

**Measurement tests (committed).** Each pinned test becomes positive at implementation, and
its strict xfail is removed in the same change (MULTI_AGENT §6), except where AU-REQID8 is
named.

| Test | Today | Must fail against |
|---|---|---|
| `test_every_sender_replaces_the_addressed_occurrence_in_place[sender-case]` | 45 pinned, 3 hold | a sender's `params=` append, its `dict` rebuild, or a decode-and-re-encode owner |
| `test_the_anonymous_and_authenticated_senders_send_the_same_query` (bytes) | pinned | either family's old branch |
| `test_a_hard_payload_on_a_query_less_url_is_quote_plus_encoded[sender]` ×6, `test_the_browser_sends_a_hard_payload_on_a_query_less_url_as_quote_plus` | hold | an encoder change (`quote` for `quote_plus`, another `safe`) |
| `test_the_cases_catch_the_decode_all_reencode_fix` | holds | weaker cases, which would let that wrong fix pass |
| `test_a_bound_duplicate_name_changes_one_occurrence_only` | **pinned for AU-REQID8** (stays failing after this item) | — |
| `test_a_fragment_only_location_is_followed_without_the_payload[anonymous-standalone, anonymous-bound, seam-standalone, seam-bound]` | anonymous-bound pinned, 3 hold | reassigning `url` to the placed URL before `_follow` |
| `test_an_empty_location_is_not_followed[anonymous, seam]` | hold | following a redirect with no `Location` |
| `test_the_browser_executor_replaces_the_addressed_occurrence_in_place[case]` ×8 | pinned | `browserexec._with_query` appending |
| `test_the_browser_get_store_step_replaces_the_addressed_occurrence_in_place` | pinned | the GET store step left on `_with_query` |
| `test_a_dom_query_point_is_loaded_with_its_siblings` (positive at implementation) | pinned | `DomXssStrategy` not passing `entries`, or the executor ignoring them |
| `test_platform_clients_rewrite_only_escapes_they_disagree_on` | holds | a client upgrade that changes §1.2 (a platform pin) |
| `test_the_equivalence_still_tells_apart_what_a_server_reads_apart` | holds | a relation that decodes `%2B`, `%3B`, `%2F` or `%20`, or maps `%E9` to U+FFFD |
| `test_control_a_query_less_url_gets_the_pair` | holds | a sender that stops appending to a query-less URL |

**New at implementation:**

| Test | Must fail against |
|---|---|
| `test_query_placement::test_the_owner_places_the_first_occurrence_and_keeps_raw_text`: every part shape of §1.2; an empty query has zero parts; `?` or `#` alone is dropped; `;` stays data | `urlparse`; a decode-and-re-encode owner; dropping empty parts |
| `…::test_name_matching_never_merges_an_invalid_escape_with_its_replacement` (`n%E9` vs `n%EF%BF%BD`) | `errors="replace"` matching |
| `…::test_bind_query_follows_the_binders_rule_and_adds_nothing_to_bound_entries` | a re-bind that appends a duplicate, or replaces one occurrence only |
| `…::test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike` (Chromium) | an executor not using `bind_query` for `entries` |
| `…::test_every_query_builder_goes_through_the_one_owner`, `…::test_the_query_builder_guard_catches_synthetic_offenders` (21 + 5 near-misses), `…::test_the_query_builder_allow_list_has_no_stale_entry` | a new builder of any shape S1–S7; a guard that misses a shape or flags a near-miss; a stale entry |
| `tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place`, `…::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` | any sender's old branch; `_Wire` reverted to a `dict` (the offenders would pass) |
| `tests/test_json_points.py::test_the_executor_places_a_fragment_inside_the_hash_route`, extended with `#/s?q=old&page=2` → `#/s?q=M&page=2` | `_with_fragment` appending a second `q` |

**Existing tests that pin the old behaviour** (M7; before and after, PA-0073(3)):

| Test | Before | After |
|---|---|---|
| `tests/test_greybox_live.py:397` | `captured["params"] == {"id": "1"}` (the `params=` call shape) | the URL `http://h/x.php?id=1`, and `params` is None |
| `tests/test_json_points.py:744-754` | imports `_with_fragment` and asserts three URLs | `_with_fragment` stays as a thin wrapper; the three asserted URLs are unchanged (route `%20`, `#!/s?page=2&q=v`, and a non-route `#q=v+w`) |
| `tests/test_fuzzer_seam.py::test_with_query_param` | tests the removed function | tests `place_query_param`. The seam-sender half (`?a=b` kept, quote-plus payload) is unchanged |
| `tests/test_fuzzer_seam.py::test_requests_sender_unchanged_standalone_behavior` | the call `("http://localhost/p.php", {"id": "1"}, 15, False)` | `("http://localhost/p.php?id=1", None, 15, False)` |
| `tests/test_sender_conformance.py::_Wire` | a `dict` | the prepared URL (F1). `test_the_placement_check_catches_a_relocating_sender` is re-checked on it |

`test_forms_phase2._App` and `test_json_points._JsonWire` check no placement, so they stay
as they are (AU-REQID8).

## 6. Requirement text (living specs, edited in place at implementation)

**FR-FUZZ-64** *(one query placement for every sender; `CC-FUZZ-0106`, BUG-0531)*. It is
complete for this item; AU-REQID8 takes a new ID.

- **One owner.** Every sender places a query value through `core.urls` (FR-CORE-501,
  SP-42). The senders are `RequestsProbeSender`, `SeamProbeSender` (every session route),
  greybox's `RequestsCorrelatingSender`, both blind-sqli senders, and the M6 browser
  executor (its observe navigation, its GET store step, and an SPA hash route's query).
- **Until AU-REQID8, a repeated name follows two rules:**
  - a **standalone** URL (no entries) addresses the **first occurrence**, in place;
  - **bound** entries (a link set, a form; the oracle's binder, unchanged) replace
    **every occurrence**, through `core.urls.bind_query`, for the HTTP senders and the M6
    executor alike.
- **Every untouched part keeps** its position, its `=` (or its absence) and its raw text,
  up to the HTTP client's own rewriting (pinned by a real-browser test). An absent name is
  appended once. The payload is `quote_plus`-encoded.
- **No sender adds a second pair** for a name already present. There is no
  duplicate-parameter probe.
- **A crawled DOM query point** is loaded in the browser with its bound siblings
  (`ExecRequest.entries`, from `DomXssStrategy`).
- **A PRG follow-up** is resolved against the probe's own URL, never the placed one.
- **Checks.** `tests/test_sender_conformance.py` checks every sender byte for byte on the
  request requests prepares. `tests/test_query_placement.py` checks them end to end, with
  Chromium under the measured relation.
- **Stated gaps:**
  - a standalone operator URL with a repeated name probes its first occurrence only
    (0 of 157 ground-truth rows carry a query);
  - a stored link set's siblings are sent from their stored decoded values, so `flag`
    becomes `flag=` and `%20` becomes `+`, and `store_adapter.query_pairs` drops empty
    parts;
  - the M6 trace records no siblings;
  - a form-body store request sends no siblings;
  - query builders in other items' files (§4.2);
  - a path point's PRG follow-up re-requests the placed path (flagged, §4.2).

**FR-CORE-501**, amended in place (title: *URL placement: a path segment or a query value;
`CC-CORE-0059`, `CC-CORE-0068`*). Its current text is kept, and this is added:

> `core.urls.QueryEntries` is the ordered list of a query's raw parts: split on `&` from
> `urlsplit`'s query, an empty query having none, empty parts kept, each name decoded with
> `surrogateescape` for matching only. `place_query_param(url, name, value)` puts
> `encode_query_value(value)` (`quote_plus`, `safe=""`) into the first part named `name`,
> or appends one part, and keeps every other part's text. `bind_query(url, entries, name,
> value)` is `with_query(url, FormEntries(entries).replace(name, value))`. `with_query`
> sets the query to the urlencoded entries. `place_route_query_param` places inside an SPA
> hash route's query (`%20`). This is the one placement (SP-42).

## 7. Shared primitives and architecture

**SP-42**, extended. The orchestrator updates the row at merge (`SHARED_PRIMITIVES.md` is a
shared doc).
- Mechanism: "Placing a value in its URL: a path segment, or a query value (standalone:
  the first occurrence in place; bound: the binder's rule)".
- Owner: `fuzzlab/core/urls.py::place_path_param`, with `place_query_param`, `bind_query`,
  `with_query`, `place_route_query_param`, `QueryEntries` and `encode_query_value`.
- Readers:
  - both probe senders;
  - greybox;
  - blind-sqli;
  - `browserexec`;
  - `harness.auto`;
  - `labels.contract`.
- Added guards:
  - `test_every_query_builder_goes_through_the_one_owner`;
  - `test_the_query_builder_guard_catches_synthetic_offenders`;
  - `test_the_query_builder_allow_list_has_no_stale_entry`;
  - `test_every_sender_places_a_query_occurrence_in_place`;
  - `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`.

**SP-20** (the sender protocol) gains the two conformance guards in its row.

**`docs/ARCHITECTURE.md` line**, drafted for the coordinator to add after `:1323` (the
FR-FUZZ-57/58 bullet that cites SP-42):

> - since FR-FUZZ-64 (CC-FUZZ-0106, CC-CORE-0068) every sender places a query value
>   through the same owner (`core.urls.place_query_param` / `bind_query` /
>   `place_route_query_param`, SP-42). A standalone URL gets the first occurrence of the
>   name in place, every other part kept with its raw text. Bound entries replace every
>   occurrence (the oracle's binder's rule, until AU-REQID8). The M6 executor places
>   through the same functions and loads a crawled DOM query point with its siblings
>   (`ExecRequest.entries`).

## 8. Draft change-control entries (pre-change gate; Effectiveness pending)

```
### CC-FUZZ-0106 — Every sender places a query value through one owner (BUG-0531) (2026-10-19)
- Change: `RequestsProbeSender`, `SeamProbeSender`, greybox `RequestsCorrelatingSender`,
  blind-sqli `RequestsSender`/`SeamSender` and `browserexec` (observe navigation, GET
  store step, `_with_fragment` as a wrapper) place query values through
  `core.urls.place_query_param` (standalone) / `bind_query` (bound) /
  `place_route_query_param`; greybox's bound branch no longer appends (`params=`);
  `RequestsProbeSender` keeps the probe's own URL for its PRG follow-up;
  `ExecRequest` gains `entries`, which `DomXssStrategy._observe` fills for a query point;
  `header_points_from_store` builds its query through `with_query` (same bytes);
  `tools/authhttp.with_query_param` / `with_query` are removed. Files:
  tools/probesender.py, greybox/run.py, tools/blind_sqli_fuzzer.py, tools/browserexec.py,
  oracle/browser.py, oracle/strategies.py (one line, after AU-OUTCOME), harness/auto.py,
  tools/authhttp.py (~70 LOC changed); tests ~500 LOC (§5). oracle/oracle.py and
  harness/pipeline.py are unchanged.
- Impact (other components / project): CORE (the owner, CC-CORE-0068). Contract change:
  `ExecRequest.entries` (writer `DomXssStrategy._observe`; readers
  `PlaywrightBrowserExecutor.run`, `FakeBrowserExecutor.run` (ignores), the M6 visit
  trace (records no siblings); 12 test files build `ExecRequest` and keep working with the
  default). Unchanged: the `Sender` protocol, `Candidate`, the binder, the store. Callers
  found by search (PA-0152): `with_query_param` (probesender, blind_sqli_fuzzer,
  tests/test_fuzzer_seam.py), `with_query` (probesender), `_with_fragment`
  (browserexec, tests/test_json_points.py). Overlap: strategies.py and oracle/* with
  AU-OUTCOME, which merges first.
- Risk: medium. The wire changes for any URL that already carries a query, for every
  crawled DOM query point with a link set, and for the GET store step (intended, measured
  on fixtures); scored ground truth is unchanged (0 of 157 rows carry a query; 0 bound DOM
  points). A live development-lab before/after needs owner authorisation (residual).
- Deliverables:
  - [ ] senders, executor, header points through the owner; PRG keeps the probe URL — todo
  - [ ] ExecRequest.entries and DomXssStrategy (after AU-OUTCOME merges) — todo
  - [ ] conformance on the prepared URL, the AST guard, the tests of §5 — todo
  - [ ] strict xfails removed, except the AU-REQID8 pin — todo
  - [ ] BUG-0531, PA-0531, ERROR_LOG, CHANGELOG (at merge) — todo
- Effectiveness (assessed after landing): pending.

### CC-CORE-0068 — One query placement: `QueryEntries`, `place_query_param`, `bind_query` (SP-42, FR-CORE-501) (2026-10-19)
- Change: `core/urls.py` gains `QueryEntries`, `encode_query_value`, `place_query_param`,
  `bind_query`, `place_route_query_param` and `with_query` (moved from
  tools/authhttp.py). No schema change; `core/forms.py` unchanged. (~110 LOC.)
- Impact: every caller in §3.3; SHARED_PRIMITIVES.md SP-42 row and ARCHITECTURE.md line
  (coordinator, at merge); FR-CORE-501 amended in place.
- Risk: low-medium (a new primitive; unit-tested over every part shape measured in §1.2;
  guarded).
- Deliverables: owner [ ] todo; unit tests [ ] todo; FR-CORE-501 [ ] todo.
- Effectiveness: pending.
```

## 9. Residual limits

1. **Two rules for a repeated name until AU-REQID8.** A standalone, operator-supplied URL
   with a repeated name now probes the first occurrence, so a last-value server (PHP
   without `[]`) may miss it. This is an accepted residual. The exposure is 0 of 157
   ground-truth rows, and AU-REQID8 resolves it. Bound entries keep replacing every
   occurrence.
2. **A stored link set's siblings are sent from their stored decoded values** (`flag` as
   `flag=`, `%20` as `+`), and `store_adapter.query_pairs` drops empty parts. AU-REQID8's
   importer fixes this.
3. **The M6 visit trace records no siblings.** It records the param and value only.
4. **Crawled DOM query points now load with their siblings.** That changes the wire for
   every such point. It was measured on fixtures and on ground truth (0 bound DOM points).
   A live development-lab before/after needs the owner's authorisation.
5. **A form-body store step sends no siblings.** Ground truth enumerates JSON store bodies
   only.
6. **Query builders in other items' files**, allow-listed with hand-offs (§4.2):
   - `disco/runner.py:262` (AU-OUTCOME);
   - `core/redaction.py`'s captured form dict and its URL redaction (AU-REDACT);
   - `store_adapter.py:274` (AU-REQID8);
   - `disco/synth` (defect 9);
   - `labgen/oracle_wrapper` (LAB);
   - `spa.query_url` (CRAWL).
7. **Greybox and M10.** Greybox points carry no siblings, and M10 cannot place a bound
   candidate (no verdict, never a negative). Both are unchanged.
8. **A path point's PRG follow-up re-requests the placed path** (measured; §4.2). This is
   an FR-FUZZ-49 question, flagged and not fixed here.

## 10. Bug record and preventive action (drafts)

**BUG-0531: each sender placed a query value differently** (audit defect 14).
- The RCA is §2.
- The corrective action is CC-FUZZ-0106 and CC-CORE-0068.

**Recurrence review.** The same root cause, one seam's implementations not in step, has
come before:

| Prior bug | Rule | What it kept in step |
|---|---|---|
| BUG-0039 | PA-0041 | transport settings |
| BUG-0044 | PA-0046 | redirects |
| BUG-0071 | PA-0072 | the signature |
| BUG-0115 | PA-0115 | placement by location |

A related rule: BUG-0110 / PA-0111, form serialisation rule by rule. `core.forms.RULES`
has "duplicates-kept-in-order", for forms only.

**Prior-preventive-action failure analysis.**
- PA-0115(2) checked placement "by discovery", but at **location granularity**. Its wire
  (`_Wire`) parses the query into a `dict`, and its probe URL has no query. The check
  could not observe an occurrence, a duplicate, order or raw text. It was not enforced at
  the level where the violation lives (cf. PA-0311(2)).
- PA-0041 and PA-0072 synchronise settings and signatures, not the request a sender
  builds.
- PA-0111's rule table covers `core.forms` serialisation. URL query mutation is a
  different code path, with no rule. Too narrow.

**Preventive action. PA-0531** strengthens PA-0115(2) and PA-0111:
1. A value placed in a URL, a query value or a path segment, is placed only through the
   one owner (SP-42).
   - An AST guard rejects every query-builder shape outside the owner (S1–S7, §3.5), with
     a reasoned allow-list that cannot go stale. It is proven on synthetic offenders of
     every shape.
   - Until AU-REQID8, a repeated name follows two stated rules: a standalone URL addresses
     the first occurrence; bound entries replace every occurrence (the binder's rule,
     through `bind_query`, for HTTP and the browser alike).
2. A placement check observes the raw request through the real client's own URL
   preparation, never a parsed `dict`. Senders that share a client are compared byte for
   byte. The check is shown to fail on a sender that appends and on one that collapses.
3. Senders on different clients (Chromium against requests) are compared under a relation
   measured on the real clients, pinned by a real-browser test, and proven not vacuous.

- Enforced by: `tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner`,
  `tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders`,
  `tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place`,
  `tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`,
  `tests/test_query_placement.py::test_platform_clients_rewrite_only_escapes_they_disagree_on`,
  `tests/test_query_placement.py::test_the_equivalence_still_tells_apart_what_a_server_reads_apart`

## 11. Size, merge order and open questions

**Size.** About 180 LOC of production code (owner ~110, senders and executor ~70) and about
500 LOC of tests. That fits one item.

**Merge order.**
1. AU-OUTCOME merges first.
2. Merge it into this branch.
3. Implement the `browser.py` and `strategies.py` parts on top of it.
4. Verify with `verify_change.py --full`.

**Open questions:**
- **Q1.** Should FR-CORE-501 be amended in place, or should the query placement get a new
  FR-CORE ID? The proposal is to amend in place, since SP-42 is the same primitive. No
  FR-CORE number was assigned.
- **Q2.** The path-point PRG follow-up (§4.2, residual 8) is a measured defect outside
  query placement. Should it be registered as its own bug and item?

## 12. Revision 2: changes keyed to the review

| Item | Change |
|---|---|
| **M1** (Q1: binder unchanged) | The binder is removed from §0, §3.3, §3.4, FR-FUZZ-64, PA-0531(1), the SP-42 readers and CC-FUZZ-0106's file list. `oracle/oracle.py` and `harness/pipeline.py` are untouched. `FormEntries.replace_at` and the body occurrence rule are dropped. `test_a_bound_duplicate_name_changes_one_occurrence_only` is re-pinned naming AU-REQID8. The two rules are stated in §0, §3.2, FR-FUZZ-64 and PA-0531. The accepted residual is residual 1, with its exposure measured: 0 of 157 rows |
| **M2** (Q3: shared bind-then-place) | `bind_query` is used by the senders' bound branch and the M6 executor. `ExecRequest.entries` is added, with its consumers named, and `DomXssStrategy` passes it. The conformance row M6 against bound HTTP with a duplicate name is added. `test_a_dom_query_point_is_loaded_with_its_siblings` becomes a positive test, and the old gap and its residual are dropped. The ground-truth exposure is measured (179 points, 8 bound, none at query or fragment; 5 DOM, none bound). The live run is a residual needing authorisation. A real-Chromium GET store-step row is added. Merge order as instructed |
| **M3** (guard shapes) | S1–S7 cover every listed shape, including subscript stores and their IfExp form, f-strings, `"&".join`, `.format`, `%`, an IfExp operand, `params=` on every send method and Playwright, tuple `urlunsplit`/`urlunparse` and `parse_qs`. It is proven on 21 offenders and 5 near-misses. The sweep (§4) is now the guard's own output on 8100959: the fix sites plus 41 allow-list entries, including every site you named and the newly found `core/trace`, `disco/fingerprint`, `header_point_estimate` and `spa.query_url`. A stale-entry test is added |
| **M4** (equivalence) | Bytes (`unquote_to_bytes`), hex upper-cased, and only the measured-to-move escapes decoded. `_CLIENT_FACTS` grows to 18 rows, with `;`/`%3B` and `%E9`/`%e9`. `differ` gains `%E9` vs `%EF%BF%BD`, `;` vs `%3B`, `/` vs `%2F`, `%20` vs `+` and empty parts. F1: HTTP is compared byte for byte; the relation is used for Chromium only |
| **M5** (cases) | pct20-sibling, empty-parts and pctE9-sibling are added, each failing on 8100959 for its stated reason (§1.1). The hard payload is checked against `quote_plus` for all 6 senders and M6. The decode-all wrong fix is proven to fail the cases |
| **M6** (PRG) | `wire` is a separate local, and `url` is kept for `_follow` (`:946`, `:964`/`:967`). Tests cover a fragment-only `Location` in 4 rows (the anonymous bound row fails today) and an empty `Location` in 2 rows. The sweep found the path branch's hazard (§4.2, flagged) |
| **M7** (old pins) | `test_greybox_live.py:397` and `test_json_points.py:744-754` are listed with their before and after (the wrapper kept), plus the `test_fuzzer_seam` pair and `_Wire` |
| **F1** | HTTP senders are compared byte for byte, and the seam's fake transport records the prepared URL |
| **F2** | The final `else` keeps placing `fragment` and unknown locations, so the BUG-0115 pin does not XPASS |
| **Spec details** | An empty query has zero parts; `urlsplit` is used, not `urlparse`; an empty `?`/`#` is dropped; names are counted with `surrogateescape`, with a test; residual 2 names `query_pairs`' dropped empty parts |
| **Chromium version** | 141.0.7390.37 (Playwright build 1194) is cited |
| **PA-0531(3)** | Its Enforced-by names both tests you requested |
| **FR-FUZZ-64** | Self-contained for this item |
| **ARCHITECTURE** | The line is drafted (§7) |
| **Labgen** | The strict xfail is removed. It is now a LAB hand-off with measured evidence (§4.2) |
| **M6 trace** | Stated as residual 3 |
