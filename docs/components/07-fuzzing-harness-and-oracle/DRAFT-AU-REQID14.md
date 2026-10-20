# DRAFT AU-REQID14: every sender places a query value through one owner

- Item: `AU-REQID14`, audit defect 14 only. Owner-supplied audit at 6552276, F-096.
- Status: **implemented, parts 1 and 2.** Part 1 (CC-FUZZ-0106 part 1, CC-CORE-0068):
  the owner, every sender's placement, the guard and the tests; merged (aafa642). Part 2
  (§14, on eb5eb4f after AU-OUTCOME merged): `ExecRequest.entries`, `DomXssStrategy`,
  the M6-vs-bound-HTTP row, and `spa.query_url` (CC-CRAWL-0053). §12 maps revision 2's must-fixes (M1–M7); §13 maps revision 3's
  blocking fixes (B1, B2) and adopted items. Where this record and the committed tests
  disagree, the tests are the truth (§4 is the guard's own output).
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
  - 179 built points, of which 8 are bound: 7 JSON leaves and 1 path account value.
    **None is at query or fragment.** The exact call (`gt_exposure.py`):
    `points_from_ground_truth(gt, "http://127.0.0.1:8080", browser_available=True,
    writes=True, account_values={"user_id": "7"})`. Reviewer A's 178 and 7 are the same
    call without `account_values`: the path account-value point is the one difference.
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
| `tools/browserexec.PlaywrightBrowserExecutor` | part 1: the observe navigation (`:552`) uses `place_query_param`; part 2 makes it `bind_query(url, request.entries, param, value)` when `entries` is given. The GET store step (`:539`) always uses `place_query_param`: a `StoreStep` has no entries. `_with_query` (`:25-29`) is removed. `_with_fragment` (`:32-48`) becomes a thin wrapper over `place_route_query_param` |
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

**M6 against HTTP (part 2, after AU-OUTCOME).** New `test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike`
sends a bound point with a repeated name through M6 (`ExecRequest.entries`) and through
`_FormBoundSender` over `RequestsProbeSender`. Both go through `bind_query`, and the two
wires must be equal under `canonical_pairs`.

### 3.5 The guard (M3, B1)

**`test_every_query_builder_goes_through_the_one_owner`** is an AST check over `fuzzlab/`,
excluding the owner `core/urls.py`. A finding is keyed by (module, enclosing function's
qualified name, shape), with a count, so it survives line moves; the module's own
statements are scope `<module>`. The shapes:

- **S1, `params` on a send:**
  - a keyword `params` on a call named `request`, `get`, `post`, `put`, `patch`,
    `delete`, `head`, `options`, `fetch` (Playwright) or `Request` (`requests.Request`);
  - a positional params: `requests.get(url, p)` (2+ positional arguments on
    `requests.get`), `x.request(method, url, p)` (3+), `requests.Request(m, u, h, f, d,
    p)` (6+).
- **S2, `params` reaching a send another way:**
  - a subscript store whose slice holds the constant `"params"`, the IfExp form
    included (`kwargs["data" if … else "params"] = …`);
  - a dict literal with a `"params"` key, or `dict(params=…)`, passed as `**` to a send;
  - the same assigned to a local name that the function passes as `**` to a send;
  - `.update(params=…)`, `.update({"params": …})` or `.setdefault("params", …)` on such
    a local name.
- **S3, a parse into a dict:** `dict(parse_qsl(...))`, `dict(parse_qs(...))`, or any
  `parse_qs(...)`.
- **S4, string building onto a query:** a `+` or `%` BinOp, a `+=`, an f-string or
  `.format`, holding a `?`/`&` string constant (keyword arguments excluded:
  `quote(s, safe="&")` is no query; an IfExp operand such as `("&" if … else "?")`
  included) and **query material**: a call to `urlencode`/`quote`/`quote_plus`, a
  `.query`, a `"&".join`, or (B1) **a local name the same scope assigned from one of
  those** (`q = urlencode(d)` … `u + "?" + q`).
- **S4b, a `[?&]name=` constant in a string build** (B1): the same build expressions,
  when one of their string constants matches `[?&][A-Za-z_][\w\[\]%.-]*=`
  (`u + "?id=" + v`, `f"{u}?id={v}"`, `"{}&page={}".format(…)`). A bare constant is not a
  builder and is not flagged: measured, the only bare ones in `fuzzlab/` are the 16
  descriptive strings of `tools/build_sql_db.py`'s catalog.
- **S5, a join on a query separator:** `"&".join(...)` or `"?".join(...)`.
- **S6, a rebuilt query or fragment:** `._replace(query=…)` or `._replace(fragment=…)`,
  and a `SplitResult`/`ParseResult` (and `…Bytes`) constructor.
- **S7, a tuple rebuild:** tuple-form `urlunsplit`/`urlunparse` whose query or fragment
  slot is neither `""` nor the unchanged `.query`/`.fragment`. So `strip_url` and
  `_no_query` do not match.

**Exact allow-list.** `ALLOWED` maps each allowed (module, function, shape) to its count
and its reason. `test_every_query_builder_goes_through_the_one_owner` fails on any finding
above its listed count (a new builder, or a second one in a listed function), and
**`test_the_query_builder_allow_list_has_no_stale_entry`** fails unless every listed
count is found exactly. Together they compare the scan to the list exactly.

**Proof on synthetic offenders.** `test_the_query_builder_guard_catches_synthetic_offenders`
runs the guard on **50 synthetic offenders**, one module each, and on **10 near-misses**
that must not match:
- offenders: `params=` on `get`/`put`/`patch`/`delete`/`head`/`options`,
  `requests.Request`, Playwright `fetch` and `get`; the three positional forms; the
  subscript store and its IfExp form; `**{"params": p}`, `**dict(params=p)`, a local
  literal and a local `dict(params=)` passed as `**`, `kw.update(params=)`,
  `kw.update({"params": …})`, `kw.setdefault("params", …)`; `dict(parse_qsl)`,
  `parse_qs`; concatenation with a quoter and with `.query`; an IfExp operand; an
  f-string, `.format` and `%` with a quoter; a local name from a quoter, from `.query`
  and from `"&".join`, each through `+`, an f-string, `.format`, `%` and `+=`; `?id=` and
  `&page=` through `+`, an f-string and `.format`; `"&".join`, `"?".join`;
  `._replace(query=)`, `._replace(fragment=)`; `SplitResult(...)`, `ParseResult(...)`;
  `urlunsplit` with a rebuilt query and with a rebuilt fragment, `urlunparse`; a
  module-level build;
- near-misses: `urlunsplit(…, "", "")`; `urlunsplit` with the query and fragment
  unchanged; `quote(s, safe="&=")`; a model's `{"params": w}`; `d.get(k, None)`;
  `d.get("params")`; `d.update(params=p)` on a dict never passed as `**`; a docstring
  holding `/p?id=1`; a `"?" in u` test beside a quoted local; a plain URL constant.

**The guard's limits** (what it does not see):
- query material that reaches a build through anything but a local name of the same
  scope: a parameter, an attribute (`self._q`), a name assigned in another function;
- a separator held in a variable (`sep.join(...)`), or a build through `"".join([...])`;
- a `params` dict that reaches `**` through an attribute or another function, and
  session-level `Session.params` (an attribute assignment; flagging it would match the
  `self.params` model attributes of `web/sitetree.py` and `tools/fetcher.py`);
- a new function given an allow-listed name in an allow-listed module.

## 4. The sweep (PA-0002, by mechanism; it is the guard's own output)

The guard run on `8100959` (`scan()` over its `fuzzlab/`) finds **57 builders under 54
keys**. Part 1 removed **12 under 11 keys** (§4.1), leaving 45 under 43. Since then
AU-OUTCOME fixed `disco/runner.py` `Runner.prepare` (CC-FUZZ-0105) and part 2 fixed
`tools/spa.py` `query_url` (CC-CRAWL-0053, §14): the allow-list is now **43 under 41
keys** (§4.2, those two rows struck), which the scan of the implemented tree equals exactly
(`test_every_query_builder_goes_through_the_one_owner` and
`test_the_query_builder_allow_list_has_no_stale_entry`).

### 4.1 Fixed by this item (the guard's findings that go away: 12 under 11 keys)

| Module · function | Shape (count) | Fix |
|---|---|---|
| `tools/authhttp.py` · `with_query_param` | S3 (1), S6 (1) | removed; the owner's `place_query_param` |
| `tools/authhttp.py` · `with_query` | S6 (1) | moved to the owner |
| `tools/probesender.py` · `RequestsProbeSender.send` | S2 `kwargs["params"]` (1) | `place_query_param` / `bind_query`; `url` kept for `_follow` |
| `greybox/run.py` · `RequestsCorrelatingSender.send_correlated` | S2 `kwargs["params"]` (2) | `place_query_param` / `bind_query` |
| `tools/blind_sqli_fuzzer.py` · `RequestsSender.get` | S1 (1) | `place_query_param` (and `SeamSender.get`, which called `with_query_param`) |
| `tools/browserexec.py` · `_with_query` | S4 (1), S7 (1) | removed: `place_query_param` |
| `tools/browserexec.py` · `_with_fragment` | S4 (1, the old `:45`, through the local `pair`), S7 (1) | thin wrapper over `place_route_query_param` |
| `harness/auto.py` · `header_points_from_store` | S4 (1) | `with_query` (same bytes) |

`SeamProbeSender._send_on`'s two branches called the removed helpers and had no shape of
their own; they now call `place_query_param` and `bind_query`.

### 4.2 Allow-listed (now 43 under 41 keys, each with its reason; none may go stale)

| Module · function | Shape (count) | Reason |
|---|---|---|
| `core/project.py` · `_ro_uri` | S4b (1) | a SQLite `file:` URI (`?mode=ro`), not HTTP |
| `core/store.py` · `_no_create_uri` | S4b (1) | a SQLite `file:` URI (`?mode=rw`), not HTTP |
| `core/redaction.py` · `redact_query`, `_redact_query_identifiers` | S5 (1 each) | storage redaction of a recorded URL, never sent. **AU-REDACT's file** |
| `core/redaction.py` · `redact_url`, `redact_url_identifiers` | S6 (1 each) | same |
| `core/trace.py` · `_blank_identifiers` | S5 (1) | trace redaction, never sent |
| `disco/fingerprint.py` · `normalise_route` | S4 (2), S5 (2) | a route key of parameter names, never sent. Covers `:83` (`route += "?" + "&".join(spa_names)`) |
| ~~`disco/runner.py` · `Runner.prepare`~~ | ~~S4 (1)~~ | fixed by AU-OUTCOME (CC-FUZZ-0105): `place_query_param`; the entry is removed and `test_the_contract_runner_places_a_query_value_in_place` is positive |
| `disco/synth.py` · `parse_body` | S3 (1) | defect 9's item: a schema from captured bodies, never sent |
| `harness/auto.py` · `header_point_estimate` | S4 (1) | a SQLite `file:` URI (`?mode=ro`), not HTTP |
| `lab_fixtures/external.py` · `_bwapp_install`, `_ecommerce_login` | S1 (1 each) | lab provisioning with constant parameters, not probing |
| `labgen/conformance/django_live_boot.py` · `DjangoLiveBootHarness.get` (S1), `.request` (S4) | 1 each | a harness client of generated cells, on query-less paths |
| `labgen/conformance/live_boot.py` · `LiveBootHarness.fetch`, `.get` (S1), `.request` (S4) | 1 each | same |
| `labgen/conformance/live_boot_spring_boot.py` · `SpringBootLiveBootHarness.get` (S1), `.request` (S4) | 1 each | same |
| `labgen/conformance/rails_live_boot.py` · `RailsLiveBootHarness.fetch`, `.get` (S1), `.request` (S4) | 1 each | same |
| `labgen/conformance/tier2.py` · `LiveBootTier2Oracle._fetch` | S1 (1) | same |
| `labgen/identifier_sqli_oracle.py` · `_build_url` | S4 (1) | its input is a mapping, so a duplicate cannot be expressed; generated cells declare none |
| `labgen/oracle_wrapper.py` · `_mark_query_param` | S6 (1) | **LAB**: re-encodes untouched pairs. Pinned: `test_the_labgen_tool_wrapper_keeps_untouched_pairs_as_written` |
| `oracle/strategies.py` · `OpenRedirectStrategy.confirm` | S4b (1, `:784`) | an open-redirect canary URL (`https://<host>/cb?fzlb=<seed>`): the payload value itself, placed by the owner like any value. AU-OUTCOME's file |
| `proxy/server.py` · `target_from_request` | S4 (1) | the proxy forwards the client's own query verbatim |
| `report/diagram.py` · `finding_deep_link` | S4b (1, `:318`) | an in-app link (`/diagrams?run=&finding=`, integer ids), not traffic to a target |
| `tools/spa.py` · `visit_key` | S4 (1), S6 (1) | the crawler's dedup key, never sent (S6: it drops an origin-less URL's fragment) |
| ~~`tools/spa.py` · `query_url`~~ | ~~S5 (1)~~ | fixed by part 2 (CC-CRAWL-0053): `core.urls.place_route_query_pairs`; the entry is removed and `test_the_spa_seed_builder_places_its_route_query_in_place` is positive |
| `tools/spider.py` · `LocalSpider._isolated_submit` | S4 (1), S1 (1) | a GET form submission replaces the action's query by its entries, as a browser does (PA-0111) |
| `tools/store_adapter.py` · `_import_forms` | S4 (1, `:634`) | a stored endpoint key keeps the POST action's query verbatim |
| `tools/store_adapter.py` · `_store_request` | S4 (1) | a stored endpoint key keeps the request's query verbatim, never sent as built |
| `tools/store_adapter.py` · `import_disco` | S3 (1) | **AU-REQID8** (the importer): a captured form body's repeated name collapses (`:274`). Pinned: `test_a_disco_form_body_keeps_a_repeated_name_in_order` |
| `web/app.py` · `create_app.repeater_from_finding_prg`, `create_app.repeater_from_flow_prg` | S3 (1 each), S4b (1 each, `:635`, `:1126`) | the operator's own UI form post, and an in-app redirect (`/proxy?repeater_tab=<id>`); not traffic to a target |
| `web/projectroutes.py` · `_form` | S3 (1) | the operator's own UI form post, not traffic to a target |

The reviewer's list for B1 is covered: `tools/store_adapter.py:634`,
`oracle/strategies.py:784`, `report/diagram.py:318`, `web/app.py:635`,
`web/app.py:1126`, `core/project.py:117` and `core/store.py:33` are the S4b/S4 rows
above; the rule set also finds `tools/spa.py` `visit_key`'s `_replace(fragment="")` (S6).
`disco/fingerprint.py:83` is one of `normalise_route`'s S4 and S5 findings, and
`browserexec.py:45` was `_with_fragment`'s S4 (through the local `pair`), gone with the fix.

**Not builders, so the guard does not match them:** `session/detect.py` (set comparison),
`session/browserlogin.strip_url` and `session/state._no_query` (`""` slots),
`tools/observe.py`, `ml/flow_anomaly.py`, `tools/fetcher.py:517` (names), the
`{"params": …}` model and history dicts (`ml/persist.py`, `ml/ranker.py`,
`proxy/history.py`, `tools/observe.py`, `web/sitetree.py`), and `tools/build_sql_db.py`'s
bare descriptive constants.

**Known instances owned elsewhere: offline strict xfails naming the owner (B2,
PA-0054(3), PA-0115(3)).** Each fails today for its stated reason (measured with
`--runxfail`, §13):

| Pin | Owner | Fails with |
|---|---|---|
| `test_the_contract_runner_places_a_query_value_in_place` | AU-OUTCOME (`disco/runner.py:262`) | `op=list&q=1&q=zqmark`, not `op=list&q=zqmark`. **Now positive** (CC-FUZZ-0105) |
| `test_the_spa_seed_builder_places_its_route_query_in_place` | CRAWL (`tools/spa.py:1812-1821`) | `#/s?q=1&p=2&q=x y`, not `#/s?q=x%20y&p=2`. **Now positive** (CC-CRAWL-0053) |
| `test_a_stored_link_set_round_trips_its_crawled_query` | AU-REQID8 (residual 2: `query_pairs` drops empty parts and `=` presence) | `flag` comes back as `flag=`, the empty part is gone, `%20` is `+` |
| `test_a_disco_form_body_keeps_a_repeated_name_in_order` | AU-REQID8 (`store_adapter.py:274`) | `['tag', 'q']`, not `['tag', 'tag', 'q']` |
| `test_the_labgen_tool_wrapper_keeps_untouched_pairs_as_written` | LAB | `flag` → `flag=`, `%20` → `+` on the untouched pairs only (marking every occurrence is not pinned) |
| `test_a_path_points_prg_follow_up_never_carries_the_payload[#top/edit × anonymous/seam]` | AU-PRGPATH | the follow-up requests `/p/zqmark/view` (`#top`) and `/p/zqmark/edit` (relative `edit`) |
| `test_a_bound_duplicate_name_changes_one_occurrence_only` | AU-REQID8 | the binder sends `tag=zqmark&tag=zqmark` |
| `test_a_dom_query_point_is_loaded_with_its_siblings` | this item's part 2 (after AU-OUTCOME) | `/p?q=<payload>` alone, no `op`. **Now positive** (part 2) |

## 5. Tests: mechanism, and the revert each must fail against (PA-0034(2))

**Mechanisms.**
- **Echo (end to end).** `tests/test_query_placement.py::_Echo` is a loopback HTTP server
  the test starts (`require_loopback`); it records each request's raw target. The HTTP
  senders are the real ones over a real `requests.Session` or a real `HttpClient`
  transport; their query is compared **byte for byte** with `_prepared(want)` (requests'
  own `prepare` of the contract's query). With `redirect` set it answers
  `302 Location: <x>` for a request carrying the mark (the PRG rows).
- **Real Chromium.** M6 runs `PlaywrightBrowserExecutor` in Chromium 141.0.7390.37
  against the echo server; `FUZZLAB_REQUIRE_BROWSER=1` makes a missing browser fail, not
  skip. Its query is compared under `canonical_pairs` (the measured relation).
- **Pure functions.** The owner's unit tests, the relation's tests, the wrong-fix proof
  (a synthetic decode-all-reencode function through the cases).
- **Offline fakes.** `tests/test_sender_conformance.py::_Wire` records, for a
  requests-style send, `requests.Request(method, url, params=…).prepare().url`, and for
  the seam transport the URL it is handed; offline, no socket.
- **AST.** The guard parses every module of `fuzzlab/`.
- **Offline pins.** The known instances in other items' code are called directly
  (`Runner.prepare`, `spa.query_url`, `store_adapter.query_pairs`/`import_disco`,
  `oracle_wrapper._mark_query_param`), as strict xfails naming the owner.

**Tests and their mechanism.**

| Test | Mechanism |
|---|---|
| `test_platform_clients_rewrite_only_escapes_they_disagree_on` | echo + real requests + real Chromium (18 queries) |
| `test_the_equivalence_still_tells_apart_what_a_server_reads_apart` | pure |
| `test_the_owner_places_the_first_occurrence_and_keeps_raw_text` ×15, `test_the_owner_encodes_a_payload_as_quote_plus`, `test_name_matching_never_merges_an_invalid_escape_with_its_replacement`, `test_bind_query_follows_the_binders_rule_and_adds_nothing_to_bound_entries` | pure (the owner) |
| `test_every_sender_replaces_the_addressed_occurrence_in_place` (6 senders × 8 cases) | echo, bytes |
| `test_control_a_query_less_url_gets_the_pair`, `test_a_hard_payload_on_a_query_less_url_is_quote_plus_encoded` ×6 | echo, bytes |
| `test_the_cases_catch_the_decode_all_reencode_fix` | echo + a synthetic wrong owner |
| `test_the_anonymous_and_authenticated_senders_send_the_same_query` | echo, bytes |
| `test_a_bound_entry_list_is_sent_by_the_binders_rule` ×2 | echo, through `_FormBoundSender` |
| `test_a_fragment_only_location_is_followed_without_the_payload` ×4, `test_an_empty_location_is_not_followed` ×2 | echo in redirect mode |
| `test_the_browser_executor_replaces_the_addressed_occurrence_in_place` ×8, `test_the_browser_sends_a_hard_payload_on_a_query_less_url_as_quote_plus`, `test_the_browser_get_store_step_replaces_the_addressed_occurrence_in_place` | echo + real Chromium |
| `test_every_query_builder_goes_through_the_one_owner`, `test_the_query_builder_allow_list_has_no_stale_entry`, `test_the_query_builder_guard_catches_synthetic_offenders` | AST |
| `tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place` ×5 (both probe senders, greybox, both blind-sqli) | offline `_Wire`, bytes; cases: the name repeated, a missing `=` + empty part + `%20`, and unbound entries with a repeated name |
| `tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender` | offline, synthetic offenders |
| `tests/test_json_points.py::test_the_executor_places_a_fragment_inside_the_hash_route` (extended: `#/s?q=old&page=2` → `#/s?q=M&page=2`) | fake Playwright + `_with_fragment` |
| Updated old pins: `tests/test_greybox_live.py::test_requests_correlating_sender_sets_header`, `tests/test_fuzzer_seam.py::test_place_query_param`, `…::test_requests_sender_unchanged_standalone_behavior`, `tests/test_probesender.py::test_requests_probe_sender_never_follows_redirects` | fake session: the URL carries the pair, `params` is None |
| Pins (strict xfail; §4.2 table) | echo / real Chromium / offline, as listed there |

**Per-revert proof** (`scratchpad/aureqid/revert_proof.py`, results in
`revert_proof.json` and `revert_proof_bind.json`). Each set put the `8100959` version of
the named files, or a named mutation, into the tree of `ed16e6c`, ran the listed test files
in one pytest (`-n 4`, `FUZZLAB_REQUIRE_BROWSER=1`), and restored the files from HEAD
(`git status` clean after):

| Revert / mutation | Fails |
|---|---|
| `probesender.py` + `authhttp.py` → 8100959 (28 failed) | the 8 cases × `probe-anonymous`; 7 cases × `probe-seam` and × `probe-seam-identity` (the seam's blank case held on the base too); anonymous-vs-seam bytes; the bound anonymous fragment-only PRG row; the guard; conformance rows `RequestsProbeSender` and `SeamProbeSender`; `test_requests_probe_sender_never_follows_redirects` |
| `greybox/run.py` → 8100959 (11) | the 8 cases × `greybox`; the guard; conformance `greybox`; `test_requests_correlating_sender_sets_header` |
| `blind_sqli_fuzzer.py` + `authhttp.py` → 8100959 (19) | 8 cases × `blind-sqli-anonymous` and 7 × `blind-sqli-seam`; the guard; conformance rows `blind-sqli-anonymous` and `blind-sqli-seam`; `test_requests_sender_unchanged_standalone_behavior` |
| `browserexec.py` → 8100959 (11) | the 8 browser cases; the GET store step; the guard; `test_the_executor_places_a_fragment_inside_the_hash_route` |
| `harness/auto.py` → 8100959 (1) | the guard only: the change is byte-identical (`with_query` is `urlencode`), so only the builder shape can tell |
| `RequestsProbeSender` follows `wire` instead of `url` (2) | `test_a_fragment_only_location_is_followed_without_the_payload[standalone-anonymous, bound-anonymous]` |
| owner: `QueryEntries.parse` drops empty parts (13) | the owner's empty-parts case; `empty-parts` × 6 senders and in Chromium; all 5 conformance rows |
| owner: names matched with `errors="replace"` (1) | `test_name_matching_never_merges_an_invalid_escape_with_its_replacement` |
| owner: standalone replaces every occurrence (21) | the owner's two repeated-name cases; `dup-sibling` and `encoded-name` × 6 senders and in Chromium; all 5 conformance rows |
| owner: `quote` instead of `quote_plus` (8) | `test_the_owner_encodes_a_payload_as_quote_plus`; the hard payload × 6 senders and in Chromium |
| owner: `bind_query` replaces the first occurrence only (4) | `test_bind_query_follows_the_binders_rule_and_adds_nothing_to_bound_entries`; conformance rows `RequestsProbeSender`, `SeamProbeSender`, `greybox` (the bound case's unbound repeated name) |

The guard's own proof is `test_the_query_builder_guard_catches_synthetic_offenders`
(50 offenders flagged, 10 near-misses not), and `test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`
is the conformance check's.

## 6. Requirement text (written in place at implementation)

- **FR-FUZZ-64** is in `docs/components/07-fuzzing-harness-and-oracle/requirements.md`,
  self-contained for this item (AU-REQID8 takes a new ID). Its "Not yet" bullet is
  part 2 (the DOM point's siblings).
- **FR-CORE-501** is amended in place in `docs/components/02-core-library/requirements.md`
  (title: *URL placement: a path segment or a query value*).

## 7. Shared primitives and architecture (shared docs: the coordinator writes them)

**SP-42 row, replacement text for `docs/SHARED_PRIMITIVES.md`** (the guard parses the
first `fuzzlab/…::name` of the owner cell; `place_path_param` stays first, and every
other owner name is defined only in `core/urls.py`, checked by search):

```
| SP-42 | Placing a value in its URL: a path-segment value in its template (`/ticket/{id}`: the one segment replaced, percent-encoded, or refused), or a query value (standalone: the first occurrence of the name in place, every other raw part kept; bound entries: the binder's rule, every occurrence; an SPA hash route's query) | `fuzzlab/core/urls.py::place_path_param`, with `place_query_param`, `bind_query`, `with_query`, `place_route_query_param`, `QueryEntries` and `encode_query_value` in the same module (read by both probe senders, greybox, both blind-sqli senders, `browserexec`, `harness.auto` and `labels.contract`) | `tests/test_sender_conformance.py::test_every_sender_places_a_path_value_in_its_segment`, `tests/test_sender_conformance.py::test_the_path_check_catches_a_sender_that_queries_it`, `tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place`, `tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender`, `tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner`, `tests/test_query_placement.py::test_the_query_builder_allow_list_has_no_stale_entry`, `tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0003, PA-0115, PA-0531 (CC-CORE-0059, CC-CORE-0068) |
```

**`docs/ARCHITECTURE.md` line**, for the coordinator to add after the FR-FUZZ-57/58
bullet that cites SP-42 (`:1323` at 8100959):

> - since FR-FUZZ-64 (CC-FUZZ-0106, CC-CORE-0068) every sender places a query value
>   through the same owner (`core.urls.place_query_param` / `bind_query` /
>   `place_route_query_param`, SP-42): both probe senders, greybox, both blind-sqli
>   senders and the M6 executor. A standalone URL gets the first occurrence of the name
>   in place, every other part kept with its raw text; bound entries replace every
>   occurrence (the oracle's binder's rule, until AU-REQID8). An AST guard keeps query
>   building in `core.urls` (`tests/test_query_placement.py`).

(When part 2 lands, the line gains: "The M6 executor loads a crawled DOM query point with
its siblings (`ExecRequest.entries`).")

## 8. Change-control entries (written at implementation)

CC-FUZZ-0106 (part 1 done, part 2 held) is at the top of
`docs/components/07-fuzzing-harness-and-oracle/change-control.md`; CC-CORE-0068 at the top
of `docs/components/02-core-library/change-control.md`.

## 9. Residual limits

1. **Two rules for a repeated name until AU-REQID8.** A standalone, operator-supplied URL
   with a repeated name probes the first occurrence, so a last-value server (PHP without
   `[]`) may miss it. Exposure: 0 of 157 ground-truth rows. Bound entries keep replacing
   every occurrence. Pinned: `test_a_bound_duplicate_name_changes_one_occurrence_only`
   (AU-REQID8).
2. **A stored link set's siblings are sent from their stored decoded values** (`flag` as
   `flag=`, `%20` as `+`), and `store_adapter.query_pairs` drops empty parts. Pinned:
   `test_a_stored_link_set_round_trips_its_crawled_query` (AU-REQID8).
3. **A non-UTF-8 query name never matches its own occurrence.** The store decodes names
   with `unquote_plus`'s default `errors="replace"` (`store_adapter.query_pairs`), while
   the owner matches with `surrogateescape` (so `n%E9` and `n%EF%BF%BD` stay two names,
   as a server reads them). Measured: `place_query_param("…?n%E9=1&a=2", "n�", "M")`
   appends `n%EF%BF%BD=M`; the bound rule sends `n%EF%BF%BD=M&a=2`. AU-REQID8's importer.
4. **The M6 visit trace records no siblings.** It records the param and value only.
5. **The M6 GET store step is always standalone**: a `StoreStep` carries no query
   siblings (its `entries` are a JSON store body's leaves), so it uses
   `place_query_param` on its own URL. A form-body store request sends no
   siblings. Ground truth enumerates JSON store bodies only.
6. **Crawled DOM query points now load with their siblings** (part 2;
   `test_a_dom_query_point_is_loaded_with_its_siblings` positive). The wire changes for
   every such point; measured on fixtures and ground truth (0 bound DOM points). A live
   development-lab before/after needs the owner's authorisation (D11).
7. **Query builders in other items' code**, each pinned by an offline strict xfail naming
   its owner (§4.2): `store_adapter.py:274` (AU-REQID8), `labgen/oracle_wrapper` (LAB).
   (`disco/runner.py:262` was fixed by AU-OUTCOME, `tools/spa.py` `query_url` by part 2.) `core/redaction.py` and `disco/synth` are allow-listed, never sent.
8. **Greybox and M10.** Greybox points carry no siblings, and M10 cannot place a bound
   candidate (no verdict, never a negative). Both are unchanged.
9. **A path point's PRG follow-up re-requests the placed path** (AU-PRGPATH; pinned, not
   fixed here). It is broader than `#top`: a relative `Location: edit` requests
   `/p/zqmark/edit`.

## 10. Bug record and preventive action

`docs/bugs/BUG-0531-each-sender-placed-a-query-value-differently.md` holds the RCA, the
recurrence review (BUG-0039/PA-0041, BUG-0044/PA-0046, BUG-0071/PA-0072,
BUG-0115/PA-0115, BUG-0110/PA-0111, BUG-0311/PA-0311(2)) and the prior-preventive-action
failure analysis.

**PA-0531**, exact text for `docs/PREVENTIVE_ACTIONS.md` (B1: (1) states what the guard
does, and its limits):

```
- **PA-0531** — Strengthens `PA-0115(2)`/`(3)` and `PA-0111`, after BUG-0531: each sender
  placed a query value its own way (an appended second pair; a `dict` rebuild that lost
  duplicates and rewrote siblings), and PA-0115's conformance check read the query as a
  `dict` on a query-less URL, so it could not see an occurrence.
  1. **A value placed in a URL's query goes through the one owner** (`core.urls`, SP-42):
     `place_query_param` for a standalone URL, `bind_query` for bound entries,
     `place_route_query_param` for an SPA hash route. An AST guard over `fuzzlab/` (the
     owner excluded) flags: `params` reaching a send (a keyword; a positional; a
     `"params"` key or `dict(params=…)` passed as `**`, directly or through a local;
     `.update`/`.setdefault` adding it to such a local); a subscript store into
     `"params"`; `dict(parse_qsl/parse_qs)` and `parse_qs`; a string build (`+`, `%`,
     `+=`, f-string, `.format`) holding a `?`/`&` constant and query material (a quoter,
     `.query`, `"&".join`, or a local name the same scope assigned from one), or holding
     a `[?&]name=` constant; `"&".join`/`"?".join`; `._replace(query=…|fragment=…)`;
     `SplitResult`/`ParseResult(...)`; a tuple `urlunsplit`/`urlunparse` rebuilding the
     query or fragment. Every finding outside the owner is on an allow-list with its
     count and its reason, compared exactly (a new builder and a stale entry both fail).
     The guard is proven on 50 synthetic offenders and 10 near-misses.
  2. **A placement check observes the raw request through the real client's own URL
     preparation, never a parsed `dict`,** on a probe URL that already carries the name,
     a missing `=`, an empty part and a raw escape. Senders that share a client are
     compared byte for byte, and the check is shown to fail on an appending and on a
     collapsing sender.
  3. **Senders on different clients (Chromium against `requests`) are compared under a
     relation measured on the real clients,** pinned by a real-browser test that fails
     when a client's rewriting changes, and proven not vacuous on pairs a server reads
     apart.
  4. **A known unfixed instance in another item's code is pinned in the same change by an
     offline strict xfail naming its owner** (`PA-0054(3)`), never a prose deferral.
  - The guard's limits: it does not see query material reaching a build through a
    parameter, an attribute or another function's name; a separator held in a variable,
    or a `"".join([...])` build; a `params` dict reaching `**` through an attribute or
    another function; session-level `Session.params`; or a new function given an
    allow-listed name in an allow-listed module. (from BUG-0531)
  - Enforced by: tests/test_query_placement.py::test_every_query_builder_goes_through_the_one_owner, tests/test_query_placement.py::test_the_query_builder_allow_list_has_no_stale_entry, tests/test_query_placement.py::test_the_query_builder_guard_catches_synthetic_offenders, tests/test_sender_conformance.py::test_every_sender_places_a_query_occurrence_in_place, tests/test_sender_conformance.py::test_the_occurrence_check_catches_an_appending_and_a_collapsing_sender, tests/test_query_placement.py::test_platform_clients_rewrite_only_escapes_they_disagree_on, tests/test_query_placement.py::test_the_equivalence_still_tells_apart_what_a_server_reads_apart
```

## 11. Size, merge order and open questions

**Size (part 1).** Production: about 90 LOC in the owner and about 75 changed across
seven files (`git diff --stat 7820bcd`). Tests: about 800 LOC changed (most in
`tests/test_query_placement.py`).

**Merge order.**
1. AU-OUTCOME merges first. `tools/probesender.py` is shared: AU-OUTCOME's edits are at
   the base's lines 206-207, 857-861, 993 and 1000; this item's hunks are at 20-27,
   792-794, 822, 939-946 and 964-965.
2. This branch merges (part 1). The guard allow-lists `disco/runner.py`
   `Runner.prepare` and `oracle/strategies.py` `OpenRedirectStrategy.confirm`; if
   AU-OUTCOME's merge moves or removes one of those builders, the stale-entry test fails
   by design and the entry is updated at merge.
3. Part 2 on top of AU-OUTCOME, then `verify_change.py --full`.

**Open questions:** Q1 (FR-CORE-501 amended in place) and Q2 (the path-point PRG defect:
its own item, AU-PRGPATH) are resolved. None open.

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

## 13. Revision 3: the blocking fixes, the adopted items, and part 1 implemented

| Item | Change |
|---|---|
| **B1** (the guard missed 16 likely shapes) | Two rules added: a local name assigned from a quoter, from `.query` or from `"&".join` is query material (S4); a `[?&]name=` constant in a string build is flagged (S4b; a bare constant is not a builder: measured, the only ones are `tools/build_sql_db.py`'s 16 descriptive strings). `"params"` as a dict key is flagged when the dict reaches `**` of a send, directly or through a local, and so are `dict(params=…)`, `kw.update(params=…)`/`({"params": …})`, `kw.setdefault("params", …)` and a positional params (`requests.get(url, p)`, `s.request(m, u, p)`, `requests.Request(…, p)`). S6 also flags `._replace(fragment=…)` and `SplitResult`/`ParseResult(...)`. One synthetic offender per new shape: 50 offenders in all, 10 near-misses. The reviewer's sites are allow-listed with reasons (`store_adapter.py:634`, `strategies.py:784`, `diagram.py:318`, `app.py:635`, `app.py:1126`, `project.py:117`, `store.py:33`), plus `spa.visit_key`'s S6; `fingerprint.py:83` is covered and `browserexec.py:45` is fixed (§4.2). §4 is the guard's output, compared exactly (57 on the base; 12 fixed; 45 allowed under 43 keys), and PA-0531(1) now states what the guard flags and its limits (§10) |
| **B2** (prose deferrals) | Each known unfixed instance is an offline strict xfail naming its owner, failing today for its stated reason (§4.2 table): `disco/runner.py:262` (AU-OUTCOME), `tools/spa.py` `query_url` (CRAWL, **to be registered by the coordinator**), residual 2 `query_pairs` (AU-REQID8), `store_adapter.py:274` (AU-REQID8), labgen's re-encoding of untouched pairs only (LAB) |
| **ADOPT: exact counts** | `test_every_query_builder_goes_through_the_one_owner` (no finding above its count) and `test_the_query_builder_allow_list_has_no_stale_entry` (every count found exactly) |
| **ADOPT: S6** | `._replace(fragment=…)` and the `SplitResult`/`ParseResult` constructors (offenders `_replace fragment`, `SplitResult`, `ParseResult`) |
| **ADOPT: M6 GET store step** | Always `place_query_param`: `StoreStep` has no entries (§3.3, residual 5, FR-FUZZ-64) |
| **ADOPT: non-UTF-8 names** | Residual 3, measured: the store decodes with `errors="replace"`, so the stored name never matches the URL's raw occurrence |
| **ADOPT: 179/8 vs 178/7** | The exact `points_from_ground_truth` call is in §1.3; 178/7 is the same call without `account_values` |
| **ADOPT: AU-PRGPATH** | Not fixed here. `test_a_path_points_prg_follow_up_never_carries_the_payload` is a strict xfail naming AU-PRGPATH over `#top` and a relative `edit`, for both probe senders |
| **Implemented now** | `core/urls.py`; every sender's placement; the guard; the tests; CC-FUZZ-0106 (part 1), CC-CORE-0068, FR-FUZZ-64, FR-CORE-501, BUG-0531 |
| **Held (Q3)** | `ExecRequest.entries`, `DomXssStrategy._observe`, the executor's `bind_query` with entries, the M6-vs-bound-HTTP row, and unpinning `test_a_dom_query_point_is_loaded_with_its_siblings`, after AU-OUTCOME merges |

## 14. Part 2 (on eb5eb4f, after AU-OUTCOME merged)

**What changed** (commit 74d42d5; CC-FUZZ-0106 part 2, CC-CRAWL-0053, CC-CORE-0068's
part 2 addition):
- `oracle/browser.py`: `ExecRequest.entries` (a query point's bound sibling entries).
- `oracle/strategies.py`: `DomXssStrategy._observe` passes the candidate's non-empty
  `base_entries` for a query point, which is the same truthiness test the oracle uses
  to wrap the HTTP sender in `_FormBoundSender`. A fragment point gets nothing. The M6
  load is an observation, not a control: it does not go through AU-OUTCOME's
  `_compared`, and `require_observed` (the HTTP sender chain) does not apply to it.
- `tools/browserexec.py`: the observe navigation is `bind_query(url, entries, param,
  value)` when `entries` is given, else `place_query_param`; fragment unchanged. The GET
  store step stays standalone: a `StoreStep`'s `entries` are a JSON store body's leaves,
  not query siblings (this corrects the part 1 wording "a `StoreStep` has no entries").
- `core/urls.py`: `encode_route_value` and `place_route_query_pairs(url, pairs,
  encode)`: each pair by the standalone rule in the route's query (the fragment's own
  query in hash mode, the URL's own query in history mode). `place_route_query_param`'s
  route branch calls it, with the same bytes.
- `tools/spa.py` (CC-CRAWL-0053, option (a)): `query_url` calls
  `place_route_query_pairs` with `seed_value` = `quote(text, safe="/")`, so a
  redirect-type name's `/` stays `/` in both modes. FR-CRAWL-17's safety test, which
  pins `redirectUrl=/`, is unchanged. Names are identifier-shaped, markers are letters
  and the filler is `fuzzlab`, so no other byte changes today. The fix is in-place
  replacement on a route that already has the name.
- Guard: the allow-list is 43 findings under 41 keys (`Runner.prepare` was removed by
  AU-OUTCOME, `spa.query_url` by this part).

**Tests and mechanism:**

| Test | Mechanism |
|---|---|
| `test_a_dom_query_point_is_loaded_with_its_siblings` (unpinned) | echo + real Chromium, through `DomXssStrategy` |
| `test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike` (new) | echo + real Chromium vs `_FormBoundSender` over `RequestsProbeSender`; equal under `canonical_pairs` and equal to `id=1&tag=M&tag=M` |
| `test_dom_xss_hands_the_executor_a_query_points_link_set` ×4 (new) | offline recording executor: query with entries, query with none, query with `()`, fragment |
| `test_the_spa_seed_builder_places_its_route_query_in_place` ×8 (was the CRAWL strict xfail) | pure, `spa.query_url` |
| `test_a_seeds_redirect_type_value_stays_a_same_origin_path_in_both_modes` ×2 (new, the unit row asked for) | pure, `spa.seed_url`, hash and history mode |
| `test_the_route_query_owner_places_each_pair_by_the_standalone_rule` ×3 (new) | pure, the owner |

**Per-revert proof** (`scratchpad/aureqid/revert_proof2.py`, results in
`revert_proof2.json`). Each set mutated the committed 74d42d5 tree, or put back a file's
eb5eb4f version. It ran `tests/test_query_placement.py`, `tests/test_spa_query.py` and
`tests/test_json_points.py` in one pytest (`-n 4`, `FUZZLAB_REQUIRE_BROWSER=1`, after
waiting for an idle host), then restored the files; `git status` was clean afterwards.

| Revert / mutation | Failed | What failed |
|---|---|---|
| `DomXssStrategy` passes no entries | 2 | the DOM siblings test, and the "query with entries" row of `test_dom_xss_hands_the_executor_a_query_points_link_set` |
| the executor ignores `ExecRequest.entries` | 2 | the DOM siblings test, and `test_the_browser_and_the_bound_http_sender_place_a_duplicate_name_alike` |
| `spa.py` back to eb5eb4f | 8 | 5 of the 8 seed-builder rows (the three that hold append to a route without the name, as before), both `/` rows, and the guard (`query_url`'s S5 is back) |
| the seed encoder encodes `/` | 7 | the two `/` rows of the seed builder, both `/` rows, and 3 tests in `tests/test_spa_query.py`: `test_a_seed_gets_the_filler_and_a_redirect_name_gets_a_same_origin_path` (FR-CRAWL-17's safety test), `test_paired_seeds_are_visited_after_their_bare_route_as_fragment_points` and `test_a_destructive_seed_is_never_visited_and_a_redirect_name_stays_on_origin` |
| the owner appends instead of replacing | 10 | 5 seed-builder rows, both `/` rows, 2 route-owner rows, and `test_the_executor_places_a_fragment_inside_the_hash_route` |
