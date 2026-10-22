# BUG-0555 — FR-AUD-20's lab predicate admitted every value a recogniser of hosts missed: a loopback authority it did not recognise kept an outside tail, and a bare outside host with an unlisted TLD was sent

- Date: 2026-10-22
- Status: fixed (CC-AUD-0058, FR-AUD-20 amended in place; SP-73's owner), with one
  neighbouring residual pinned for FUZZ (below)
- Severity: high. A value naming a host outside the lab was sent to the lab app as a
  sibling, and bound fresh from a page, verbatim (D11's lab-only rule; FR-AUD-20). The
  same predicate gates all three senders of app-supplied values:
  `harness.auto._send_value`, `harness.auto._outside_lab` and
  `oracle._FormBoundSender._bind_fresh`.

## Description
`audit/value_shape.py::names_outside_lab` (SP-73) decides whether an app-supplied value
may be sent (FR-AUD-20, amended by FR-FUZZ-67). BUG-0544's three review rounds made its
proof an allow-list: a loopback authority with a numeric port, and a path, query and
fragment in the safe tail grammar (`_tail_in_grammar`). But the proof ran only behind a
gate:

```python
if not isinstance(value, str) or neutral_value(value) == value:
    return False
return not _names_only_lab(value)
```

`neutral_value` is the stand-in chooser, and it decides with a recogniser: it replaces a
value only when it contains `://`, starts with `//`, or `value_shape` reads the value,
or its prefix up to the first `/` or `:` (`_host_prefix`), as an `ip` or a `hostname`.
`value_shape`'s `hostname` needs a two-letter TLD or one of the closed `GENERIC_TLDS`;
its `ip` is Python's `ipaddress`, which refuses every short, integer, hex, octal or
trailing-dot spelling. Whatever that recogniser missed returned False (the lab) before
the allow-list ran. So the allow-list of BUG-0544 round 3 decided only the values the
recogniser had already flagged.

## Where encountered
The check of BUG-0544's final round (8fee220), recorded as residual N-R3-1
(`docs/bugs/BUG-0544-stored-evidence-was-replayed-as-the-request.md`, "Residuals after
the final round"; `scratchpad/reqid78/residuals_r3.md`), pinned by two strict xfails over
twelve spellings. The same values are sent verbatim at dcc7091 (older than the
amendment). Reproduced on 7393c90 by those two tests with the pin removed (12 + 12
failures), and by this lane's sweep (below).

## What it caused to fail
Each of these was the lab to `names_outside_lab` at 7393c90, so `_send_value` sent it
unchanged, `_outside_lab` let its request be rebuilt, and `_bind_fresh` bound it. WHATWG
reads each one as naming an outside host (node 22, `new URL("http://" + v)`):
- a loopback authority with no `/` before `?` or `#`: `127.0.0.1?next=evil.top`,
  `localhost?next=evil.example`, `127.0.0.1#evil.example:8080`, `localhost?u=134744072`,
  `127.0.0.1?next=https:evil.example`, `127.0.0.1?next=//evil.top/x`,
  `LOCALHOST?next=8.8.8.8:53` (host 127.0.0.1 or localhost, the tail naming evil.top,
  evil.example or 8.8.8.8);
- a loopback authority spelled so the recogniser misses it: `127.0.0.1./?next=evil.top`,
  `localhost./?next=evil.example`, `127.1/?next=evil.top`, `2130706433/?next=evil.top`,
  `0x7f000001/?next=evil.example:8080` (WHATWG: 127.0.0.1, or `localhost.`);
- the broader gap with the same cause, a top-level outside value: `evil.top`,
  `evil.top/x`, `evil.shop:8080`, `134744072`, `8.8.2056/x`, `8.8.8.8./x`,
  `0x8080808:53` (evil.top, evil.shop, 8.8.8.8), and `ｅｖｉｌ．ｔｏｐ`, `evil%2Etop`,
  `evil​.top`, `evil。top` (each evil.top), `/evil.top` and `\\evil.top/x`
  (evil.top), `user@evil.example` (evil.example).

An app that reads such a value as a URL or a host (an SSRF or redirect sink, a
`next=` parameter) is sent a host outside the lab by the fuzzer.

## What the bug was identified to be
The admission decision of a safety predicate was made by a recogniser of the forbidden
thing (`neutral_value` → `value_shape` → `GENERIC_TLDS`, `ipaddress`, `_host_prefix`),
in front of the allow-list that BUG-0544 round 3 required. The allow-list itself
(`_names_only_lab`, `_tail_in_grammar`) was correct for the values it saw.

## Root cause analysis (Five Whys)
1. Why were `127.1/?next=evil.top` and `evil.top` sent? `names_outside_lab` returned
   False without running its proof.
2. Why? It returned early when `neutral_value(value) == value`, which it is for every
   value `neutral_value`'s recogniser does not flag.
3. Why was the gate a recogniser? `names_outside_lab` was introduced (BUG-0544) as a
   refinement of `neutral_value`: "a value `neutral_value` would replace whose host is not
   loopback". The three review rounds each tightened what happens after the gate (the
   authority split, then the tail grammar) and never questioned which values reach it.
4. Why did round 3's guard and sweep not catch it? The guard
   (`test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts`) read
   `_tail_in_grammar` only, not the predicate's entry or anything else it reaches. The
   sweep (`_r3_sweep`) varied the tail token only; every position put a recognised
   authority (`http://127.0.0.1/`, `127.0.0.1/`, `localhost:3000/`, `http://[::1]:8080/`)
   before it, so the gate always passed.
5. Why was the scope of the guard and the sweep the tail? PA-0544(7) round 3 said "every
   part" and "a guard that the predicate reads no recogniser", but its enforcement named
   one helper, and "every part" was read as authority and tail of a value already known
   to have them: the decision of *which values have a host at all* was not seen as a part.

**Root cause:** the predicate's admission was split into "is this a URL-like value" and
"is this URL-like value loopback", and only the second was made an allow-list; the
first stayed a recogniser of hosts, and the guard and sweep that PA-0544(7) required were
scoped to the second.

## Corrective action
CC-AUD-0058 (FR-AUD-20 amended in place; SP-73's row text updated at the merge):
- `names_outside_lab` no longer reads `neutral_value` or `value_shape`. It decides on
  every text a reader parses from the value (`_reader_texts`: WHATWG's tab/newline
  removal and C0/space trim, an application's Unicode trim, and a C reader's cut at the
  first NUL). A value of a **URL or authority shape** (`_authority_shaped`: a scheme and
  `:`, any scheme; a leading `//`, `\` or `/\`; or a leading token, or the host a reader
  that puts `http://` before the value takes -- leading slashes skipped, userinfo cut at
  its last `@` -- that is a `_host_token`) is the lab only when `_names_only_lab` proves
  it: its authority, up to the first `/`, `?` or `#`, is one of an **explicit set of
  loopback spellings** (`_lab_authority`: `localhost` in any case, `[::1]`, and
  `127.a.b.c` in canonical dotted decimal, with at most a port of one to five digits),
  `urlsplit` agrees, the tail is in `_tail_in_grammar`, and no `@`, `\`, `%`, control,
  space or non-ASCII character is anywhere. Anything else names no host to any reader
  but a single-label one, and is the lab.
- `_host_token` (what a reader takes for a host): WHATWG can read it (no space or
  control after percent-decoding, NFKC case folding and dropping ignorable characters)
  and it holds a dot or an IDNA full stop, is a bracketed literal, is `localhost`, or is a
  dotless number that WHATWG reads as 0.0.0.0 or as an address of at least 2**24 (and
  below 2**32). A bare dotless number below 2**24 (0 included) is no shape.
- `neutral_value` stands loopback in for every value `names_outside_lab` puts outside
  (SAFE_URL with a scheme, path, query or fragment, else SAFE_HOST), so `_send_value`
  never returns an outside value unchanged.
- Bounded: a token longer than `MAX_LEN` with no space is read as a dotted host (fail
  closed); `int()` never sees more than ten decimal digits; the shape checks are C-level
  string operations (a 10 MB value: 0.2 s, measured).

**Design measured, then narrowed.** The first version also held two shapes with no host
of their own to the tail grammar: a reference to the page's own origin (a leading `/`,
`?` or `#`: resolved against the lab it is a lab URL) and a single-label authority before
a tail (`intranet/?next=evil.top`). Measured on random tokens before shipping
(`token_cost.py`, 20,000 each): the reference rule put 99.9% of ASP.NET-shaped view
states (`/wE...`) outside, and the single-label rule 20.5% of 32-byte standard base64
tokens (21.5% with both), so their forms' fresh-bound tokens would be unbound. Both
rules were dropped for the stated residual below; with the shipped design, standard base64
tokens are 0.1% outside (those starting `0/`, which WHATWG reads as 0.0.0.0, or `//`),
view states, URL-safe base64, hex and UUID tokens 0%.

**Measurements** (CLAUDE.md step 8; scripts in
`scratchpad/lanes/LABAUTH/`):
- **WHATWG readings, node 22.22.0** (`probe.js`, `measure.py`): the 69 readings
  embedded in the tests (`_MEASURED_OUTSIDE`, `_MEASURED_LAB`) were checked against node
  (`check_tables.py`: 0 mismatches). Notable: `127.1`, `2130706433`, `0x7f000001`,
  `0177.0.0.1`, `127.0.0.1.` are 127.0.0.1; `localhost.` stays `localhost.`;
  `[0:0:0:0:0:0:0:1]` is `[::1]`; `/evil.top`, `\\evil.top/x` and `/\evil.top/x` are
  evil.top and `/8.8.8.8:53/x` is 8.8.8.8:53 with `http://` before them;
  `evil.top\x00` is evil.top (trailing C0 trimmed); `user@evil.example` is
  evil.example; `42` is 0.0.0.42, `0:3000` is 0.0.0.0:3000; `4294967296`,
  `hello world`, `a b.top` and `/?next=evil.top` are no host.
- **Soundness against node** (`soundness.py`): 2,730,000 generated values (18 prefixes,
  7 userinfos, 91 host spellings, 7 ports, 13 tails); 16,159 admitted. For every
  admitted value node reads, as an absolute URL and with `http://` before it, either no
  host, or a loopback host (or 0.0.0.0) whose path, query and fragment are in the
  grammar, or (with `http://` before it) a single-label name or a non-zero 0.0.0.0/8
  address: **0 unsound admissions**; 2,710 of the admitted values are the stated
  residual (a single-label host before a tail outside the grammar).
- **0.0.0.0/8 on the test host** (Linux 6.18; a UDP `connect`, a route lookup that sends
  nothing): 0.0.0.0 is routed to 127.0.0.1; 0.0.0.1, 0.0.0.42, 0.1.2.3 and
  0.255.255.255 go to the default route (Linux treats 0/8 as unicast since 5.3).
  Hence 0 is a host token (it is this host: its port and tail must be proven), and the
  other small numbers are a stated residual, not "no host".
- **Flip cost** (`collect_store_values.py`, `flips.py`): over the 532 fuzzlab stores on
  this host holding sibling values (the test suite's and the lanes' recorded runs; form
  entries, parameter examples, stored URLs' query values), 3,509 distinct non-filler
  values (14,755 occurrences): 15 distinct values (188 occurrences) move from the lab to
  outside, none the other way: `robots.txt` (72), `lang_en.php` (32), `portal.php`,
  `message.txt` (8 each), `getting-started.html`, `2.5` (4 each),
  `keyboard-shortcuts.html` (2), two `.md` file names (1 each), two long values over
  `MAX_LEN` (5 and 1), `disco.user@example.com` (27), `a@lab.test`, `a@b.example` (8
  each), a free text holding `...@fuzzlab.lab)` (7). Over the values written in the
  repo's test fixtures and lab sources (`collect_fixture_values.py`: HTML `value=`
  attributes and URL query values, 217 distinct non-filler), 32 flip: the tests' own
  outside spellings, file names (`login.php`, `xss_login.php`, `lang_fr.php`,
  `clip123.mp4`), `1.2.3`, `1.`, `...`, `/manager.php` and path-traversal payloads. The
  literal reading of "a leading token WHATWG parses as a host" (a pure word before a
  delimiter, `text/html`, outside too) would flip one more stored value
  (`1;token=<hex>`); this design keeps the word a single-label name, as bare.

**Accepted false positives** (outside: a sibling or fresh value is unbound, a stand-in
context gets loopback): a dotted token (`robots.txt`, `lang_en.php`, `2.5`, `1.2.3`,
`0.00`, `v1.2`, `Hello.`, a JWT), also as a path's first segment (`/index.php`) or a
leading `..`; an e-mail address (`user@mail.example.com`: it names its domain to a reader
that puts `http://` before it; this supersedes FR-AUD-20's stated e-mail residual); a
dotless number from 2**24 to 2**32 - 1 (an 8- to 10-digit id or Unix timestamp: an IPv4
address to WHATWG and inet_aton) and one reading 0.0.0.0 before a port or path (`00:30`,
`0/x`); text starting with a word and `:` (a scheme to WHATWG: `Note: x`, `sort:asc`,
`intranet:8080/x`, `javascript:`, `mailto:`); a loopback spelling outside the explicit set
(`127.1`, `2130706433`, `localhost.`, `[0:0:0:0:0:0:0:1]`, `[::ffff:127.0.0.1]`,
`127.0.0.1.`, `/127.0.0.1/`).

**Stated residuals** (the lab): a pure dotless word and a dotless number of 2**32 or more
(single-label names: a host only to a resolver that completes them from a search list or
a hosts file), whatever follows them (`intranet/?next=evil.top`); a non-zero dotless
number below 2**24 (0.0.0.0/8: RFC 6890 not forwardable; this kernel routes it to the
default route); free text with a space (no reader reads a host from it); a value naming
no host of its own whose path, query or fragment does (`/?next=evil.top`, `/go/evil.top`,
`?next=evil.top`, `#evil.zip`): resolved against the lab it is a lab URL with such a tail,
but holding it to the grammar costs the tokens measured above.

**Tests** (`tests/test_replay_bindings.py`; each reproduction run once on 7393c90's
`value_shape.py` in a scratch copy, see CC-AUD-0058):
- the two N-R3-1 pins, now plain tests (24 cases);
- `test_every_authority_spelling_outside_the_lab_set_is_outside_the_lab` (the generated
  sweep: IPv4 one- to four-part, integer, hex, octal, trailing-dot and upper-case
  spellings of 8.8.8.8, 127.0.0.1, 10.0.0.1 and 1.2.3.4; host names in other cases,
  trailing dots, percent-encoded, with IDNA, fullwidth and halfwidth full stops,
  fullwidth letters and ignorable characters; IPv6 literals with `::ffff:127.0.0.1` and
  `::ffff:8.8.8.8`; in 23 positions: bare, port, path, query, fragment, `;`, absolute,
  upper-case scheme, scheme-relative, backslashed, special scheme without `//`,
  userinfo both ways) and `test_the_binder_never_binds_an_authority_spelling_outside_the_lab_set`;
- `test_a_lab_set_authority_with_a_grammar_tail_is_the_lab` (70 loopback controls, sent
  and bound as given);
- `test_a_value_a_reader_takes_for_a_host_beyond_the_lab_set_is_outside` and
  `test_a_pure_word_a_small_number_and_free_text_are_the_lab` (the measured tables);
- `test_a_reference_is_outside_only_when_a_reader_takes_a_host_from_it` (the
  `http://`-reader host after leading slashes, the scheme reading of `word:`, and the
  residual, with a view state and a standard base64 token kept);
- `test_the_lab_predicate_reaches_no_recogniser_of_hosts` and
  `test_the_recogniser_guard_catches_a_synthetic_offender` (an AST walk of everything
  `names_outside_lab` reaches, proven on N-R3-1's own early return and on a recogniser
  three calls down).
- Amended with before/after: `tests/test_forms_phase2.py::test_neutral_value_errs_toward_loopback`
  (`lang_en.php` and the e-mail row now get loopback) and
  `::test_link_query_siblings_are_bound` (`u=robots.txt` is outside: loopback holds its
  slot, and the points that need it as a sibling carry a `replay_refusal`).

**Residual pinned (FUZZ):**
`tests/test_replay_bindings.py::test_an_access_control_replay_never_reads_a_stand_in_for_its_own_value`
(strict xfail, `raises=AssertionError`). The point builder puts loopback in a point's
own slot when its value is outside the lab (FR-AUD-20: the payload's slot), but
`CrossAccountReplayStrategy` (a SEED category, PA-0530) replays that slot as the object
key: the owner's request for `127.0.0.1` answers 404, and the point is read as a
negative, not inconclusive. Measured in plain Python (`pin_check.py`): `10.0.0.5`
(outside at 7393c90 too) and `100000001` (outside since this change) give no verdict and
no inconclusive, `42` confirms. Pre-existing for an ip- or host-name-valued id; wider now
for 8- to 10-digit ids. R-ACCESS-CONTROL fires only on id-named parameters
(`*_id`, `id`, `uuid`, `guid`), and no recorded store holds such an id.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a safety predicate whose
admission a recogniser decided, and for FR-AUD-20's predicate:
- **BUG-0544 / PA-0544(7)**: the same predicate, the same root cause, four times. Round 1
  (B3): the authority was read with `urlsplit` only (`127.0.0.1:80@evil.example/`
  passed). Round 2 (R2-1): the tail was read with `value_shape` (`?next=evil.example:8080`
  passed). Round 3 (R3-1): the tail rule was still a recogniser (`?next=evil.top`
  passed); fixed by `_tail_in_grammar`. Final check (N-R3-1): the gate in front of the
  allow-list was a recogniser (`127.1/?next=evil.top`, `evil.top` passed); pinned. This
  is that pinned residual, and a recurrence of the same root cause.
- BUG-0124 (FR-AUD-21's redirect seed): an explicit, operator-approved exception, not
  a predicate; not this cause.
- PA-0123, PA-0132 (scope predicates for the browser and redirects): about where fuzzlab
  sends, not what an app-supplied value names.

## Prior-preventive-action failure analysis
**PA-0544(7)** (BUG-0544, rounds 1 to 3) required that the predicate admit only what it
proves for every part of the value, as an allow-list, "enforced by a guard that the
predicate reads no recogniser, and by a generated sweep of each bypass class". It did not
prevent this recurrence because:
- **Enforced on the wrong layer, too narrow.** Its guard
  (`test_the_tail_rule_is_an_allow_list_never_a_recogniser_of_hosts`) parses
  `_tail_in_grammar` alone. "The predicate" was implemented as the tail helper;
  `names_outside_lab`, the predicate's entry, read `neutral_value` and the guard never
  looked there. A guard of one helper cannot see a recogniser in its caller.
- **The sweep varied one part.** `_r3_sweep` generated every tail token in every position,
  but every position began with an authority the recogniser recognises, so the gate never
  failed open in the sweep. "Each bypass class" was read as "each tail token class".
- **"Every part" omitted the shape decision.** Which values have an authority at all was
  decided before the proof, and was not treated as a part to prove.
- It was followed in name (the allow-list exists) and the residual was pinned per
  PA-0530(4), as required, by a strict xfail: the pin worked, which is why this fix is
  scoped exactly.

## Preventive action
**PA-0555** (strengthens PA-0544(7); PA-0002 sweep below):
1. **A safety predicate's guard reads everything the predicate reaches**, from its
   public entry through each function of its module it calls (a transitive walk, not one
   helper), and fails on any recogniser, classifier, closed list or parser of the
   forbidden thing; it is proven on a synthetic offender at the entry (an early return)
   and one several calls down.
2. **The shape decision is a part.** Deciding which values are subject to the proof is
   itself fail closed: made syntactically on every text a reader parses (WHATWG's
   preprocessing, an application's trim, a C reader's NUL), and a value of uncertain shape
   is subject to the proof. A carve-out that admits without proof (a pure word, a small
   number) is a stated residual with its measurement and its measured flip cost.
3. **An admitted host is an explicit set of spellings every reader reads alike**, never
   "a reader reads it as loopback": other spellings of the same address are outside
   (stated false positives).
4. **A generated sweep varies every part of the value**: the authority's spelling in
   every form, the delimiter after it, the prefix before it, and the tail, and is checked
   against the real reader (node) at design time, with the measured readings embedded in
   the test. A sweep whose fixed parts pass a gate cannot test the gate.

- Enforced by: tests/test_replay_bindings.py::test_the_lab_predicate_reaches_no_recogniser_of_hosts, tests/test_replay_bindings.py::test_the_recogniser_guard_catches_a_synthetic_offender, tests/test_replay_bindings.py::test_every_authority_spelling_outside_the_lab_set_is_outside_the_lab, tests/test_replay_bindings.py::test_the_binder_never_binds_an_authority_spelling_outside_the_lab_set, tests/test_replay_bindings.py::test_a_value_a_reader_takes_for_a_host_beyond_the_lab_set_is_outside, tests/test_replay_bindings.py::test_a_loopback_authority_the_recogniser_misses_is_still_outside_the_lab

**PA-0002 sweep** (by primitive, SP-73: every caller of the owner and every consumer of
what changed):
- `harness.auto._send_value` (sibling and own entries of form, link-set, path and JSON
  points; header points' representative query): reads the owner; `neutral_value` now
  stands loopback in for every outside value, so it never returns one unchanged.
- `harness.auto._outside_lab` (a point's `replay_refusal`; `first_link_set`'s accept for
  header points): reads the owner.
- `oracle._FormBoundSender._bind_fresh`: reads the owner.
- Consumers of the own slot's stand-in: the strategies' payloads replace it, except the
  SEED categories (PA-0530): command-injection starts from `base_value` (SAFE_HOST or
  none), open-redirect from its `redirect_seed` (FR-AUD-21's exception), nosql-injection
  reads only the leaf's type, and access-control replays it -- the pinned residual above.
- Other uses of `value_shape` (`harness.auto._shapes`, the rule predicates, the
  command-injection `base_value`, `redirect_seed`) choose categories and starting values;
  none admits a value to be sent.
- Other admit predicates for app-supplied values: none (grep of `names_outside_lab`,
  `neutral_value`, `is_loopback_origin` callers on values; `core.urls` scope predicates
  judge fuzzlab's own request URLs, PA-0123).

## Review round 1 (added in review round 1, 2026-10-22)
One review of 1338d7a; each finding below was confirmed by a skeptic with a run on both
1338d7a and 7393c90 (`scratchpad/lanes/LABAUTH/review_round1.md`). LA-2 and LA-5 are one
defect. Fixed on `lane/LABAUTH-r1` (CC-AUD-0058, review round 1; FR-AUD-20 amended in
place; FR-AUD-32). This section supersedes the paragraphs above where they disagree.

### What the fix still let through, or claimed without measuring
- **LA-1 (a regression this fix introduced): a value holding `://` after a prefix that
  is no scheme was sent and bound.** 7393c90's entry gate, `neutral_value(value) ==
  value`, was a recogniser, but it held every value with `://` anywhere (SAFE_URL), so
  only `_names_only_lab` could admit one. The rewrite removed the gate and put in its
  place a shape test that saw a host only at a scheme-shaped start, a leading `//` or
  `\`, or in a dotted leading token or `http://`-reader host. `/login?next=https://evil.example/`,
  `?next=http://evil.top`, `url=http://evil.top`, `{"u":"http://evil.top"}`,
  `see http://evil.top` and `(http://evil.top)` were outside at 7393c90 and the lab at
  1338d7a, through `_send_value`, `_outside_lab` and `_bind_fresh`. Measured per point
  (below): 326 recorded points newly sent beside `/go?ret=https://host.example/cb?x=1`.
  The residual stated for "a value naming no host of its own whose tail does" was
  justified by a token measurement whose alphabets hold no `:`, so it never covered this.
- **LA-2 / LA-5 (a regression this fix introduced): an unbracketed IPv6 literal was the
  lab.** At 7393c90 `value_shape` read `2001:4860:4860::8888` as `ip` (`ipaddress`), so
  `neutral_value` changed it and it was outside. The rewrite's leading token and
  `http://`-reader host cut at the first `:` (`2001`, `64`, or empty for `::ffff:8.8.8.8`),
  which `_host_token` reads as a small number or nothing. Only literals starting with
  a-f were caught, by the scheme rule. `getaddrinfo(AI_NUMERICHOST)` and `inet_pton`
  read every one as its address (measured), `value_shape` still calls each `ip` (a
  command-injection default), and WHATWG refuses each after `http://` -- so the round-0
  soundness check against node, the only reader it ran, could not see them. The sweeps
  held bracketed literals only.
- **LA-3 (an unstated carve-out the fix kept): a JSON number was the lab without proof.**
  `names_outside_lab` began `if not isinstance(value, str): return False`, so the JSON
  number `134744072` (the text `134744072`, 8.8.8.8 to WHATWG: an app doing
  `"http://" + body.host`, node 22) was sent as a sibling on the ground-truth, stored-XSS
  and crawled JSON paths, while the string was outside. It predates this fix but is the
  bug's own class on a path the fix names, and PA-0555(2) required such a carve-out to
  be stated with its measurement; it was not, and the guard test hard-coded the early
  return as the expected head.
- **LA-4 (a pre-fix proof not on its own assertion).** On 7393c90
  `test_the_lab_predicate_reaches_no_recogniser_of_hosts` failed at its helper-presence
  assertion (`_lab_authority` and `_host_token` did not exist), so its stated reason --
  the recognisers reached -- was never checked; and
  `test_the_recogniser_guard_catches_a_synthetic_offender` failed at
  `source.count(head) == 1`, a source-text precondition. CC-AUD-0058 and the Tests list
  above still counted "both guard tests" among the reproductions (`prefix_run2.txt`).
- **LA-6 (an unstated cost in a recorded lab result).** In ground-truth mode Mongection's
  SDLMG-0002 (`/login` password, NoSQL injection, expected vulnerable) was refused
  before any strategy ran: the answer key's JSON sibling `email=user@lab.test` was
  outside, so the point was read inconclusive with no send (recall 2/2 to 1/2), and
  `/register` name the same. The NoSQL strategy never sends that stored e-mail. The cost
  statement missed it: it was measured per distinct value, on recorded stores and the
  repo's HTML `value=` attributes and URL queries, never on the answer keys' `json_body`
  leaves or `lab/external/*/.cache` (a `glob('**')` skips dot directories), and never per
  point.

### Corrections of the claims above (added in review round 1)
- "15 distinct values ... move from the lab to outside, **none the other way**" holds
  only for the recorded-store values that were measured. The rewrite also moved values
  the other way (LA-1, LA-2: outside at 7393c90, the lab at 1338d7a); measured per point
  below.
- "**0 unsound admissions**" was measured against one reader, node's WHATWG parser.
  Bare IPv6 literals, which WHATWG refuses and `getaddrinfo` reads, were admitted.
- "Every reproduction fails: ... **both guard tests**" (CC-AUD-0058, and the Tests list
  above): the recogniser guard failed on 7393c90 at its helper-presence assertion, not
  at its stated reason, and the synthetic-offender test is a guard of the guard (on the
  old code its head is not there), not a reproduction. Re-recorded below: on 7393c90
  the guard now fails at its first assertion, naming
  `FILE_EXTENSIONS, GENERIC_TLDS, _host_prefix, _is_filename, _is_hostname, _is_ip,
  _is_path, _is_url, ipaddress, is_loopback_origin, neutral_value, value_shape`.
- "Expected on bWAPP: BWAPP-0054 and BWAPP-0055 ... become inconclusive": no longer, a
  bare `robots.txt` is the lab under the bare-token rule (below).
- The accepted false positive "a dotted token (`robots.txt`, `lang_en.php`, ... a JWT)"
  now holds before a path, query or fragment only; in a bare token, only a name under a
  delegated TLD or a number WHATWG reads as IPv4 is outside.

### Root cause of the review findings (added in review round 1)
Five Whys, LA-1 and LA-2:
1. *Why were `?next=http://evil.top` and `2001:4860:4860::8888` sent at 1338d7a and not
   at 7393c90?* The rewrite removed the old gate, and the new shape test held neither a
   `://` after a prefix nor an unbracketed IPv6 literal.
2. *Why did the new shape test omit shapes the old gate held?* It was derived anew from
   one reader's reading (WHATWG, with `http://` before the value), not from the set of
   values the code it replaced put outside.
3. *Why did no test catch the loss?* The sweeps were generated for the bypass classes
   the rewrite targeted (authority spellings at the start, tails after a loopback
   authority); none was generated from the old rule's coverage, and the IPv6 spellings
   were bracketed only.
4. *Why did the soundness and cost measurements not catch it?* Soundness was measured
   against node alone, which refuses bare IPv6; cost was measured per distinct value,
   and only in the direction the author expected.
5. *Why one reader and one direction?* PA-0555(2) said "every text a reader parses",
   and the rewrite read it as every *preprocessing* of the text by WHATWG, not every
   reader of the value (an address parser, a percent-decoding application); and nothing
   required a rewrite of a safety predicate to keep what the old one caught.

**Root cause:** a safety predicate was rewritten from a model of one reader, and checked
against that reader and the classes it targeted, with no non-regression against what
the predicate it replaced held. LA-3 is the same failure of the entry (an input type
the model did not cover, admitted by an early return), LA-4 a pre-fix proof read for
its outcome and not its assertion (PA-0545(6) not followed), LA-6 a cost measured per
value on the sources at hand instead of per point on every source of points.

### Corrective action (added in review round 1)
`fuzzlab/audit/value_shape.py` (CC-AUD-0058 review round 1; FR-AUD-20 amended in place;
FR-AUD-32 new):
- **LA-1:** `_authority_shaped` treats `://`, `:\` and `:/\` anywhere
  (`_AUTHORITY_MARKS`) as an authority shape, so only `_names_only_lab` admits such a
  value. `_reader_texts` also reads the value percent-decoded until stable (at most
  eight times, `_percent_decoded`), so an encoded `https%3A%2F%2Fevil.top` is the same
  shape: the bare-token rule below would otherwise have admitted the 54 recorded points
  beside a triple-encoded `/go?ret=https://host.example/...` that 1338d7a's
  `_host_text` decoding had caught (measured).
- **LA-2 / LA-5:** `_ipv6_shaped`, syntactic (no address parser, PA-0555): the text up
  to its first `/ ? # \ ;` or whitespace, before its first `@` or after its last, of hex
  digits, `:` and `.` (a zone after `%`) with `::` or at least six `:`, also after
  leading slashes. Proven like any authority, so only `[::1]` is the lab; `12:00:00`
  and a MAC address are not shapes.
- **LA-3:** `names_outside_lab` judges `_judged_text(value)`: a string as it is, an int
  or float (never a bool) by its `json.dumps` text, anything else (bool, null, an empty
  container) as naming nothing; `neutral_value` and so `_send_value` put `127.0.0.1` in
  a number's place.
- **LA-6, by design (the bare-token rule; no answer key edited):** a bare token (none of
  `/ ? # \`, no scheme, no authority mark) is of an authority shape only when its
  leading token or `http://`-reader host (`_named_host`) is an IP literal in any form
  (bracketed; dotted with a numeric last label in any radix; a dotless number read as
  0.0.0.0 or from 2^24 to 2^32 - 1), `localhost`, or a dotted name whose last label is a
  TLD delegated in the DNS root (`_delegated_tlds`: IANA's root-zone list, bundled
  verbatim with its date, FR-AUD-32; the label read up to its first non-LDH character; a
  non-ASCII label taken for an IDN TLD). Reserved and undelegated names (`.test`,
  `.example`, `.invalid`, `.localhost`, `.local`, `.corp`, file extensions) are not:
  `robots.txt`, `lang_en.php` and `user@lab.test` are the lab, `evil.top`, `evil.zip`
  and `user@gmail.com` outside. A value with a path, query or fragment keeps 1338d7a's
  rule (any dotted leading token or reader host is proven).
- **LA-4:** the guard asserts the recognisers reached first, with them in its message,
  then the helpers' presence; the offender test's docstring says it is a guard of the
  guard.

**Measured cost, per point** (`scratchpad/lanes/LABAUTH/r1/measure_points.py`,
`point_cost.txt`; each version's `value_shape` loaded in turn, the predicate applied as
`harness.auto` applies it):
- Recorded stores (2,953 stores on the test host, 9,562 parameter rows with sibling
  entries: form, link-set and JSON-leaf points): unbound 843 at 7393c90, 705 at
  1338d7a, 1,081 now. Against 7393c90: 248 newly unbound (140 JSON points beside the
  float leaf `2.5`, LA-3; 108 beside a percent-encoded URL naming `host.example`), 10
  newly bound (`db.lab.example`: `.example` is reserved). Against 1338d7a: 538 newly
  unbound (326 beside `/go?ret=https://host.example/cb?x=1`, LA-1; 140 `2.5`; 72
  encoded URLs), 162 newly bound (`robots.txt` 85, `a@lab.test` 50, `db.lab.example`
  10, `lang_en.php`, `portal.php`, `message.txt` 5 each, a free text holding
  `...@fuzzlab.lab)` 2).
- Lab answer keys (22, 352 points with writes on and off, `points_from_ground_truth`):
  none refused now; 1338d7a refused 4 (Mongection `/login` password, SDLMG-0002,
  expected vulnerable, and `/register` name, each with writes on and off); 7393c90 none.
- External labs' sources (`lab/external/*/.cache`, 733 files; node_modules and vendor
  skipped): 123 HTML form-field points, none unbound; 2,095 URL-query points, 62
  unbound now and at 1338d7a, none at 7393c90 -- third-party Google Maps and Fonts URLs
  in amarelo-designs' templates (`28.659344,-81.187888`, `0.128789,0.264187`,
  `Roboto:300,400,500`), which a lab crawl does not make points of (another origin).
- Readings embedded in the tests, checked against the real readers
  (`r1/check_tables_r1.py`): 114, 0 mismatches (node 22 for the WHATWG tables and the
  JSON numbers, `getaddrinfo(AI_NUMERICHOST)` for the bare IPv6 table).

**Accepted false positives and residuals, as amended** (FR-AUD-20 holds the full list):
new false positives are a JSON float leaf WHATWG reads as IPv4 (`2.5`, `19.99`), a file
name under a delegated TLD (`archive.zip`, `readme.md`, `script.py`), a bare `::1`, and
a hex string with `::` or six `:`. New residuals: a bare dotted name under an
undelegated TLD (`intranet.corp`, `printer.local`, `db.lab.example`) is the lab -- a host
only to a private resolver, a hosts file or mDNS; a TLD delegated after the snapshot's
date is the lab until it is refreshed (FR-AUD-32); a value percent-encoded more than
eight times is read only that far. The bare-token rule decides a bare dotted name with
one list, IANA's root zone: the owner's design for this round. It is the definition of
the names a public resolver answers, bundled verbatim and dated, not a recogniser's
closed list (`GENERIC_TLDS`, `FILE_EXTENSIONS` stay unreachable from the predicate); a
test proves the decision is the file's, label for label.

**Tests** (`tests/test_replay_bindings.py` unless named; each fails on the commit its
finding names at its own assertion, recorded below):
- LA-1: `test_a_value_holding_an_authority_mark_anywhere_is_outside_the_lab` (14 values
  through `_send_value`, `_outside_lab` and `_bind_offered`) and
  `test_every_value_the_old_scheme_anywhere_rule_put_outside_is_still_outside` (6,930
  generated `scheme://` values after 15 prefixes; the expectation is written out, 7393c90's
  rule: every one outside but the 48 loopback URLs its proof admitted; it passes on
  7393c90 and fails on 1338d7a).
- LA-2 / LA-5: `test_a_bare_ipv6_literal_is_outside_the_lab` (the measured
  `getaddrinfo` table, with path, query, port, userinfo, leading slash and free-text
  positions), and `_BARE_IPV6` added to both generated sweeps
  (`test_every_authority_spelling_outside_the_lab_set_is_outside_the_lab`,
  `test_the_binder_never_binds_an_authority_spelling_outside_the_lab_set`).
- LA-3: `test_a_json_number_leaf_is_judged_by_its_json_text` (through `_send_value`,
  `neutral_value` and `_outside_lab` on a JSON body's leaves; controls: small, negative
  and 2^32 numbers, bools, null, empty containers) and
  `test_an_answer_keys_json_number_sibling_leaves_its_point_unbound` (through
  `points_from_ground_truth`); `tests/test_forms_phase2.py::test_neutral_value_errs_toward_loopback`
  gains the number row.
- LA-4: `test_the_lab_predicate_reaches_no_recogniser_of_hosts` (reordered).
- LA-6: `test_no_expected_vulnerable_answer_key_point_is_unbound_by_the_lab_predicate`
  (every lab answer key; no allowance list was needed),
  `test_a_bare_token_naming_no_delegated_host_is_the_lab` (reserved and undelegated
  names in every spelling, bare and as an e-mail's domain, sent and bound as given; the
  same names in every structured position stay outside in the sweeps), and
  `test_the_bare_token_rule_reads_ianas_root_zone_and_nothing_else` (FR-AUD-32). The
  measured tables move `robots.txt`, `lang_en.php`, `Hello.`, `user@evil.example` and
  `localhost.` to the lab table and add `evil.zip`, `user@gmail.com`, `com.`, an IDN TLD
  and `19.99` to the outside one; `tests/test_forms_phase2.py::test_link_query_siblings_are_bound`
  is back to 7393c90's expectation (`u=robots.txt` sent as given, no refusal) and
  `::test_neutral_value_errs_toward_loopback` keeps `lang_en.php` and `user@lab.test` as
  given and puts loopback in for `evil.zip`.

**Pre-fix proof** (PA-0545(6): the failing assertion of every test in the two files,
not only the review's): one pytest invocation, 1338d7a's `value_shape.py` in place of the
fix and then restored (`scratchpad/lanes/LABAUTH/r1/prefix_r1.txt`): 63 failed, 591
passed, 3 xfailed. Every failure is at its test's own assertion
(`r1/assert_lines.py` maps each to its line): LA-1 11 of 14 values (the three
percent-encoded ones were outside at 1338d7a, through `_host_text`'s decoding, and fail
on 7393c90) and the old-rule corpus; LA-2/5 18 of 19 bare-IPv6 values (`fe80::1%eth0`
was outside by the scheme reading) and both sweeps; LA-3 the six outside JSON leaves
and the answer-key JSON test; LA-6 the answer-key guard (SDLMG-0002), the bare-token
test, the TLD source test, 15 lab-table rows and four `test_forms_phase2` cases. On
1338d7a the recogniser guard fails at its helper-presence assertion (the helpers it
names are new in this round) and the synthetic-offender test at its precondition (a
guard of the guard). The guard's stated reason is recorded on 7393c90, where the review
said it belongs, by a plain-Python call of the test functions with 7393c90's module in
place (no pytest session; `r1/prefix_7393c90_plain.txt`): it fails at its first
assertion with "names_outside_lab reaches recognisers of hosts: ['FILE_EXTENSIONS',
'GENERIC_TLDS', '_host_prefix', '_is_filename', '_is_hostname', '_is_ip', '_is_path',
'_is_url', 'ipaddress', 'is_loopback_origin', 'neutral_value', 'value_shape']". The
passes are the controls (the loopback set, the remaining lab-table rows, the JSON
controls) and the earlier tests.

**A test 1338d7a broke, unseen.** The targeted run of this round (one pytest invocation,
20 files, `r1/targeted_r1.txt`: 1 failed, 1387 passed, 1 skipped, 13 xfailed) failed
`tests/test_nosqli.py::test_auto_turns_a_json_body_point_into_a_json_leaf_candidate`,
which fails on 1338d7a at the same assertion. Its fixture's e-mail `a@b.co` is under the
delegated `.co`, so since BUG-0555 its domain is a host outside the lab and loopback
holds the point's own slot (the payload's: the NoSQL strategy replaces it), while the
test asserted the stored value. 1338d7a's `verify_change.py` run did not select it: the
harness selects the importers of a changed module, and this test reaches the predicate
only through `harness.auto`. Amended: the point is built with `user@lab.test` (sent as
given) and with `a@b.co` (loopback in its own slot); a plain-Python call shows it passing
on the fix and failing on 1338d7a (the lab e-mail) and on 7393c90 (the stand-in). A scan
of every literal in the 50 test files that use `harness.auto` (`r1/literal_scan.py`)
finds no other sibling value this round newly puts outside.

### Recurrence review (added in review round 1)
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` again: the findings recur
BUG-0544's and this bug's root cause (FR-AUD-20's predicate admitted what its model of a
reader did not cover) for the fifth time, and LA-4 recurs BUG-0545's review finding B2
(a test failing on the old code for another reason than its own; PA-0545(6)).

### Prior-preventive-action failure analysis (added in review round 1)
- **PA-0555(2)** ("the shape decision is a part ... on every text a reader parses ... a
  carve-out that admits without proof is a stated residual") was followed in name: the
  shape decision was made syntactic, but from one reader's texts (WHATWG's
  preprocessing), not every reader of the value (an address parser, a decoding
  application); and the non-string early return was kept unstated. Too narrow, and not
  enforced: no test fed it a value type other than a string or a reader other than
  WHATWG.
- **PA-0555(4)** ("a generated sweep varies every part of the value") was enforced on the
  classes the rewrite targeted; nothing generated values from the coverage of the code it
  replaced, so a regression was invisible to it. Wrong layer: it tested the new design,
  never the change.
- **PA-0545(6)** ("a regression test's pre-fix proof is on its own assertion") was not
  followed for the guard; its record showed the other assertion failing and the bug doc
  cited the record as a reproduction.
- **PA-0002 / step 8** (measure): the flip cost was measured per value and on the
  sources at hand; the points a lab's answer key defines were not among them.

### Preventive action (added in review round 1)
**PA-0555 strengthened in place** (not yet merged: its text is handed over in
`scratchpad/lanes/LABAUTH/doc_texts.md`, "r1 changes"; it now also strengthens
PA-0545(6)): (1) names IANA's root zone (FR-AUD-32) as the one list the predicate may
read, for a bare token, proven to decide label for label; (2) the shape decision reads
every reader of the value (WHATWG with and without `http://`, an application's trim and
percent-decoding, a C reader's NUL, an address parser) and every value type that
reaches the predicate (a JSON number by its text), and soundness is measured against
more than one reader; (4) the sweep holds bracketed and bare spellings; (5) a rewrite of
a safety predicate keeps what the predicate it replaces held, proven by a non-regression
corpus generated from the old rule's coverage with its expectation written out, or
states each loss with its measured cost; (6) a predicate's cost is measured per point on
every source of points (recorded stores, every lab answer key's leaves, the external
labs' sources), against the base and the previous version, and a guard keeps every
lab's expected-vulnerable answer-key point unrefused; (7) a guard asserts its stated
reason first, its pre-fix record names what it found, and a guard of a guard is never
counted as a reproduction. Enforced by the review tests above, added to PA-0555's
`Enforced by:` line.

## Review round 2 (added in review round 2, 2026-10-22; the owner's final round)
One review of d3cb339 (`scratchpad/lanes/LABAUTH/review_round2.md`); each finding was
reproduced by the reviewer on d3cb339 and 7393c90 in plain Python. The owner approved
this round as the final one and chose its scope, exactly: (1) a special scheme and `:`
after any character that cannot be part of a scheme is an authority mark, in every
reader text, raw and percent-decoded; (2) an IPv6 literal ends at any character outside
its alphabet, and the raw value is judged as well as WHATWG's texts; (3) a JSON decimal
is no host: a number leaf is judged only when it is an integer, and the float residual
is stated with its measured per-point gain. Anything a check finds after this round is
pinned by a strict xfail, never a further fix. Fixed on `lane/LABAUTH-r2` (CC-AUD-0058,
review round 2; FR-AUD-20 amended in place). This section supersedes the paragraphs
above where they disagree.

### What the fix still let through
- **N1 (LA-1's neighbouring path): a special scheme and `:` or `:/` after a prefix was
  sent and bound.** Round 1's `_AUTHORITY_MARKS` (`://`, `:\`, `:/\`) held the
  backslashed spellings WHATWG reads as `//` after a special scheme, but not the others
  it reads the same way: `https:evil.top`, `https:/evil.top` and `https:\evil.top` are
  all https://evil.top/, `ws:evil.top` is ws://evil.top/ (node 22). So
  `?next=https:evil.top`, `go=https:/evil.top/x`, `/login?next=https:evil.example/`,
  `see https:evil.top`, `url=ws:evil.top`, `(https:evil.top)`,
  `{"u":"https:/evil.top"}`, `?next=https%3Aevil.top` and `?next=https%3A%2Fevil.top`
  were sent verbatim, left their request rebuildable and were bound at d3cb339, while
  `http://127.0.0.1/?next=https:evil.top` was outside: LA-1's relative-versus-absolute
  inconsistency, and FR-AUD-20 itself listed `?next=https:evil.example` as outside.
  The same at 7393c90 (not a regression).
- **N2 (LA-2/LA-5's neighbouring paths): an IPv6 literal before a tab, LF or CR, or
  beside a character outside a closed delimiter list, was the lab.** `_ipv6_shaped`
  ended the literal at `/ ? # \ ;` or whitespace, but it read only `_reader_texts`,
  which had already removed tab, LF and CR the way WHATWG does; the readers the rule
  exists for (`getaddrinfo`, `ping6`, a shell, `str.split`) keep them, so
  `2001:db8::1\tis the server` (read `2001:db8::1is`) was the lab while the space form
  was outside. Any other neighbour kept it from being a literal at all:
  `dns=2001:4860:4860::8888`, `2001:4860:4860::8888,2001:4860:4860::8844` (a DNS-server
  list), `"2001:4860:4860::8888"`, `(2001:4860:4860::8888)`, `2001:4860:4860::8888|id`,
  `2001:4860:4860::8888&` were the lab while their IPv4 forms were outside (the
  reviewer's battery: 1,634 such pairs), against FR-AUD-20's claim that anything else
  names no host. The same at 7393c90 (not a regression).
- **The owner's third item: a JSON decimal was judged as a host.** Round 1 judged every
  JSON float by its text, so the leaf `2.5` (2.0.0.5 to WHATWG) was outside and 140
  recorded points beside it were unbound -- an accepted false positive round 1 stated
  and measured. The owner chose to judge a number leaf only when it is an integer.

### Root cause (Five Whys)
1. *Why were `?next=https:evil.top` and `dns=2001:4860:4860::8888` sent at d3cb339?*
   The authority marks were `://`, `:\`, `:/\`, and the IPv6 literal ended only at
   `/ ? # \ ;` or whitespace, on WHATWG's texts.
2. *Why those lists?* Each rule was written from the spellings at hand -- the old
   gate's `://`, the review's backslashed spellings, the delimiters the author knew a
   reader cuts at -- not from the reader's rule (WHATWG's special-scheme states take
   `//`, `/`, `\` or nothing before the host) or from the complement of the literal's
   alphabet (a reader that extracts an address stops at any character not in it).
3. *Why was the tab missed?* The rule for address parsers was applied to the texts
   `_reader_texts` makes for WHATWG, whose preprocessing removes tab, LF and CR; the
   raw value was not among them.
4. *Why did no test catch either?* The round-1 sweeps varied the delimiter and the
   prefix over the same closed lists the rules used (`_SWEEP_POSITIONS`, the bare-IPv6
   positions, the old-rule corpus's `://` only), so they confirmed each rule against
   itself.
5. *Why did the preventive action not stop it?* PA-0555(4) asked the sweep to vary
   "the delimiter after it" and "the prefix before it", and did not say over what; and
   no rule said a token's end is the complement of its alphabet.

**Root cause:** a token boundary and an authority mark were written as closed lists of
known spellings -- a recogniser of delimiters, the same class as a recogniser of hosts
(BUG-0544, BUG-0555) one level down -- applied to one reader's preprocessed text, and
swept over the same lists. The JSON decimal is not a defect of that class: it was a
stated, measured false positive that the owner chose to trade the other way.

### Corrective action
`fuzzlab/audit/value_shape.py` (fffc66b, its docstring 8d8c270; CC-AUD-0058 review round 2;
FR-AUD-20 amended in place):
- **N1:** `_special_scheme_mark` -- one of `_SPECIAL_SCHEMES` (`http`, `https`, `ws`,
  `wss`, `ftp`, `file`, any case) and `:` at the text's start or after any character
  outside `_SCHEME_CHARS` (ASCII letters, digits, `+`, `-`, `.`) -- is an authority
  mark in `_authority_shaped`, so only `_names_only_lab` can admit such a value, and it
  admits none (no spelling of this mark is in its proof). `xhttps:`, `web+https:` and
  `1https:` are not marks (another scheme, or none: WHATWG reads no host from
  `?next=xhttps:evil.example`). Linear: each `:` is checked against six schemes.
- **N2:** `_ipv6_shaped` reads a run of `_IPV6_CHARS` (hex digits, `:`, `.`) ended at
  either side by any other character, holding `::` or at least six `:` -- so any `::`
  is a literal -- and `_reader_texts` now starts with the raw value (and adds the raw
  percent-decoded value), so every rule reads the text a non-WHATWG reader parses too.
  `_IPV6_ENDS` and the `@` split are gone (subsumed).
- **The JSON decimal:** `_judged_text` judges an int, and a float with an integral
  value as that int (JavaScript's `JSON.parse` reads `134744072.0` as 134744072,
  8.8.8.8 after `http://`, measured in node 22 while making this change); any other
  float is the lab, the stated residual.
- Checked against the real readers (`scratchpad/lanes/LABAUTH/r2/check_tables_r2.py`,
  `check_tables_r2.txt`: 38 readings, 0 mismatches -- node 22 for the special-scheme
  rows, the controls and the floats, `getaddrinfo(AI_NUMERICHOST)` after each named
  reader for the IPv6 rows; round 1's 113 readings re-checked, 0 mismatches).

**Measured cost, per point, against 7393c90 and d3cb339**
(`scratchpad/lanes/LABAUTH/r2/measure_points_r2.py`, round 1's script with the versions
7393c90, d3cb339 and the tree; `point_cost.txt`; the host now holds more stores):
- Recorded stores (4,216 stores, 13,684 parameter rows with sibling entries): unbound
  992 at 7393c90, 1,300 at d3cb339, 1,104 now. Against d3cb339: none newly unbound,
  196 newly bound, every one beside the JSON float leaf `2.5` -- the float residual's
  gain (140 when round 1 measured it on 9,562 points), all from 14 stores of
  `tests/test_json_points.py`'s adversarial body (`float_points.txt`). The special-scheme
  mark and the IPv6 rule cost no recorded point. Against 7393c90: 126 newly unbound
  (beside percent-encoded URLs naming `host.example`, round 1's decoding), 14 newly
  bound (`db.lab.example`).
- Lab answer keys (22, 352 points with writes on and off): none refused at any of the
  three; the guard test stays green.
- External labs' sources (`.cache`, 733 files): 123 form-field points, none unbound; 62
  of 2,095 URL-query points unbound, as at d3cb339 (third-party Maps/Fonts URLs).
- Test literals (`r2/literal_scan_r2.py` over all 452 test files, `literal_scan_r2.txt`):
  152 string literals move outside against d3cb339 -- pytest node ids and messages
  holding `::` or ` file:` (`tests/x.py::test_y`, `a SQLite file: URI`), none a value a
  test sends through `harness.auto` or the binder (the targeted run below) -- and 116
  float literals move to the lab.

**Accepted false positives and residuals, as amended** (FR-AUD-20 holds the full
list): new false positives are text naming a special scheme and `:` after a non-scheme
character (`Upload a file: x.pdf`, `see http: below`) and any `::` (a scope operator
`use std::string`, a CSS `a::before`); the hex-string false positive is now any run of
the IPv6 alphabet with `::` or six `:`. New residual: a JSON float leaf that is not an
integer (`2.5`, `8.8` -- 8.0.0.8 to an app that puts `http://` before it). The
free-text residual is restated: free text with whitespace is the lab unless an IPv6
literal or a mark is in it, though a reader that splits it may take an IPv4 address or
a name from it (`8.8.8.8\tx`, `8.8.8.8 is the server`, `evil.top foo`); the owner's
scope made only the IPv6 rule stricter.

**Tests** (`tests/test_replay_bindings.py`; each fails on d3cb339 at its own assertion,
recorded below):
- N1: `test_a_value_holding_an_authority_mark_anywhere_is_outside_the_lab` gains 16
  values (the review's eleven, `?next=HTTPS:evil.top`, `?next=ftp:evil.top`,
  `?next=wss:/evil.top`, `next=Http:8.8.8.8`, and `go to\thttps:evil.top`, whose mark
  only the raw value holds), through `_send_value`, `_outside_lab` and the binder;
  `test_a_special_scheme_after_a_non_scheme_character_is_outside_the_lab` (generated:
  20 prefixes -- nothing, separators, a space, a tab, LF, brackets, quotes, `é`,
  `%20` -- by 8 scheme spellings by `//`-less separators `""`, `/`, `\`, `%2F`, `%5C`
  by 5 hosts, loopback ones included, by 4 tails, and each again with `%3A`: 31,200
  values, every one outside with loopback in its place; four controls the lab, sent and
  bound as given).
- N2: `test_a_bare_ipv6_literal_is_outside_the_lab` gains `_IPV6_BESIDE_READ` (13
  values, each with the reader that takes the literal from it and the address
  `getaddrinfo` reads), `test_an_ipv6_literal_ends_at_any_character_outside_its_alphabet`
  (generated: the 16 bare literals beside each of the 80 characters outside the
  alphabet -- printable ASCII, tab, LF, CR, VT, FF, NUL, NBSP, U+3000, `é` -- before,
  after, both and between words: 5,120 values outside, the binder refusing 156; a time
  of day, a date-time and a MAC address beside a space, tab, LF, parenthesis, quote or
  comma stay the lab), and both sweeps gain `_IPV6_BESIDE_POSITIONS`.
- The JSON decimal: `test_a_json_float_leaf_is_the_lab_a_stated_residual` (`2.5`, `8.8`,
  `19.99`, `0.5`, `134744072.5`: sent as given, a JSON body holding one rebuilt);
  `_JSON_LEAVES` loses its two floats and gains `134744072.0` (judged as 134744072).
- The guard: `test_the_lab_predicate_reaches_no_recogniser_of_hosts` names
  `_special_scheme_mark` among the helpers it must reach (a guard: on d3cb339 it fails
  at that helper-presence assertion, its stated reason holding there; not a
  reproduction).

**Pre-fix proof**: one pytest invocation of `tests/test_replay_bindings.py` whole on fffc66b, with
d3cb339's `value_shape.py` copied in place of the fix and then the fix restored (digest
checked, `git status` clean; `scratchpad/lanes/LABAUTH/r2/prefix_r2.txt`): 38 failed, 376
passed, 3 xfailed, each failure at its test's own assertion -- N1: 16 of the 30
`_AUTHORITY_ANYWHERE` values (the 16 added) at `assert names_outside_lab(value)`, and
the generated special-scheme test at `kept == []`; N2: 12 of the 13 `_IPV6_BESIDE_READ`
values at `assert names_outside_lab(value)` (`2001:4860:4860::8888;id` was outside
already: `;` was in round 1's list), the generated IPv6 test at `kept == []`, and both
sweeps at `kept == []` and `bound == []`; the JSON decimal: the 5 float-residual cases
at `assert not names_outside_lab(value)`. The recogniser guard fails at its
helper-presence assertion (`_special_scheme_mark` is new): a guard, not counted as a
reproduction. The passes are the earlier tests and the controls (`134744072.0` in
`_JSON_LEAVES` was outside on d3cb339 too, by its text).

**Targeted run**: one pytest invocation on 8d8c270 (`FUZZLAB_PYTEST_LOCK_WAIT=7000`, `-n 3 --dist
loadfile`; `scratchpad/lanes/LABAUTH/r2/targeted_r2.txt`) of 50 files: every test file
that reaches FR-AUD-20's predicate or its callers (46: the importers of `value_shape`,
`harness.auto` and the binder, so the callers' tests that round 1's import-based
selection missed are held), packaging, lint, traceability and the shared-primitives
table: 2600 passed, 0 failed, 5 skipped (four live external-lab tests without
`FUZZLAB_LIVE_EXTERNAL_LABS=1`, `bdist_wheel` unavailable), 18 xfailed, in 12 min 29 s.
`scripts/verify_change.py` was not run here: the orchestrator verifies at the merge.

### Recurrence review (added in review round 2)
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` again: N1 and N2 recur this bug's
root cause (FR-AUD-20's predicate admitted what its model of a reader did not list) for
the sixth time -- BUG-0544 rounds 1 to 3, BUG-0555, its review round 1, and now -- this
time in the delimiters and marks rather than the hosts. No other bug doc records a
closed delimiter list in a safety predicate.

### Prior-preventive-action failure analysis (added in review round 2)
- **PA-0555(2)** ("the shape decision ... on every text every reader of the value
  parses (... an address parser such as `getaddrinfo`)") was not followed for the IPv6
  rule: a rule written for `getaddrinfo` was applied to WHATWG's preprocessed texts.
  Wrong layer: `_reader_texts` was taken for every reader's texts.
- **PA-0555(4)** ("a generated sweep varies every part of the value -- ... the
  delimiter after it, the prefix before it ...") was followed over the delimiters and
  prefixes the rules themselves listed. Too narrow: it did not say over what a part
  varies, so a closed list satisfied it.
- **PA-0555(5)** (a non-regression corpus of the old rule) does not apply: neither
  finding regressed from 7393c90; both are neighbours no version held.

### Preventive action (added in review round 2)
**PA-0555 strengthened in place** (no new number; its text is handed over in
`scratchpad/lanes/LABAUTH/doc_texts.md`, "r2 changes"): (4) a delimiter or prefix
varies over every character (printable ASCII, whitespace with tab, LF and CR, NUL,
non-ASCII), never over the list the rule uses; new (8) a token's boundary is the
complement of its alphabet, a mark is the reader's whole rule (a special scheme with
`//`, `/`, `\` or nothing), and a rule written for a reader reads that reader's text
(the raw value for an address parser, a shell or a splitting application). Enforced by
`test_a_special_scheme_after_a_non_scheme_character_is_outside_the_lab` and
`test_an_ipv6_literal_ends_at_any_character_outside_its_alphabet`, added to PA-0555's
`Enforced by:` line. The sweep for this round was itself done by character, not by
list: the IPv6 test iterates the complement of the alphabet, the special-scheme test
every class of preceding character.
