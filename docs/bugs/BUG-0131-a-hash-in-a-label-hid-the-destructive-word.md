# BUG-0131 — A `#` in a label, control name, entry or option hid the destructive word

- Date: 2026-10-14
- Status: fixed (CC-CORE-0052, CC-CRAWL-0024, CC-AUD-0039)
- Severity: medium. A destructive SPA button, control, link-set entry or selector option
  whose text had a `#` before the destructive word passed the gate: the crawler could
  click it (`--submit-spa-forms`), submit a selector option, or the importer could keep
  a link set as fuzzable siblings.

## Description
Four gates judged a **text** with the URL rule by embedding it in a query:
`destructive_reason("/?x=" + text.replace(" ", "+"))`. `destructive_reason` reads only
the URL's path and query, and `urlsplit` turns everything after a `#` into the
fragment. So `"#1 Delete"` became path `/`, query `x=`, fragment `1+Delete`, and was
judged not destructive.

## Where encountered
Forms phase 4 (FR-CRAWL-15/16), while writing the shared label gate for reveal
candidates and checkbox labels, which needed to judge arbitrary page texts. Reproduced
on the integration commit 514f326:
`spa.form_refusal({... "button": "#1 Delete" ...}, "contact", named=None)` returned
None; `"Delete"` alone was refused. Same for `store_adapter.entries_refusal([("note",
"#x delete everything")])`, `formnav.option_refusal("a", "#2 remove")` and a control
named `#a_drop_table`.

## What it caused to fail
NFR-CRAWL-safe ("deny-list destructive actions") at four gates:
- `spa.form_refusal`'s button text / aria-label and control-name checks (FR-CRAWL-13;
  also the session manager's browser login, FR-SESS-19, which calls it);
- `store_adapter.entries_refusal` (link sets and captured bodies, FR-FUZZ-43 /
  FR-AUD-22);
- `formnav.option_refusal` (selector navigation, FR-CRAWL-8).
No live incident: no lab label carries a `#` before a destructive word, which is why
nothing failed.

## What the bug was identified to be
A text gate implemented by encoding the text into another grammar (a URL) whose
parser is lossy for some of the text's characters, then applying that grammar's rule.

## Root cause analysis
Five Whys:
1. *Why was `#1 Delete` not refused?* The rule never saw `Delete`: it was in the URL
   fragment.
2. *Why was it in the fragment?* The text was spliced into `"/?x=" + text`, and `#`
   starts a fragment in a URL.
3. *Why splice a text into a URL?* `destructive_reason` was the one destructive rule
   (PA-0003), written for URLs; reusing it through a synthetic URL looked like reuse,
   and it worked for every label anyone tried.
4. *Why did no test catch it?* The tests fed labels made of words and spaces; none fed
   a text containing a URL-structural character (`#`, `?`, `&`, `%`).
5. *Why was there no rule against it?* PA-0083(3) requires a gate on an obfuscatable
   signature to match normalised forms **as well as** the raw one; it assumes the raw
   form reaches the gate whole. Nothing required the gate's own input preparation to be
   lossless.

**Root cause:** a gate prepared its input through a lossy adapter (a text embedded in a
URL, parsed by `urlsplit`), so part of the input never reached the rule; tests used only
inputs the adapter happens to preserve.

## Corrective action
- `core.urls.text_destructive_reason(text)` (CC-CORE-0052): the same tokens and pairs
  over the whole text, decoded as the URL rule decodes (up to 3 rounds of `%xx`/`+`),
  never parsed as a URL. `destructive_reason` shares `_destructive_tokens` with it.
- The four sites use it: `spa.form_refusal` (button text and aria-label, control names;
  the route keeps the URL rule and adds the text rule), `store_adapter.entries_refusal`
  (CC-AUD-0039), `formnav.option_refusal` (CC-CRAWL-0024).
- `spa.route_destructive_reason` also judges a SPA fragment as a whole text, so a second
  `#` inside it hides nothing (`/#/a#/logout`).
- Tests: `tests/test_forms_phase4.py::test_a_hash_in_a_label_name_value_or_option_hides_nothing`
  (each site), `::test_the_text_rule_agrees_with_the_url_rule_on_texts_without_a_hash`
  (no behaviour change for texts the old embedding read whole),
  `::test_a_second_hash_in_a_spa_fragment_hides_nothing`. Mutation check: reverting the
  control-name site to the old embedding fails the first test.

## Recurrence review
Checked `docs/bugs/` and `docs/PREVENTIVE_ACTIONS.md` for a gate that did not see its
whole or canonical input:
- **BUG-0082 / PA-0083(3)** — the destructive-payload gate matched only raw text, so
  obfuscated forms (`DR/**/OP`, `%44ROP`) slipped past. Same root-cause family: the gate
  did not evaluate the input in the form that matters. **Match (related root cause).**
- BUG-0084 / PA-0085 (redaction of URL tokens never implemented), BUG-0122 / PA-0122
  (session rules by substring, not canonical tokens), BUG-0086 / PA-0087 (two parsers
  for one policy): related doctrine (one canonical parse), different mechanism; not the
  same root cause.
- No prior bug with a lossy input adapter in front of a gate.

## Prior-preventive-action failure analysis
**PA-0083(3) (from BUG-0082) was too narrow.** It says a gate on an obfuscatable
signature "matches the normalised form as well as the raw one (normalising only adds
refusals)". It covered *adding* forms of the input and was written and enforced at the
payload gate (`catalog.refuse_destructive`). It took for granted that the raw input
reaches the rule intact, and it said nothing about the step that *prepares* a gate's
input — here a lossy embedding that removes part of it before any rule runs. It was
also unenforced outside the mutation catalog: no guard looks at how other gates build
their input. So when the forms phases reused the URL rule for texts, nothing flagged the
embedding.

## Preventive action
**PA-0131** (strengthens PA-0083(3)):
1. A gate judges its **whole** input in the input's **own** grammar: a text by the text
   rule (`core.urls.text_destructive_reason`), a URL by the URL rule. An input is never
   embedded in another grammar's container (a text in a URL, a value in a query string)
   to reuse a rule, where that container's parser can drop or reinterpret part of it.
2. A gate's tests feed inputs carrying the structural characters of every grammar its
   input passes through (`#`, `?`, `&`, `%`, quotes), and assert the refusal.
3. Enforced by an AST guard (`tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url`):
   no call of a URL rule over `fuzzlab/` takes an argument built with a `?`, except a
   listed, reasoned allowance; proven on synthetic offenders
   (`::test_the_text_guard_catches_synthetic_offenders`, PA-0034(2)).

**PA-0002 sweep (by mechanism: every call of `destructive_reason` /
`route_destructive_reason` and every text gate):**
- fixed: `spa.form_refusal` (button, aria-label, control names; route also judged as a
  text), `store_adapter.entries_refusal`, `formnav.option_refusal`,
  `spa.route_destructive_reason` (fragment also judged as a text);
- new code (FR-CRAWL-15/16) uses the text rule from the start: `spa.label_refusal`
  (reveal candidates, menu items, options, checkboxes);
- fine (real URLs): `navguard` route and hops, `fetcher`, `formnav.refusal` (an action
  URL), `store_adapter` (an action or request URL), `session.manager`, `browserlogin`,
  `harness.auto` (URLs and pages), `core.urls.check_send_url`, `spa.classify_route`
  (route characters exclude `#`);
- **not fixed, recorded:** `harness.auto._crawl_url_refusal` re-joins a SPA route's own
  path and query (`route[0] + "?" + route[1]`). These are URL parts, not a text; a second
  `#` inside a fragment is the app's own fragment in Angular's and Vue's routers (the
  route is the part before it), so the route the app shows is judged. Changing it is a
  FUZZ change with no change-control number assigned in this lane; it is the guard's one
  listed allowance and is reported to the orchestrator.
- other text gates (`transaction_reason`, `formnav.settings_word`,
  `browserlogin._account_hit`, `is_sensitive_name`) tokenise texts directly: not
  instances.

## Follow-up (2026-10-14, CC-FUZZ-0077): the recorded residual is fixed
The orchestrator assigned CC-FUZZ-0077 for the one instance the sweep had left.

**Corrective action, added:** `harness.auto._crawl_url_refusal` no longer re-joins a SPA
route's path and query into a URL (`destructive_reason(route[0] + "?" + route[1])`,
which read only what preceded a second `#`). It judges the route's whole fragment as a
text, `core.urls.text_destructive_reason(fragment)`, after the URL rule. A fragment's
path and query give the same tokens either way, so nothing else changes. A crawl point
on `/#/a#/logout`, `/#/a?next=1#delete` or `/#!/x#/sign-out?y=1` is now left out and
reported. Tests:
`tests/test_json_points.py::test_a_second_hash_in_a_spa_route_hides_nothing_from_point_selection`
and `::test_a_destructive_route_behind_a_second_hash_is_never_a_point` (through
`injection_points_from_store`). Mutation check: restoring the re-join fails both tests,
and the AST guard as well.

**PA-0131's guard now has no exceptions:** `_ALLOWED_EMBEDDINGS` in
`tests/test_forms_phase4.py` is empty, and `test_no_text_is_judged_through_a_url` fails
on any URL-rule call over `fuzzlab/` whose argument is built with a `?`.

**Sweep, updated:** every instance found is fixed. The four text gates and
`spa.route_destructive_reason` were fixed in CC-CORE-0052, CC-CRAWL-0024 and CC-AUD-0039.
`harness.auto._crawl_url_refusal` is fixed in CC-FUZZ-0077. There is no residual.
