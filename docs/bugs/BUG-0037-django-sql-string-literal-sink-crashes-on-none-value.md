# BUG-0037 — `django` emitter's `sql_string_literal` vulnerable sink crashes (500) instead of failing safely (404) on a missing POST parameter

## Description

`fuzzlab.labgen.emitters.django`'s `sql_string_literal_lookup.py.j2` sink
template (the vulnerable, unbound branch — `CC-LAB-0091`'s Phase B widening
of the `django` emitter) concatenates the tainted `value_expr` directly
into a SQL string with Python's `+` operator, without first casting it to
`str()`. When the source parameter is absent (`request.POST.get(...)`
returns `None`), this raises an unhandled `TypeError` at runtime, which
Django's own request/response cycle turns into a real HTTP `500`.

## Where encountered

`tests/test_labgen_django_live_boot_phase_b.py::
test_login_mismatched_http_method_does_not_widen_attack_surface` — the
`PA-0034` adversarial test `CC-LAB-0091`'s own pre-change review (reviewer
#2) required before that entry could land: a real, executed live-boot
request with a mismatched HTTP method (`GET` instead of `POST`) against the
newly `@csrf_exempt`-decorated `/api/login` view, run against the real,
booted Django app (`fuzzlab.labgen.conformance.django_live_boot.
DjangoLiveBootHarness`).

## What it caused to fail

The test asserted `resp.status == 404` (Django's `request.POST` on a `GET`
request is an empty `QueryDict`, so `request.POST.get("username")` returns
`None`, and the expected, safe behavior is "no row matches its criteria" —
a `404`, matching the existing behavior every other cell in this emitter
already has for a non-matching lookup). Instead, the real HTTP response was
a `500` (Django's own generic error page — confirmed with no stack-trace
leak, since `CC-LAB-0090`'s `DEBUG = False` enforcement is still working
correctly; only the status code and the underlying exception were wrong).
Caught before landing, since `CC-LAB-0091`'s own pre-change review made
this test a required deliverable, not caught after the fact by a
production incident or a later, unrelated test.

## What the bug was identified to be

`fuzzlab/labgen/emitters/django/templates/sinks/
sql_string_literal_lookup.py.j2`'s unbound branch read:

```
"SELECT id, {{ column }} FROM {{ table }} WHERE {{ column }} = '" + {{ value_expr }}
+ "' AND password = '" + {{ password_var }} + "'"
```

With `value_expr` rendering to the Python identifier `username`, and
`username = request.POST.get("username")` evaluating to `None` on a `GET`
request, the generated line becomes (at runtime, not at codegen time):

```python
"SELECT id, username FROM users WHERE username = '" + username + "' AND password = '" + password_hash + "'"
```

`str + None` raises `TypeError: can only concatenate str (not "NoneType")
to str`, uncaught by the generated view, propagating up through Django's
request-handling machinery as an unhandled server error (a real `500`).

## Root cause analysis (Five Whys)

1. **Why did the `GET` request to `/api/login` return a `500`?** Because the
   generated Python view code raised an uncaught `TypeError` while building
   the raw SQL string for the vulnerable twin's lookup.
2. **Why did it raise `TypeError`?** Because `username` (the tainted
   source value) was `None` (the request had no `POST` body to read from),
   and the sink template concatenated it directly with Python's `+`
   operator instead of first casting it with `str(...)`.
3. **Why did the sink template concatenate without casting?** Because it
   was authored (this session, as part of `CC-LAB-0091`) by adapting the
   *shape* of `node_express`'s own `sql_string_literal_lookup.js.j2` sink
   (`"...'" + {{ value_expr }} + "'..."`, in JavaScript, where `+` on a
   string and `undefined`/`null` coerces to text rather than raising) and
   PHP's equivalent (`.` string concatenation, where PHP's loose typing
   coerces `null` to an empty string rather than raising) — without
   noticing that Python's `+` operator has no such coercion, and does not
   behave the same way as its JS/PHP analogs for this specific operation.
4. **Why wasn't this caught before it reached a real HTTP boundary?** Tier 0
   (`python -m py_compile`) only checks syntax, not runtime type behavior
   for a value that is `None` at execution time — a syntactically valid
   line can still raise at runtime depending on the actual value flowing
   through it. The emitter's own happy-path live-boot tests (`test_
   login_normal_credentials_both_twins`, `test_login_sqli_bypass_payload_
   differential`) only ever exercised this sink with a real, non-`None`
   string value, so the `None`-value code path was never actually executed
   until the `PA-0034` adversarial test (a mismatched HTTP method,
   orthogonal to the SQLi shape's own happy-path/attack-path demonstration)
   deliberately exercised it.
5. **Root cause:** the `django` emitter's `sql_string_literal_lookup.py.j2`
   sink template ported the *shape* of an existing, proven module
   (`node_express`'s own sink) across a language boundary without
   re-verifying a language-specific runtime-behavior assumption (whether
   `+`-concatenating a possibly-absent value with a string is safe) that
   does not hold in the new target language, and no test exercised the
   absent-value code path before the `PA-0034`-mandated adversarial test
   did.

## Recurrence review

Checked `docs/bugs/` (all entries, by filename/title) and
`docs/PREVENTIVE_ACTIONS.md` (full read) for a prior occurrence of this
same bug, or a different bug with the same root cause (a cross-language
port silently carrying over a runtime-behavior assumption that doesn't
hold in the new language). **None found.** The closest prior bugs are a
different root-cause class: `BUG-0031`/`PA-0034` (a code-generation
increment's own tests verifying only the design it was written to satisfy,
not an adversarial/orthogonal input — which is exactly what caught *this*
bug, not a prior instance of it) and `BUG-0033` (a capability probe using
the wrong transport, not a cross-language type-coercion mismatch). No
prior-preventive-action failure analysis is needed — this is a new bug
class for this codebase, not a recurrence.

Also checked: `fuzzlab.labgen.emitters.django`'s own sibling sink,
`sql_numeric_lookup.py.j2` (Phase A, `CC-LAB-0090`) — that one already
casts with `str(...)` (`"...= " + str({{ value_expr }})`), so this specific
defect was not present in Phase A's own shape; it was introduced only in
this session's new Phase B sink, which did not consistently apply the same
cast.

## Corrective action

Added the missing `str(...)` cast to `sql_string_literal_lookup.py.j2`'s
unbound branch (landed with `CC-LAB-0091`,
`fuzzlab/labgen/emitters/django/templates/sinks/
sql_string_literal_lookup.py.j2`):

```
"SELECT id, {{ column }} FROM {{ table }} WHERE {{ column }} = '" + str({{ value_expr }})
+ "' AND password = '" + {{ password_var }} + "'"
```

Re-ran `tests/test_labgen_django_live_boot_phase_b.py` for real after the
fix: all 4 tests pass, including the `PA-0034` adversarial test that
originally caught this (now observing the correct real `404`).

## Preventive action (PA-0039, added to `docs/PREVENTIVE_ACTIONS.md`)

**PA-0039 — a cross-language module port must re-verify every
language-specific runtime-behavior assumption the source language's shape
relied on, not just its syntax/structure; a possibly-absent tainted value
concatenated with `+`/string-building in a new sink must be defensively
cast to that language's own string type before concatenation, matching
whatever sibling sink in the same emitter already does this correctly.**
Swept `fuzzlab/labgen/emitters/django/templates/` for every other
`+`-concatenation site (`grep -rn "value_expr\|password_var"`) — the only
other tainted-value concatenation site, `html_body_echo.py.j2`, already
casts correctly (`str({{ value_expr }})`); `sql_numeric_lookup.py.j2`
likewise. No other instance of this bug class found in this emitter. A
future emitter porting a module across a language boundary should run the
same sweep (`PA-0002`'s own convention) before considering that class of
module "ported," not just "renders the same shape."
