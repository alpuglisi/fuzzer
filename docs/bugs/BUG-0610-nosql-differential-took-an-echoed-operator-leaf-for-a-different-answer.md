# BUG-0610 — The NoSQL operator differential took an echoed operator leaf for a different answer

- Date: 2026-11-20
- Status: fixed
- Severity: medium (a missed true positive; no false positive)

## Description

`NoSqlOperatorStrategy` (FR-FUZZ-54) compares the answer to an operator that matches
nothing (V, `{"$in": []}`) with the answer to a random string literal (B) and requires
the two to be the same. A JavaScript server that echoes the submitted leaf back into its
page renders the object as `String({...})` = `[object Object]`, while B's echo is B's own
token. The comparison stripped every reflected form of the tokens it sent, but not the
form an object takes when a JavaScript server prints it, so V never looked like B and an
injectable query was never confirmed.

## Where encountered

Lane NODE (CC-LAB-0331), the first live ground-truth run against OWASP NodeGoat at
c5cb68a7: `/login`'s JSON `userName` leaf reaches `usersCol.findOne({userName})`, and the
login page re-renders the submitted name into `<input name="userName" value="...">`.
Measured by hand (2026-11-20): `{"$in":[]}` answers "Invalid username" with
`value="[object Object]"`, `{"$ne":"zz"}` "Invalid password" with the same echo, a string
token "Invalid username" with the token echoed.

## What it caused to fail

NGOAT-0014 (NoSQL injection in `/login` `userName`) scored a false negative: the screen
stopped after three requests (`B`, `V`, `D`) in the BASELINE run (tp=1 of 11).

## What the bug was identified to be

`NoSqlOperatorStrategy.confirm.same()` normalised only the reflections of the string
tokens in `sent`; an operator leaf's reflection, `[object Object]`, stayed in V's and D's
text and made V differ from B.

## Root cause analysis

Five whys:
1. Why was NGOAT-0014 missed? V was judged not the same as B.
2. Why? V's page held `[object Object]` where B's held B's (stripped) token.
3. Why was that not stripped? `same()` strips `_reflection_forms` of the strings it sent,
   and an object is not a string it sent: its echo is the server's coercion of it.
4. Why did no test catch it? Every `tests/test_nosqli.py` server fake answers with a
   fixed message that never echoes the submitted value; PA-0133(2) ("every confirmer has
   a true-positive fixture in a realistic page: the input echoed where real apps echo
   it") was written for evaluation markers' literal echo and applied there, never to the
   differential confirmers.
5. Why was the echo of a non-string value not considered? The differential's
   normalisation was designed for the strings a probe sends, and the one confirmer that
   sends a non-string value (an object) inherited it without asking how the target
   prints that value.

**Root cause:** a differential confirmer normalised the reflections of the values it
sent only as the probe spelled them, not as the target renders them (type coercion of a
non-string JSON value), and no true-positive fixture echoed the input.

## Corrective action

`fuzzlab/oracle/strategies.py` (CC-FUZZ-0611): `_JS_OBJECT_STRING = "[object Object]"`
and `NoSqlOperatorStrategy.confirm.same()` strips its reflected forms with the tokens'.
Soundness is kept: a server that stringifies every object answers V and D alike (both
`[object Object]`, matching nothing), so D is still like B and nothing confirms
(`tests/test_oracle_strategies_ssjs.py::test_nosql_still_refuses_a_server_that_stringifies_every_object`);
the echoing login confirms
(`tests/test_oracle_strategies_ssjs.py::test_nosql_confirms_a_login_that_echoes_the_submitted_leaf`).
Live: NGOAT-0014 confirmed in the AFTER run (CC-LAB-0331); secDevLabs Mongection
unchanged (tp=2 fp=0 fn=0 tn=2, 48 requests, both trees).

## Recurrence review

Checked `docs/bugs/` for differential, reflection and echo defects (BUG-0083, BUG-0089,
BUG-0117, BUG-0127, BUG-0133, BUG-0529) and `docs/PREVENTIVE_ACTIONS.md` (PA-0084,
PA-0094, PA-0117, PA-0133). **Match: BUG-0133 / PA-0133** — a different bug with the
same root cause: a confirmer misjudged a page because the input was echoed in a form
control (M4 refused Juice Shop's evaluated SSTI because its literal sat in the profile's
edit field).

## Prior-preventive-action failure analysis

PA-0133(1) is enforced by an AST guard over evaluation markers' literal checks
(`_echo`), and PA-0133(2) asks for a realistic echoing fixture for "every confirmer"; it
was not applied to the differential confirmers (no test of `NoSqlOperatorStrategy` echoes
anything), and it was **too narrow** in what an echo is: it speaks of "the input echoed",
and the probe's input is an object the page can only show coerced. It was **not
enforced** for differentials: its enforcement tests cover the M4 family only.

## Preventive action

PA-0610 (strengthens PA-0133(2)): a confirmer's normalisation covers every value it
sends as the target renders it (a non-string JSON value as the server stringifies it),
and each differential confirmer has a true-positive fixture whose page echoes the
submitted value. Sweep (PA-0002): every confirmer that sends a non-string value was
read — `NoSqlOperatorStrategy` (fixed); `_differential`'s families and both
server-side JavaScript families send strings only (their reflections are already
stripped); `MassAssignmentPrivilegedFieldStrategy` and `PriceTrustDifferentialStrategy`
read a JSON field's value, not a page comparison; `InsecureDeserializationTypeConfusionStrategy`
compares two positive answers. None other compares a page holding a coerced echo.
