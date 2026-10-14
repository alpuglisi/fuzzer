# BUG-0129 — Any page dialog confirmed DOM or stored XSS

- Date: 2026-10-14
- Status: fixed (CC-FUZZ-0074)
- Severity: high for precision. A confirmed false positive on every DOM or stored XSS
  probe of a page that opens a dialog by itself (a welcome `alert`, a `confirm`
  guard, a timed notice). Every such probe also became a positive training label.

## Description
`PlaywrightBrowserExecutor.run` registered `page.on("dialog", …)` and recorded the
probe's token for **any** dialog. Before CC-FUZZ-0073 it did this through
`page.evaluate(sentinel(token))`; after, through `hits.add(token)`. The M6 payloads
(`oracle/strategies._xss_exec_payloads`) never open a dialog: each calls the sentinel
with its token. A dialog therefore carried no information about the probe, yet it
confirmed it.

## Where encountered
Code review of the forms phase 3 review round (38a37e6). Reviewers A and B each found
it independently in the line the round had just rewritten. It was reproduced on a real
browser: a page that runs `alert('hello')` on load and renders the parameter with
`textContent` (inert). The old executor reported `executed=True`.

## What it caused to fail
Precision of M6 (FR-FUZZ-48) on any app with its own dialogs. No live run is known to be
affected: Juice Shop's confirmed `xss-dom` is a real sentinel call (verified, 2.1 s).

## What the bug was identified to be
An evidence channel that does not carry the probe's token (any dialog) was treated as
the probe's own signal.

## Root cause analysis
1. *Why a confirmation?* The dialog handler recorded the token.
2. *Why did it record the token for any dialog?* It was written for `alert(1)`-style
   payloads, and the payloads later changed to a tokened sentinel call. The handler
   kept counting dialogs it could no longer attribute.
3. *Why was that not caught?* Every M6 test page is silent unless the payload runs. No
   test page opened a dialog of its own.
4. *Why did PA-0117's noise guard not catch it?* It runs each strategy against
   payload-independent noise through fake senders and fake executors. Noise produced
   inside the real browser never reached it.

**Root cause:** a signal channel without the probe's token counted as evidence, and the
noise guard covered strategies, not the executor's own evidence channels.

## Corrective action
- The dialog handler only dismisses: `page.on("dialog", lambda d: d.dismiss())`. The
  sentinel binding (CC-FUZZ-0073), called with the probe's token, is the only
  evidence.
- Test: `tests/test_browser_scope.py::test_an_apps_own_dialog_is_never_a_hit` uses real
  Chromium, an app `alert` and `confirm`, and an inert reflection. It is not confirmed,
  and it fails on the old code (`executed=True`).

## Recurrence review
- **BUG-0117 / PA-0117 — the same root cause.** Strategies confirmed on a signature the
  benign page also showed. PA-0117(1): "a fixed signature counts only when it is absent
  from a benign control". PA-0117(3): every strategy runs against payload-independent
  noise.
- **BUG-0089 / PA-0090** (in-band SSRF on a mere reflection) and **BUG-0083 /
  PA-0084**: confirmation on evidence the probe did not cause, in other mechanisms.

## Prior-preventive-action failure analysis
PA-0117 was applied at the **wrong layer** for M6. Its noise guard exercises strategies
with fake executors, so the executor's own evidence channels (dialogs, console,
navigation) were never fed noise. PA-0117(1)'s "absent from a benign control" was never
checked for the dialog channel, because no M6 probe has a benign control: the executor
was trusted to report only payload-caused events.

## Preventive action
**PA-0129** (strengthens PA-0117 at the executor layer): an execution signal counts
only when it carries the probe's own fresh token. A channel that cannot carry it
(dialogs, console messages, generic navigation) is never evidence. Each executor
channel is tested against a real page that produces that channel's noise with an inert
payload.

## PA-0002 sweep
| Site | Channel | Disposition |
|---|---|---|
| `browserexec.py` dialog handler | any dialog | fixed (dismiss only) |
| `browserexec.py` sentinel binding | the token, called by the payload | cleared (tokened) |
| `oracle/browser.FakeBrowserExecutor` | test fake | cleared (tests only) |
| `oracle/oob.OobListener` | hits keyed by a minted token | cleared (tokened) |
| greybox M10 | sink coverage per correlation id | cleared (correlated per probe) |

## Residuals
- A page whose own script calls the sentinel name with our token is impossible without
  the token, which is fresh per probe.
