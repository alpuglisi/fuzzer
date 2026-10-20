# AU-REDACT (audit defect 26) — parked by the owner, 2026-10-20

Paused at revision 4 of the design, before its final review round and before any
`fuzzlab/` change. Nothing here runs: the test module is renamed so pytest never collects
it, and the prototypes live outside the package.

- `DRAFT-CC-CORE-0067.md` — the design, revision 4 (reviews: rounds 1–3 both reviewers
  DISAGREE; revision 4 answers round 3's blockers B1–B7 and the adopted items).
- `parked_test_text_body_redaction.py` — 255 cases (on 8100959: 199 fail on their own
  canary/marker assertion, 54 stated controls pass, 2 strict xfails; 0 fail with the
  revision-4 prototypes patched in). Restore as `tests/test_text_body_redaction.py`.
- `body_redaction/` — its fixtures (restore as `tests/data/body_redaction/`).
- `prototypes/` — `proto3.py` (text pass), `framing4.py` (framed proxy bodies),
  `proto3_plugin.py` (patches them in for the tests), revert and cost scripts.

To resume: register the item again, restore the three paths, send revision 4 to its
final review round, then implement in `core/redaction.py`, `proxy/redact.py`,
`proxy/history.py`, `tools/spider.py` (text, title), `tools/fetcher.py` and the importer
under CC-CORE-0067, CC-CRAWL-0051, CC-PROXY-0028, CC-AUD-0057 (BUG-0527, PA-0527,
FR-CORE-506, SP-55). The defect stays open until then.
