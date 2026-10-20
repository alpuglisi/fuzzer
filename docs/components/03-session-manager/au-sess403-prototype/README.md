# AU-SESS403 revision 2: the prototype behind the draft's revert proofs

`DRAFT-AU-SESS403.md` §6 names, for every test in
`tests/test_session_forbidden_answers.py`, the revert it must fail against
(PA-0034(2)). Until the design is implemented, those reverts are proven against this
run-time prototype of the design. This is the technique reviewer B used to find the
masked reverts of revision 1.

- `proto.py` patches the drafted behaviour onto `SessionManager` and `session.detect` at
  run time. `REVERT=<name>` undoes one decision. `proto.REVERTS` lists all 43, and
  `run_reverts.sh` runs every one.
- `proto_plugin.py`: `-p proto_plugin`, with this directory on `PYTHONPATH`. A
  `guard_*` revert re-executes T19's guard in the test module with one branch off.
- `run_reverts.sh <worktree>`: each revert against its tests, then the prototype as
  drafted.

Nothing here is part of `fuzzlab/`, and pytest never collects it. Phase 2 implements the
design in `fuzzlab/session/` and deletes this directory in the same change.
