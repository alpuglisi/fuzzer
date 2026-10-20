#!/bin/bash
# The reverts whose proofs changed after the round-4 fixes (framing4 switches, the
# unswallowable smoke alarm, the page-text Token case). Sequential: one pytest at a time.
cd /home/user/fuzzer/.claude/worktrees/agent-a2fdaec634de56899 || exit 1
export PYTHONPATH=/home/user/fuzzer/.claude/worktrees/agent-a2fdaec634de56899:/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-redact
run() {
  echo "== REVERT=$1  (-k $2)"
  REVERT="$1" timeout 1200 python -m pytest -q -p no:cacheprovider -p proto3_plugin --tb=line \
    -rf tests/test_text_body_redaction.py -k "$2" 2>&1 \
    | grep -E "^FAILED|passed|failed|_SmokeAlarm|smoke alarm" \
    | sed -e 's/tests\/test_text_body_redaction.py:://' | cut -c1-170
}
run maxlen0 "decoded_cap_reached"
run recopy "many_gzip_members"
run rawtext_regex "whole_body_scan and (script or style)"
run jwt_regex "whole_body_scan and (eyJ or base64)"
run schemeword "auth_scheme or credential_after"
