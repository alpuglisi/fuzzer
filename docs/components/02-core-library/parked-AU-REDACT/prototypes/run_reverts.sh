#!/bin/bash
# Each revert re-creates one defect in the prototypes; the named tests must fail against it.
# Runs sequentially: one pytest at a time on this host.
cd /home/user/fuzzer/.claude/worktrees/agent-a2fdaec634de56899 || exit 1
export PYTHONPATH=/home/user/fuzzer/.claude/worktrees/agent-a2fdaec634de56899:/tmp/claude-0/-home-user-fuzzer/2f299c5d-40a8-582c-a2d4-d0cdcbec2db1/scratchpad/au-redact
run() {
  echo "== REVERT=$1  (-k $2)"
  REVERT="$1" timeout 1200 python -m pytest -q -p no:cacheprovider -p proto3_plugin --tb=line \
    -rf tests/test_text_body_redaction.py -k "$2" 2>&1 \
    | grep -E "^FAILED|passed|failed|TimeoutError|smoke alarm" \
    | sed -e 's/tests\/test_text_body_redaction.py:://' | cut -c1-160
}
run maxlen0 "decoded_cap_reached"
run recopy "many_gzip_members"
run jsontext "sniffed_json or repeated_names"
run cutfirst "before_cutting or target_blank"
run idblank "dedup_key"
run anyunquoted "scripts_keep"
run bindnothing "unprovable_and_unusual"
run nocap "bounded_work_on_crafted"
run rawtext_regex "whole_body_scan and (script or style)"
run jwt_regex "whole_body_scan and (eyJ or base64)"
run skeleton_unbounded "whole_body_scan and skeleton"
run privatefield "scripts_keep"
run rev3framing "desync or precompressed"
run jsonomit "unparseable_declared_json or cut_json"
run schemeword "auth_scheme or credential_after"
