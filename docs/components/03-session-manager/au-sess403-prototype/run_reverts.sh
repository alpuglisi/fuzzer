#!/bin/bash
# AU-SESS403 revision 2 (PA-0034(2)): each revert recreates one defect in the prototype,
# and every test named for it must fail. Then the prototype as drafted: every test passes
# but two:
# - T19's whole-package assertion: it reads fuzzlab/'s source, which the run-time
#   prototype cannot change;
# - F3's strict-xfail pin: a stated residual, not in this item.
#
# Sequential, one pytest at a time: the host lock (BUG-0532) makes each run wait.
# Usage: run_reverts.sh <worktree>   (prints one line per revert: selected / failed)
set -u
WT=${1:?worktree}
PROTO=$WT/docs/components/03-session-manager/au-sess403-prototype
F=tests/test_session_forbidden_answers.py
cd "$WT" || exit 2
export PYTHONPATH="$WT:$PROTO" FUZZLAB_PYTEST_LOCK_WAIT=7000

T1=test_a_forbidden_answer_never_logs_in_and_checks_at_most_once
T2=test_a_throttled_answer_never_triggers_anything
T3=test_a_suspected_loss_on_a_live_session_is_checked_once_and_never_logs_in
T4=test_a_credential_submissions_answer_is_checked_never_an_unconfirmed_loss
T4b=test_a_password_change_point_still_recovers_a_real_expiry
T5=test_a_real_expiry_is_recovered_with_one_login_and_one_check
T6=test_a_late_answer_from_an_earlier_session_is_ignored
T7=test_the_single_flight_lock_stops_simultaneous_duplicate_logins
T8=test_concurrent_forbidden_rounds_never_log_in_again
T9=test_each_login_records_the_resource_its_answers_prove
TP1=test_a_401_expiry_on_an_api_route_is_recovered_with_one_login
TP2=test_an_in_place_login_form_expiry_is_recovered_with_one_login
TP3=test_a_basic_expiry_is_recovered_and_a_password_page_is_never_a_signal
TP4=test_an_app_that_ends_sessions_with_403_is_recovered_with_one_login
TP5=test_a_page_that_answers_any_cookie_never_hides_a_real_expiry
TP6=test_a_static_redirect_base_neither_churns_nor_misses_an_expiry
T12=test_an_inconclusive_check_pauses_and_never_changes_the_identity
T14=test_a_live_verdict_is_cached_for_its_window_its_generation_and_its_url
TOFF=test_an_expiry_that_redirects_to_another_origins_login_is_lost_at_its_hop
TM7=test_n_concurrent_signals_make_one_health_get
TM7b=test_a_pause_found_for_an_older_generation_never_pauses_the_new_one
T18=test_a_header_probe_bypasses_a_warm_cache_and_trips_the_breaker_on_its_own_send
T17=test_listeners_hear_only_a_lost_session_and_a_pause_recheck_has_no_culprit
T24=test_the_health_and_login_locks_never_deadlock
T13=test_an_unknown_session_is_sticky_and_costs_nothing_after
T13b=test_the_runs_pause_budget_ends_a_second_pause_early
T15=test_relogins_draw_on_a_refilling_budget
TCP=test_credential_posts_are_counted_and_the_json_control_too
T21=test_verify_live_waits_out_an_unknown_and_then_reads_live
T21b=test_verify_live_never_reads_the_cache
THOP=test_an_unapproved_redirect_from_the_resource_fails_fast_and_never_pauses
TROT=test_a_health_check_never_kills_a_rotating_session
T22=test_prepare_records_the_generation_it_applied
T23=test_request_entry_names_reads_query_form_and_json_leaves_and_is_total
T10=test_detect_logout_reads_a_policy_block_never_as_a_loss
T11=test_detect_logout_keeps_its_loss_signals_and_never_reads_a_throttle

run() {   # run <revert> <node ids...>: every selected test must FAIL
  local revert=$1; shift
  local ids=()
  for t in "$@"; do ids+=("$F::$t"); done
  local out
  out=$(REVERT="$revert" timeout 1200 python3 -m pytest -q -p no:cacheprovider \
        -p proto_plugin --runxfail --tb=no -rf "${ids[@]}" 2>&1)
  local failed passed
  failed=$(grep -c "^FAILED" <<<"$out")
  passed=$(grep -oE "[0-9]+ passed" <<<"$out" | grep -oE "[0-9]+" || echo 0)
  local verdict="OK"
  [ "$failed" -eq "$#" ] || verdict="MASKED"
  echo "REVERT=$revert selected=$# failed=$failed passed=${passed:-0} $verdict"
  if [ "$verdict" != "OK" ]; then
    grep -E "passed|PASSED" <<<"$out" | head -5
  fi
}

run 403 "$T1[admin-403-none]" "$T1[waf-403-none]" "$T1[csrf-403-none]" "$T8[none]" "$T10[403]"
run policy_loss "$T10[451]" "$T10[403]"
run throttle "$T2[redirect]" "$T2[none]" "$T11"
run noconfirm "$T3[scope-401]" "$T3[privilege-login-redirect]"
run nosubmission "$T4[password-401-none]" "$T4[name-only-401-none]"
run submission_ignored "$T4[password-401-redirect]" "$T4[name-only-401-redirect]" "$T4b"
run noentrynames "$T4[name-only-401-none]" "$T23"
run nogen "$T6[redirect]" "$T6[none]"
run nogenrecord "$T22" "$T6[redirect]" "$T6[none]"
run nologinlock "$T7"
run noflight "$TM7"
run nocache "$T1[admin-403-redirect]" "$T1[waf-403-redirect]" "$T1[csrf-403-redirect]" \
    "$T3[scope-401]" "$T3[privilege-login-redirect]" "$T8[redirect]" "$T14"
run cache_nourl "$T14"
run cache_nogen "$T14"
run foreign "$T18"
run rule2verify "$T9[static-None]" "$TP6"
run nocorrupt "$T9[presence-None]" "$TP5"
run norefusal "$T9[forbid-403]" "$TP4"
run publicbase "$T9[none-None]"
run policy_nocheck "$TP4" "$T1[admin-403-redirect]" "$T1[waf-403-redirect]" \
    "$T1[csrf-403-redirect]"
run nostop "$TOFF"
run redirect_live "$T5" "$TP1"
run content_rule_off "$TP2" "$T11"
run basic_content "$TP3"
run inconclusive_lost "$T12"
run inconclusive_live "$T12"
run nosticky "$T13"
run nobudget "$T13b"
run nobucket "$T15[100.0-raises]" "$T15[300.0-200]"
run nocount "$TCP"
run notify_pause "$T17"
run verifylive_false "$T21"
run verifylive_cache "$T21b"
run nocas "$TM7b"
run hop_pauses "$THOP"
run noadopt "$TROT"
run relogin_under_health_lock "$T24"

echo "== the prototype as drafted (no revert)"
REVERT= timeout 1200 python3 -m pytest -q -p no:cacheprovider -p proto_plugin --runxfail \
  --tb=line -rf "$F" 2>&1 | tail -4
