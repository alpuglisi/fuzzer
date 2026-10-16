# Shared primitives

The mechanisms in this project that have **exactly one implementation**. Every
component that needs one of these decisions calls its owner; nothing re-derives it.
`tests/test_shared_primitives.py` checks this table: every owner exists, no other
module of `fuzzlab/` defines a function or class of the owner's name, and every
guard test named below exists.

**Why this table exists.** In the retrospective of BUG-0110..BUG-0139, a fix or rule
for a shared mechanism that was not swept across all its callers was a cause in 11 of
the 25 bugs (class T3). The longest chain (C1: BUG-0123, 0126, 0128, 0134, 0136, 0137,
0138) was one browser primitive whose every fix broke its next consumer. The
recurrences that did not happen were the ones a whole-package guard caught.

**The rule (see `CLAUDE.md`, definition of done).** A change to the behaviour of a
primitive listed here:

1. is made in its owner only;
2. sweeps **every caller** of the owner (`grep` the owner's name over `fuzzlab/` and
   `tests/`), and follows the change to every consumer that waits on or reads what it
   changed (PA-0138(3)), not only the path its bug came from;
3. updates this table in the same change (a new owner, a new guard, a new primitive);
4. is verified with `scripts/verify_change.py`, which always runs every guard below.

A new mechanism that two or more components must agree on gets a row here, an owner,
and a guard: an AST guard where one is possible (proven on a synthetic offender,
PA-0034(2)), otherwise at least the defined-once check this table already applies.

| ID | Mechanism | Owner | Guard test(s) | From |
|---|---|---|---|---|
| SP-01 | Navigating a guarded page and waiting for its load state | `fuzzlab/tools/navguard.py::navigate` (with `reload`, `wait_for_state`, `load_state_reached`) | `tests/test_guarded_navigation.py::test_every_guarded_navigation_goes_through_the_one_helper`, `tests/test_guarded_navigation.py::test_the_navigation_guard_catches_synthetic_offenders` | PA-0138 |
| SP-02 | How a refused browser request is aborted (the abort code) | `fuzzlab/tools/navguard.py::_abort_code` | `tests/test_navigation_aborts.py::test_every_abort_reason_keeps_the_document_for_a_navigation`, `tests/test_shared_primitives.py::test_route_aborts_happen_only_in_navguard` | PA-0136 |
| SP-03 | Chromium launch configuration (headless, scoped args, the operator's binary) | `fuzzlab/tools/navguard.py::chromium_launch_kwargs` | `tests/test_browser_scope.py::test_the_launch_sites_are_the_four_known_ones`, `tests/test_browser_scope.py::test_the_browser_guard_catches_synthetic_offenders` | PA-0126 |
| SP-04 | Browser launch confinement (no proxy, resolver rules per scope origin) | `fuzzlab/tools/navguard.py::browser_launch_args` | `tests/test_browser_scope.py::test_launch_args_disable_the_proxy_and_resolve_only_scope_origins`, `tests/test_browser_scope.py::test_every_browser_path_in_fuzzlab_is_scoped` | PA-0123 |
| SP-05 | The origin key of a URL (scheme, canonical host, port) | `fuzzlab/core/urls.py::canonical_origin` | `tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0123, PA-0134 |
| SP-06 | Is a URL in an origin scope | `fuzzlab/core/urls.py::in_origin_scope` | `tests/test_browser_scope.py::test_origin_scope_is_scheme_host_and_port`, `tests/test_browser_scope.py::test_the_route_handler_has_no_unscoped_form` | PA-0123 |
| SP-07 | How an explicit allowance names a URL (origin plus path) | `fuzzlab/core/urls.py::url_key` | `tests/test_destructive_urls.py::test_the_send_gate_refuses_unless_explicit_and_keys_canonically`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0083 |
| SP-08 | Which document a URL loads (origin, path and query) | `fuzzlab/core/urls.py::document_key` | `tests/test_guarded_navigation.py::test_a_same_path_document_with_another_query_never_fills_this_urls_row`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | BUG-0138 |
| SP-09 | Is a URL destructive (and the send gate built on it) | `fuzzlab/core/urls.py::destructive_reason` (gate: `check_send_url`) | `tests/test_destructive_urls.py::test_every_probe_sender_calls_the_send_gate`, `tests/test_destructive_urls.py::test_the_sender_guard_catches_a_synthetic_offender` | PA-0083, PA-0114 |
| SP-10 | Is a text (label, control name, option) destructive | `fuzzlab/core/urls.py::text_destructive_reason` | `tests/test_forms_phase4.py::test_no_text_is_judged_through_a_url` | PA-0131 |
| SP-11 | Does a route, label or request name a transaction | `fuzzlab/core/urls.py::transaction_reason` | `tests/test_transaction_words.py::test_every_word_is_refused_as_a_label_a_route_and_a_url`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0003 |
| SP-12 | May credentials (or a login navigation) go to a URL | `fuzzlab/session/manager.py::SessionManager._credential_destination_ok` | `tests/test_session_credential_destination.py::test_every_allow_path_is_overridden_by_the_deny`, `tests/test_session_credential_destination.py::test_a_cross_origin_form_action_gets_no_credentials` | PA-0082, PA-0093, PA-0098 |
| SP-13 | Which origins a secret-bearing session may be sent to | `fuzzlab/session/state.py::SessionState.origins` | `tests/test_session_origin_scope.py::test_no_session_send_decision_compares_hosts` | PA-0134 |
| SP-14 | Is a cookie a credential or ambient | `fuzzlab/session/manager.py::credential_cookie` | `tests/test_session_browser_login.py::test_one_predicate_tells_credential_cookies_from_ambient_ones` | PA-0007, PA-0003 |
| SP-15 | The session state carried from one client to another | `fuzzlab/session/manager.py::_jar_cookies` | `tests/test_session_browser_login.py::test_jar_cookies_are_host_scoped_unexpired_and_secure_only_over_https`, `tests/test_shared_primitives.py::test_every_owner_is_defined_once` | PA-0132 |
| SP-16 | Is a URL a login URL (session and auth state) | `fuzzlab/session/detect.py::looks_like_login_url` | `tests/test_logout_redirect.py::test_no_substring_test_decides_session_or_auth_state`, `tests/test_logout_redirect.py::test_the_guard_catches_a_synthetic_offender` | PA-0122 |
| SP-17 | Is a name sensitive (redaction) | `fuzzlab/core/redaction.py::is_sensitive_name` | `tests/test_proxy_redaction.py::test_logs_use_the_same_predicate`, `tests/test_storage_redaction.py::test_every_traffic_producer_goes_through_the_redaction_boundary` | PA-0085, PA-0100 |
| SP-18 | Does a value look like an identifier (redaction, pinning) | `fuzzlab/core/redaction.py::looks_like_identifier` | `tests/test_identifier_predicate.py::test_defined_once` | PA-0003 |
| SP-19 | Is a form a credential-change form | `fuzzlab/tools/store_adapter.py::credential_change_rule` | `tests/test_json_points.py::test_the_credential_change_rule_is_one_function_shared_with_forms` | PA-0003 |
| SP-20 | The probe sender protocol, its implementations and wrappers | `fuzzlab/oracle/probe.py::Sender` | `tests/test_sender_conformance.py::test_every_seam_class_accepts_the_full_protocol_signature`, `tests/test_sender_conformance.py::test_every_wrapper_forwards_every_protocol_argument`, `tests/test_sender_conformance.py::test_the_placement_check_catches_a_relocating_sender` | PA-0072, PA-0115 |
| SP-21 | Complexity claims are measured by operation counts (the wall-clock guard) | `fuzzlab/tools/spa.py::StepCounter` | `tests/test_no_wall_clock_ratio.py::test_no_test_asserts_a_wall_clock_ratio`, `tests/test_no_wall_clock_ratio.py::test_the_guard_catches_bug_0135_and_each_synthetic_offender` | PA-0135 |
| SP-22 | Starting and stopping a child process tree | `fuzzlab/procutil.py::start_server` (with `run_bounded`) | `tests/test_procutil_guard.py::test_every_child_process_goes_through_procutil`, `tests/test_procutil_guard.py::test_guard_flags_synthetic_offenders` | PA-0125 |
| SP-23 | A listener binds loopback only | `fuzzlab/core/net.py::require_loopback` | `tests/test_loopback_listeners.py::test_every_listener_in_fuzzlab_is_gated`, `tests/test_loopback_listeners.py::test_every_server_launched_through_procutil_pins_loopback` | PA-0081, PA-0130 |
| SP-24 | Does a script container execute | `fuzzlab/oracle/context.py::script_executes` | `tests/test_oracle_xss_structural.py::test_script_executes_is_the_one_predicate` | PA-0094 |
| SP-25 | Where a probe's literal is echoed (a confirmer's disqualifier) | `fuzzlab/oracle/strategies.py::_echo` | `tests/test_evaluation_marker_echo.py::test_no_strategy_judges_its_literal_by_a_raw_substring`, `tests/test_evaluation_marker_echo.py::test_the_literal_guard_catches_the_old_rule` | PA-0133 |
| SP-26 | Which categories a parameter's value shape selects | `fuzzlab/audit/value_shape.py::SHAPE_CATEGORIES` | `tests/test_open_redirect_seed.py::test_every_shape_has_a_row_and_the_rules_match_the_table` | PA-0124 |
| SP-27 | Which model row is current for a run | `fuzzlab/ml/model_registry.py::select_latest` | `tests/test_ml_model_selection.py::test_no_module_reads_model_as_newest_row_of_any_family`, `tests/test_ml_model_selection.py::test_guard_catches_the_buggy_shapes` | PA-0063, PA-0067 |
| SP-28 | The out-of-fold partition behind every held-out number | `fuzzlab/ml/metrics.py::oof_folds` | `tests/test_ml_oof.py::test_no_out_of_fold_scorer_bypasses_oof_folds`, `tests/test_ml_oof.py::test_guard_counts_a_raw_group_kfold_call` | PA-0064 |
| SP-29 | Which labels are sealed (holdout) | `fuzzlab/ml/holdout.py::sealed_split` | `tests/test_ml_holdout_seal.py::test_every_metric_input_call_says_whether_the_row_is_sealed`, `tests/test_ml_holdout_seal.py::test_no_trainer_or_reader_uses_the_today_only_split` | PA-0092 |
| SP-30 | Writing a secret file (0600 from creation, complete or raising) | `fuzzlab/core/secretfile.py::write_secret` | `tests/test_shared_primitives.py::test_every_owner_is_defined_once`, `tests/test_secretfile.py::test_a_planted_symlink_is_not_followed` | PA-0080, PA-0097 |
| SP-31 | Starting a server and knowing it is up: its own process listens on its port | `fuzzlab/procutil.py::start_server_on_free_port` (with `port_owner`, `wait_until_listening`, `free_port`) | `tests/test_server_port_ownership.py::test_every_started_server_is_checked_for_owning_its_port`, `tests/test_server_port_ownership.py::test_the_guard_catches_a_bare_connect_boot` | PA-0149 |
| SP-32 | The Laravel live boot's locked dependencies, installed once per host | `fuzzlab/labgen/conformance/live_boot.py::cached_vendor` (with `materialize_vendor`) | `tests/test_live_boot_vendor_cache.py::test_the_harness_never_runs_a_per_boot_install`, `tests/test_live_boot_vendor_cache.py::test_each_app_gets_its_own_autoloader_and_shared_package_files` | PA-0148 |
| SP-33 | The Django live boot's pinned environment, built once per host | `fuzzlab/labgen/conformance/django_live_boot.py::cached_venv` | `tests/test_live_boot_vendor_cache.py::test_the_django_harness_never_builds_a_per_boot_environment`, `tests/test_live_boot_vendor_cache.py::test_the_pinned_django_environment_is_built_once_per_host` | PA-0148 |
| SP-34 | A probe that got no complete response: transport failure classified as "not observed", "timeout" or loud | `fuzzlab/tools/probesender.py::_unobserved` (with `_is_timeout`; raising `ProbeUnobserved`) | `tests/test_probe_unobserved.py::test_every_http_sender_maps_a_transport_failure`, `tests/test_probe_unobserved.py::test_the_sender_guard_finds_a_new_sender`, `tests/test_probe_unobserved.py::test_a_target_that_cannot_be_reached_fails_loudly` | PA-0153 |
| SP-35 | Which send rules a run enforces (destructive, transactions, credential changes; D71) | `fuzzlab/core/sendpolicy.py::enforced` (filters `destructive`, `transaction`, `credential_change`; set by `apply`) | `tests/test_send_policy.py::test_destructive_rule_on_and_off_at_its_refusal_sites`, `tests/test_send_policy.py::test_the_login_flow_keeps_every_rule_whatever_the_flags` | D71 |
| SP-36 | What a captured request's headers may store (allowlisted, non-secret; a credential header named, never its value) | `fuzzlab/core/redaction.py::redact_captured_headers` | `tests/test_crawl_survey_options.py::test_only_allowlisted_non_secret_headers_are_kept`, `tests/test_crawl_survey_options.py::test_a_captured_requests_headers_are_stored_redacted_and_an_old_db_gains_the_column` | PA-0100 |
