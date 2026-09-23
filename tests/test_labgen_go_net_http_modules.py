"""Module-composition unit tests for `go_net_http` (category 4 pilot,
`CC-LAB-0170`/`FR-LAB-76` Phase A, `CC-LAB-0172`/`FR-LAB-78` Phase B).

Mirrors `tests/test_labgen_node_express_modules.py`'s convention exactly,
scoped to `fuzzlab.labgen.emitters.go_net_http.modules`'s own registries
and templates (a separate, self-contained module inventory).
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.go_net_http.modules import (
    COMPLEXITIES,
    SINKS,
    SOURCES,
    TRANSFORMS,
    _COMPLEXITY_ENV,
    _SINK_ENV,
    _SOURCE_ENV,
    _TRANSFORM_ENV,
    render_route_line,
)


def test_module_environments_set_determinism_flags_explicitly() -> None:
    for env in (_SOURCE_ENV, _TRANSFORM_ENV, _SINK_ENV, _COMPLEXITY_ENV):
        assert env.trim_blocks is True
        assert env.lstrip_blocks is True
        assert env.keep_trailing_newline is True


def test_read_webhook_signature_source_publishes_naive_comparison_by_default() -> None:
    result = SOURCES["read_webhook_signature"].render({})
    assert "hmac.New(sha256.New, webhookSecret)" in result.code
    assert result.context["computed_var"] == "computed"
    assert result.context["header_var"] == "headerSig"
    assert result.context["value_expr"] == "headerSig == computed"


def test_naive_string_compare_transform_leaves_naive_comparison() -> None:
    ctx = {"header_var": "headerSig", "computed_var": "computed"}
    result = TRANSFORMS["naive_string_compare"].render(ctx)
    assert result.context["value_expr"] == "headerSig == computed"
    assert "==" in result.code


def test_constant_time_compare_transform_publishes_hmac_equal() -> None:
    ctx = {"header_var": "headerSig", "computed_var": "computed"}
    result = TRANSFORMS["constant_time_compare"].render(ctx)
    assert result.context["value_expr"] == "hmac.Equal([]byte(headerSig), []byte(computed))"
    assert "hmac.Equal" in result.code


def test_webhook_signature_verification_sink_branches_on_value_expr() -> None:
    ctx = {"value_expr": "hmac.Equal([]byte(headerSig), []byte(computed))"}
    result = SINKS["webhook_signature_verification"].render(ctx)
    assert "if hmac.Equal([]byte(headerSig), []byte(computed)) {" in result.code
    assert "http.StatusOK" in result.code
    assert "http.StatusUnauthorized" in result.code


def test_render_only_complexity_wraps_body_in_handler_func() -> None:
    result = COMPLEXITIES["render_only"].render({"body": "\tdoSomething()", "handler_name": "handleTest"})
    assert result.code.startswith("func handleTest(w http.ResponseWriter, r *http.Request) {")
    assert "doSomething()" in result.code


def test_render_route_line_uses_method_pattern_syntax() -> None:
    line = render_route_line(method="POST", path="/generated/labgen-go-0001", handler_name="handleLabgenGo0001")
    assert line.strip() == 'mux.HandleFunc("POST /generated/labgen-go-0001", handleLabgenGo0001)'


# -- CC-LAB-0172 Phase B: SSRF (server_side_http_fetch) -----------------------


def test_read_url_query_param_source_reads_the_named_query_param() -> None:
    result = SOURCES["read_url_query_param"].render({"var_name": "targetUrl", "param_name": "url"})
    assert result.code.strip() == 'targetUrl := r.URL.Query().Get("url")'


def test_unchecked_url_fetch_sink_has_no_validation_before_fetching() -> None:
    result = SINKS["unchecked_url_fetch"].render({"var_name": "targetUrl"})
    assert "client.Get(targetUrl)" in result.code
    assert "http.Client{Timeout:" in result.code
    assert "url.Parse" not in result.code
    assert "LookupIP" not in result.code


def test_scheme_and_resolved_ip_allowlist_sink_rejects_non_https_and_checks_resolved_ip() -> None:
    result = SINKS["scheme_and_resolved_ip_allowlist"].render({"var_name": "targetUrl"})
    assert 'parsed.Scheme != "https"' in result.code
    assert "net.LookupIP(parsed.Hostname())" in result.code
    assert "ip.IsLoopback()" in result.code
    assert "ip.IsPrivate()" in result.code
    assert "ip.IsLinkLocalUnicast()" in result.code
    assert "http.Client{Timeout:" in result.code


# -- Phase B increment 2: access-control / IDOR (db_row_by_id_lookup) --------


def test_read_channel_id_and_broadcaster_header_source_publishes_vulnerable_default() -> None:
    result = SOURCES["read_channel_id_and_broadcaster_header"].render({"param_name": "channel_id"})
    assert result.code.strip() == (
        'channelID := r.URL.Query().Get("channel_id")\n'
        'broadcasterID := r.Header.Get("X-Broadcaster-Id")'
    )
    assert result.context["channel_id_var"] == "channelID"
    assert result.context["broadcaster_var"] == "broadcasterID"
    assert result.context["value_expr"] == "true"   # vulnerable by default: no check at all


def test_no_ownership_check_transform_leaves_the_always_true_default() -> None:
    ctx = {"channel_id_var": "channelID", "broadcaster_var": "broadcasterID"}
    result = TRANSFORMS["no_ownership_check"].render(ctx)
    assert result.context["value_expr"] == "true"


def test_identity_match_before_fetch_transform_requires_matching_ids() -> None:
    ctx = {"channel_id_var": "channelID", "broadcaster_var": "broadcasterID"}
    result = TRANSFORMS["identity_match_before_fetch"].render(ctx)
    assert result.context["value_expr"] == "channelID == broadcasterID"


def test_object_lookup_authorization_check_sink_branches_on_value_expr() -> None:
    ctx = {"value_expr": "channelID == broadcasterID", "channel_id_var": "channelID",
           "broadcaster_var": "broadcasterID"}
    result = SINKS["object_lookup_authorization_check"].render(ctx)
    assert "if channelID == broadcasterID {" in result.code
    assert "http.StatusOK" in result.code
    assert "http.StatusForbidden" in result.code
    assert "subscriber_count" in result.code
    assert "_ = broadcasterID" in result.code   # always used, even on the vulnerable path


# -- Phase B increment 3: JWT alg:none confusion (jwt_signature_verification) --


def test_read_authorization_bearer_token_source_publishes_vulnerable_default() -> None:
    result = SOURCES["read_authorization_bearer_token"].render({})
    assert 'authHeader := r.Header.Get("Authorization")' in result.code
    assert "hmac.Equal(expectedSig, sigBytes)" in result.code
    assert result.context["alg_none_var"] == "algIsNone"
    assert result.context["alg_hs256_var"] == "algIsHS256"
    assert result.context["hmac_valid_var"] == "hmacValid"
    assert result.context["claims_var"] == "claimsJSON"
    # vulnerable by default: an alg:none token bypasses the HMAC check entirely
    assert result.context["value_expr"] == "algIsNone || hmacValid"


def test_jwt_alg_none_default_transform_leaves_the_bypass_default() -> None:
    ctx = {"alg_none_var": "algIsNone", "alg_hs256_var": "algIsHS256", "hmac_valid_var": "hmacValid"}
    result = TRANSFORMS["jwt_alg_none_default"].render(ctx)
    assert result.context["value_expr"] == "algIsNone || hmacValid"


def test_jwt_none_alg_opt_in_transform_requires_pinned_algorithm_and_valid_hmac() -> None:
    ctx = {"alg_none_var": "algIsNone", "alg_hs256_var": "algIsHS256", "hmac_valid_var": "hmacValid"}
    result = TRANSFORMS["jwt_none_alg_opt_in"].render(ctx)
    assert result.context["value_expr"] == "algIsHS256 && hmacValid"


def test_jwt_claims_response_sink_branches_on_value_expr() -> None:
    ctx = {"value_expr": "algIsHS256 && hmacValid", "alg_none_var": "algIsNone",
           "alg_hs256_var": "algIsHS256", "claims_var": "claimsJSON"}
    result = SINKS["jwt_claims_response"].render(ctx)
    assert "if algIsHS256 && hmacValid {" in result.code
    assert "http.StatusOK" in result.code
    assert "http.StatusUnauthorized" in result.code
    assert "channel_id" in result.code
    # both identifiers guarded, even though only one is referenced by value_expr
    assert "_, _ = algIsNone, algIsHS256" in result.code


# -- Phase B increment 4: predictable session token (session_token_generation) --


def test_no_op_token_request_source_publishes_nothing() -> None:
    result = SOURCES["no_op_token_request"].render({})
    assert "tainted request input at all" in result.code
    assert result.context == {}


def test_predictable_token_source_sink_uses_unix_nano_timestamp() -> None:
    result = SINKS["predictable_token_source"].render({})
    assert "time.Now().UnixNano()" in result.code
    assert "session_token" in result.code


def test_csprng_token_sink_uses_crypto_rand() -> None:
    result = SINKS["csprng_token"].render({})
    assert "rand.Read(buf)" in result.code
    assert "hex.EncodeToString(buf)" in result.code
    assert "session_token" in result.code


def test_read_channel_profile_body_source_publishes_default_body_var() -> None:
    result = SOURCES["read_channel_profile_body"].render({})
    assert "io.ReadAll(r.Body)" in result.code
    assert result.context["body_var"] == "reqBody"


def test_unfiltered_object_assign_sink_unmarshals_onto_the_full_record() -> None:
    result = SINKS["unfiltered_object_assign"].render({"body_var": "reqBody"})
    assert "json.Unmarshal(reqBody, &channel)" in result.code
    assert "IsPartner   bool" in result.code
    # No separate allowlisted DTO struct -- the whole record is the target.
    assert "var update struct" not in result.code


def test_typed_schema_allowlist_sink_only_copies_the_dto_fields() -> None:
    result = SINKS["typed_schema_allowlist"].render({"body_var": "reqBody"})
    assert "var update struct" in result.code
    assert "json.Unmarshal(reqBody, &update)" in result.code
    assert "channel.DisplayName = update.DisplayName" in result.code
    assert "channel.Bio = update.Bio" in result.code
    # The DTO struct itself never declares `is_partner` -- no field to
    # unmarshal into even if the client sends the key.
    assert "IsPartner" not in result.code.split("var update struct", 1)[1].split("}", 1)[0]
