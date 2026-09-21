"""Module-composition unit tests (T-LAB0.4).

Each fragment under `fuzzlab/labgen/modules/{sources,transforms,sinks,
complexities}/` renders correctly in isolation, and the Jinja2 environments
that render them have the determinism-relevant flags set explicitly (never
left at Jinja2's defaults), per `docs/LAB_PHASE_0_PLAN.md`'s own rule.
"""

from __future__ import annotations

from fuzzlab.labgen.modules import (
    COMPLEXITIES,
    SINKS,
    SOURCES,
    TRANSFORMS,
    _COMPLEXITY_ENV,
    _SINK_ENV,
    _SOURCE_ENV,
    _TRANSFORM_ENV,
)


def test_module_environments_set_determinism_flags_explicitly() -> None:
    for env in (_SOURCE_ENV, _TRANSFORM_ENV, _SINK_ENV, _COMPLEXITY_ENV):
        assert env.trim_blocks is True
        assert env.lstrip_blocks is True
        assert env.keep_trailing_newline is True


def test_get_param_source_renders_extraction_and_publishes_value_expr() -> None:
    ctx = {"var_name": "id", "param_name": "id"}
    result = SOURCES["get_param"].render(ctx)
    assert "$_GET['id']" in result.code
    assert "$id = " in result.code
    assert result.context["value_expr"] == "$id"
    assert result.context["bound"] is False


def test_identity_transform_leaves_bound_false() -> None:
    ctx = {"value_expr": "$id", "bound": False}
    result = TRANSFORMS["identity"].render(ctx)
    assert "$id" in result.code
    assert result.context["bound"] is False


def test_param_bind_transform_sets_bound_true() -> None:
    ctx = {"value_expr": "$id", "bound": False}
    result = TRANSFORMS["param_bind"].render(ctx)
    assert result.context["bound"] is True
    # The transform's own fragment never emits a literal SQL query -- that
    # is the sink's job; it only documents the binding decision.
    assert "SELECT" not in result.code.upper()


def test_sql_numeric_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {"value_expr": "$id", "bound": False, "table": "products", "column": "id"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert '"SELECT * FROM products WHERE id = " . $id' in result.code
    assert "prepare(" not in result.code


def test_sql_numeric_lookup_sink_renders_prepared_statement_when_bound() -> None:
    ctx = {"value_expr": "$id", "bound": True, "table": "products", "column": "id"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert "$stmt = $pdo->prepare(" in result.code
    assert "$stmt->execute([$id])" in result.code
    assert '" . $id' not in result.code


def test_single_statement_complexity_wraps_body_in_one_function() -> None:
    ctx = {"body": "    // body\n", "handler_name": "handle_x"}
    result = COMPLEXITIES["single_statement"].render(ctx)
    assert result.code.startswith("function handle_x(PDO $pdo) {\n")
    assert "// body" in result.code
    assert result.code.rstrip("\n").endswith("}")


def test_post_param_source_renders_extraction_from_post_and_publishes_value_expr() -> None:
    ctx = {"var_name": "username", "param_name": "username"}
    result = SOURCES["post_param"].render(ctx)
    assert "$_POST['username']" in result.code
    assert "$username = " in result.code
    assert result.context["value_expr"] == "$username"
    assert result.context["bound"] is False


def test_read_stored_field_source_renders_a_non_request_assignment() -> None:
    ctx = {"var_name": "bio", "stored_expr": "$currentUser['bio']"}
    result = SOURCES["read_stored_field"].render(ctx)
    assert result.code.strip() == "$bio = $currentUser['bio'];"
    assert result.context["value_expr"] == "$bio"
    assert "$_GET" not in result.code
    assert "$_POST" not in result.code


def test_html_entity_escape_transform_wraps_value_expr_in_htmlspecialchars() -> None:
    ctx = {"value_expr": "$bio"}
    result = TRANSFORMS["html_entity_escape"].render(ctx)
    assert result.context["value_expr"] == "htmlspecialchars($bio)"
    assert "SELECT" not in result.code.upper()


def test_sql_string_literal_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {
        "value_expr": "$username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "WHERE username = '\" . $username . \"'" in result.code
    assert "prepare(" not in result.code
    assert "md5(" in result.code


def test_sql_string_literal_lookup_sink_renders_prepared_statement_when_bound() -> None:
    ctx = {
        "value_expr": "$username",
        "bound": True,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "$stmt = $pdo->prepare(" in result.code
    assert "$stmt->execute([$username, $password_hash])" in result.code
    assert "\" . $username" not in result.code


def test_html_body_echo_sink_renders_an_echo_of_value_expr() -> None:
    ctx = {"value_expr": "$bio", "css_class": "bio"}
    result = SINKS["html_body_echo"].render(ctx)
    assert result.code.strip() == "echo '<div class=\"bio\">' . $bio . '</div>';"


def test_html_body_echo_sink_reflects_whatever_value_expr_it_is_given() -> None:
    # The sink doesn't know or care whether value_expr was escaped -- that's
    # entirely the upstream transform's responsibility (see
    # HtmlEntityEscapeTransform's docstring).
    raw = SINKS["html_body_echo"].render({"value_expr": "$bio", "css_class": "bio"})
    escaped = SINKS["html_body_echo"].render({"value_expr": "htmlspecialchars($bio)", "css_class": "bio"})
    assert "htmlspecialchars" not in raw.code
    assert "htmlspecialchars($bio)" in escaped.code


def test_render_only_complexity_wraps_body_with_no_return_statement() -> None:
    ctx = {"body": "    // body\n", "handler_name": "handle_x"}
    result = COMPLEXITIES["render_only"].render(ctx)
    assert result.code.startswith("function handle_x() {\n")
    assert "return" not in result.code
    assert result.code.rstrip("\n").endswith("}")


# Per-module minimal context sufficient to render each fragment, used only to
# check every module is internally deterministic (byte-identical across two
# calls with the same input) -- not to check each module's actual output
# shape, which the tests above already cover per module.
_DETERMINISM_CTX_BY_MODULE: dict[str, dict[str, object]] = {
    "get_param": {"var_name": "id", "param_name": "id"},
    "post_param": {"var_name": "username", "param_name": "username"},
    "read_stored_field": {"var_name": "bio", "stored_expr": "$currentUser['bio']"},
    "identity": {"value_expr": "$id"},
    "param_bind": {"value_expr": "$id"},
    "html_entity_escape": {"value_expr": "$bio"},
    "sql_numeric_lookup": {"value_expr": "$id", "bound": False, "table": "products", "column": "id"},
    "sql_string_literal_lookup": {
        "value_expr": "$username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    },
    "html_body_echo": {"value_expr": "$bio", "css_class": "bio"},
    "single_statement": {"body": "    // x\n", "handler_name": "handle_x"},
    "render_only": {"body": "    // x\n", "handler_name": "handle_x"},
}


def test_every_module_renders_deterministically_twice() -> None:
    for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES):
        for name, module in registry.items():
            ctx = _DETERMINISM_CTX_BY_MODULE[name]
            first = module.render(dict(ctx))
            second = module.render(dict(ctx))
            assert first.code == second.code, f"{name} module is non-deterministic"


def test_every_registered_module_has_a_determinism_ctx_fixture() -> None:
    # Guards against a new module being added to a registry without also
    # being added to _DETERMINISM_CTX_BY_MODULE above (a silent test gap).
    all_names = {name for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES) for name in registry}
    assert all_names == set(_DETERMINISM_CTX_BY_MODULE)
