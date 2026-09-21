"""Module-composition unit tests for `node_express` (L-P3.1).

Mirrors `tests/test_labgen_modules.py`'s convention exactly, scoped to
`fuzzlab.labgen.emitters.node_express.modules`'s own registries and
templates (a separate, self-contained module inventory -- see that
module's docstring for why it does not extend `fuzzlab.labgen.modules`).
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.node_express.modules import (
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


def test_get_query_param_source_renders_extraction_and_publishes_value_expr() -> None:
    ctx = {"var_name": "id", "param_name": "id"}
    result = SOURCES["get_query_param"].render(ctx)
    assert "req.query.id" in result.code
    assert "const id = " in result.code
    assert result.context["value_expr"] == "id"
    assert result.context["bound"] is False


def test_post_body_param_source_renders_extraction_and_publishes_value_expr() -> None:
    ctx = {"var_name": "username", "param_name": "username"}
    result = SOURCES["post_body_param"].render(ctx)
    assert "req.body.username" in result.code
    assert "const username = " in result.code
    assert result.context["value_expr"] == "username"
    assert result.context["bound"] is False


def test_read_stored_field_source_renders_a_non_request_assignment() -> None:
    ctx = {"var_name": "bio", "stored_expr": "currentUser.bio"}
    result = SOURCES["read_stored_field"].render(ctx)
    assert result.code.strip() == "const bio = currentUser.bio;"
    assert result.context["value_expr"] == "bio"
    assert "req.query" not in result.code
    assert "req.body" not in result.code


def test_identity_transform_leaves_bound_false() -> None:
    ctx = {"value_expr": "id", "bound": False}
    result = TRANSFORMS["identity"].render(ctx)
    assert "id" in result.code
    assert result.context["bound"] is False


def test_param_bind_transform_sets_bound_true() -> None:
    ctx = {"value_expr": "id", "bound": False}
    result = TRANSFORMS["param_bind"].render(ctx)
    assert result.context["bound"] is True
    # The transform's own fragment never emits a literal SQL query -- that
    # is the sink's job.
    assert "SELECT" not in result.code.upper()


def test_html_entity_escape_transform_wraps_value_expr_in_escape_html_call() -> None:
    ctx = {"value_expr": "bio"}
    result = TRANSFORMS["html_entity_escape"].render(ctx)
    assert result.context["value_expr"] == "escapeHtml(bio)"
    assert "SELECT" not in result.code.upper()


def test_sql_numeric_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {"value_expr": "id", "bound": False, "table": "products", "column": "id", "handler_name": "handleX"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert "'SELECT * FROM products WHERE id = ' + id" in result.code
    assert "pool.query(sql)" in result.code


def test_sql_numeric_lookup_sink_renders_parameterized_query_when_bound() -> None:
    ctx = {"value_expr": "id", "bound": True, "table": "products", "column": "id", "handler_name": "handleX"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert "pool.query('SELECT * FROM products WHERE id = ?', [id])" in result.code
    assert "+ id" not in result.code


def test_sql_string_literal_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {
        "value_expr": "username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "passwordHash",
        "password_param": "password",
        "handler_name": "handleX",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "WHERE username = '\" + username + \"'" in result.code
    assert "createHash('md5')" in result.code
    assert "pool.query(sql)" in result.code


def test_sql_string_literal_lookup_sink_renders_parameterized_query_when_bound() -> None:
    ctx = {
        "value_expr": "username",
        "bound": True,
        "table": "users",
        "column": "username",
        "password_var": "passwordHash",
        "password_param": "password",
        "handler_name": "handleX",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "pool.query('SELECT id, username FROM users WHERE username = ? AND password = ?', [username, passwordHash])" in (
        result.code
    )
    assert '" + username' not in result.code


def test_html_body_echo_sink_renders_a_send_of_value_expr() -> None:
    ctx = {"value_expr": "bio", "css_class": "bio"}
    result = SINKS["html_body_echo"].render(ctx)
    assert result.code.strip() == "res.send('<div class=\"bio\">' + bio + '</div>');"


def test_html_body_echo_sink_reflects_whatever_value_expr_it_is_given() -> None:
    raw = SINKS["html_body_echo"].render({"value_expr": "bio", "css_class": "bio"})
    escaped = SINKS["html_body_echo"].render({"value_expr": "escapeHtml(bio)", "css_class": "bio"})
    assert "escapeHtml" not in raw.code
    assert "escapeHtml(bio)" in escaped.code


def test_single_statement_complexity_wraps_body_in_one_async_function() -> None:
    ctx = {"body": "    // body\n", "handler_name": "handleX"}
    result = COMPLEXITIES["single_statement"].render(ctx)
    assert result.code.startswith("async function handleX(req, res) {\n")
    assert "// body" in result.code
    assert "res.json(row);" in result.code


def test_render_only_complexity_wraps_body_with_no_json_response() -> None:
    ctx = {"body": "    // body\n", "handler_name": "handleX"}
    result = COMPLEXITIES["render_only"].render(ctx)
    assert result.code.startswith("function handleX(req, res) {\n")
    assert "res.json" not in result.code
    assert result.code.rstrip("\n").endswith("}")


def test_render_route_line_renders_an_express_registration() -> None:
    line = render_route_line(method="GET", path="/generated/labgen-ne-0001", handler_module="labgen-ne-0001")
    assert line.strip() == "app.get('/generated/labgen-ne-0001', require('./routes/labgen-ne-0001'));"


# Per-module minimal context sufficient to render each fragment, used only
# to check every module is internally deterministic across two calls --
# mirrors tests/test_labgen_modules.py's own convention.
_DETERMINISM_CTX_BY_MODULE: dict[str, dict[str, object]] = {
    "get_query_param": {"var_name": "id", "param_name": "id"},
    "post_body_param": {"var_name": "username", "param_name": "username"},
    "read_stored_field": {"var_name": "bio", "stored_expr": "currentUser.bio"},
    "identity": {"value_expr": "id"},
    "param_bind": {"value_expr": "id"},
    "html_entity_escape": {"value_expr": "bio"},
    "sql_numeric_lookup": {"value_expr": "id", "bound": False, "table": "products", "column": "id", "handler_name": "handleX"},
    "sql_string_literal_lookup": {
        "value_expr": "username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "passwordHash",
        "password_param": "password",
        "handler_name": "handleX",
    },
    "html_body_echo": {"value_expr": "bio", "css_class": "bio"},
    "single_statement": {"body": "    // x\n", "handler_name": "handleX"},
    "render_only": {"body": "    // x\n", "handler_name": "handleX"},
}


def test_every_module_renders_deterministically_twice() -> None:
    for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES):
        for name, module in registry.items():
            ctx = _DETERMINISM_CTX_BY_MODULE[name]
            first = module.render(dict(ctx))
            second = module.render(dict(ctx))
            assert first.code == second.code, f"{name} module is non-deterministic"


def test_every_registered_module_has_a_determinism_ctx_fixture() -> None:
    all_names = {name for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES) for name in registry}
    assert all_names == set(_DETERMINISM_CTX_BY_MODULE)
