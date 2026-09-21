"""Module-composition unit tests for the ``python_fastapi`` emitter (L-P3.2).

Mirrors `tests/test_labgen_modules.py`'s shape and coverage exactly, against
`fuzzlab.labgen.emitters.python_fastapi.modules`'s own, fully independent
module registries (see that module's docstring for why it does not extend
`fuzzlab.labgen.modules`).
"""

from __future__ import annotations

from fuzzlab.labgen.emitters.python_fastapi.modules import (
    COMPLEXITIES,
    COMPLEXITY_ENV,
    SCAFFOLD_ENV,
    SINK_ENV,
    SINKS,
    SOURCE_ENV,
    SOURCES,
    TRANSFORM_ENV,
    TRANSFORMS,
)


def test_module_environments_set_determinism_flags_explicitly() -> None:
    for env in (SOURCE_ENV, TRANSFORM_ENV, SINK_ENV, COMPLEXITY_ENV, SCAFFOLD_ENV):
        assert env.trim_blocks is True
        assert env.lstrip_blocks is True
        assert env.keep_trailing_newline is True


def test_get_param_source_renders_manual_query_params_extraction() -> None:
    ctx = {"var_name": "id", "param_name": "id"}
    result = SOURCES["get_param"].render(ctx)
    assert 'request.query_params.get("id")' in result.code
    assert "id = " in result.code
    assert result.context["value_expr"] == "id"
    assert result.context["bound"] is False


def test_post_param_source_renders_await_request_form_extraction() -> None:
    ctx = {"var_name": "username", "param_name": "username"}
    result = SOURCES["post_param"].render(ctx)
    assert 'await request.form()).get("username")' in result.code
    assert result.context["value_expr"] == "username"
    assert result.context["bound"] is False


def test_read_stored_field_source_renders_a_non_request_assignment() -> None:
    ctx = {"var_name": "bio", "stored_expr": "current_user['bio']"}
    result = SOURCES["read_stored_field"].render(ctx)
    assert result.code.strip() == "bio = current_user['bio']"
    assert result.context["value_expr"] == "bio"
    assert "request." not in result.code


def test_identity_transform_leaves_bound_false() -> None:
    ctx = {"value_expr": "id", "bound": False}
    result = TRANSFORMS["identity"].render(ctx)
    assert "id" in result.code
    assert result.context["bound"] is False


def test_param_bind_transform_sets_bound_true_and_emits_no_sql() -> None:
    ctx = {"value_expr": "id", "bound": False}
    result = TRANSFORMS["param_bind"].render(ctx)
    assert result.context["bound"] is True
    assert "SELECT" not in result.code.upper()


def test_html_entity_escape_transform_wraps_value_expr_in_html_escape() -> None:
    ctx = {"value_expr": "bio"}
    result = TRANSFORMS["html_entity_escape"].render(ctx)
    assert result.context["value_expr"] == "html.escape(bio)"
    assert "SELECT" not in result.code.upper()


def test_sql_numeric_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {"value_expr": "id", "bound": False, "table": "products", "column": "id"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert 'text("SELECT * FROM products WHERE id = " + str(id))' in result.code
    assert ":id" not in result.code


def test_sql_numeric_lookup_sink_renders_parameterized_query_when_bound() -> None:
    ctx = {"value_expr": "id", "bound": True, "table": "products", "column": "id"}
    result = SINKS["sql_numeric_lookup"].render(ctx)
    assert 'text("SELECT * FROM products WHERE id = :id")' in result.code
    assert '{"id": id}' in result.code
    assert '" + str(id)' not in result.code


def test_sql_string_literal_lookup_sink_renders_raw_concat_when_not_bound() -> None:
    ctx = {
        "value_expr": "username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "WHERE username = '\"" in result.code
    assert "+ str(username)" in result.code
    assert ":username" not in result.code
    assert "hashlib.sha256" in result.code


def test_sql_string_literal_lookup_sink_renders_parameterized_query_when_bound() -> None:
    ctx = {
        "value_expr": "username",
        "bound": True,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    }
    result = SINKS["sql_string_literal_lookup"].render(ctx)
    assert "WHERE username = :username AND password = :password" in result.code
    assert '"username": username' in result.code
    assert "+ str(username)" not in result.code


def test_html_body_echo_sink_renders_jinja_template_and_returns_html_response() -> None:
    ctx = {"value_expr": "bio", "css_class": "bio"}
    result = SINKS["html_body_echo"].render(ctx)
    assert 'class="bio"' in result.code
    assert ".render(value=bio)" in result.code
    assert "return HTMLResponse(content=html_fragment)" in result.code


def test_html_body_echo_sink_reflects_whatever_value_expr_it_is_given() -> None:
    raw = SINKS["html_body_echo"].render({"value_expr": "bio", "css_class": "bio"})
    escaped = SINKS["html_body_echo"].render({"value_expr": "html.escape(bio)", "css_class": "bio"})
    assert "html.escape" not in raw.code
    assert "html.escape(bio)" in escaped.code


def test_single_statement_complexity_wraps_body_in_an_async_handler_with_db_dependency() -> None:
    ctx = {"body": "    row = None\n", "handler_name": "handle_x"}
    result = COMPLEXITIES["single_statement"].render(ctx)
    assert result.code.startswith("async def handle_x(request: Request, db: Session = Depends(get_db)):\n")
    assert "row = None" in result.code
    assert result.code.rstrip("\n").endswith("return dict(row) if row else {}")


def test_render_only_complexity_wraps_body_with_current_user_dependency_and_no_return() -> None:
    ctx = {"body": "    pass\n", "handler_name": "handle_x"}
    result = COMPLEXITIES["render_only"].render(ctx)
    assert result.code.startswith(
        "async def handle_x(request: Request, current_user: dict = Depends(get_current_user)):\n"
    )
    assert "db:" not in result.code


# Per-module minimal context sufficient to render each fragment (mirrors
# `tests/test_labgen_modules.py`'s own fixture, scoped to this registry).
_DETERMINISM_CTX_BY_MODULE: dict[str, dict[str, object]] = {
    "get_param": {"var_name": "id", "param_name": "id"},
    "post_param": {"var_name": "username", "param_name": "username"},
    "read_stored_field": {"var_name": "bio", "stored_expr": "current_user['bio']"},
    "identity": {"value_expr": "id"},
    "param_bind": {"value_expr": "id"},
    "html_entity_escape": {"value_expr": "bio"},
    "sql_numeric_lookup": {"value_expr": "id", "bound": False, "table": "products", "column": "id"},
    "sql_string_literal_lookup": {
        "value_expr": "username",
        "bound": False,
        "table": "users",
        "column": "username",
        "password_var": "password_hash",
        "password_param": "password",
    },
    "html_body_echo": {"value_expr": "bio", "css_class": "bio"},
    "single_statement": {"body": "    row = None\n", "handler_name": "handle_x"},
    "render_only": {"body": "    pass\n", "handler_name": "handle_x"},
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
