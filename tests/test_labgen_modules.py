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


def test_every_module_renders_deterministically_twice() -> None:
    ctx = {
        "var_name": "id",
        "param_name": "id",
        "table": "products",
        "column": "id",
        "value_expr": "$id",
        "bound": False,
        "body": "    // x\n",
        "handler_name": "handle_x",
    }
    for registry in (SOURCES, TRANSFORMS, SINKS, COMPLEXITIES):
        for name, module in registry.items():
            first = module.render(dict(ctx))
            second = module.render(dict(ctx))
            assert first.code == second.code, f"{name} module is non-deterministic"
