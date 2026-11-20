"""A GraphQL variable's argument context, for the audit rules (FR-AUD-600).

A captured or ground-truth GraphQL request is a JSON body whose ``query`` leaf holds
the document and whose ``variables.<name>`` leaves hold the inputs (`core.jsonbody`
names). The variable's own name is the client's choice (``$h``); what the server acts
on is the **field argument** it feeds (``importPaste(host: $h)``). This module reads,
for a JSON-leaf point under ``variables``, which ``(field, argument, sibling
arguments)`` the variable is bound to in the request's own document
(`tools.apiop.graphql_variable_bindings`, the one GraphQL reader), so a name rule sees
the argument's name, and the `graphql_field_regex` / `graphql_sibling_regex`
predicates see the field and the field call's other arguments (`audit.rules`).

Total on hostile input: a point that is not such a leaf, or whose entries hold no
parseable document, has no binding (an empty tuple), never an error.
"""

from __future__ import annotations

from functools import lru_cache

from fuzzlab.core import jsonbody

#: The JSON key that holds a GraphQL request's variables (GraphQL over HTTP).
VARIABLES_KEY = "variables"
QUERY_KEY = "query"
OPERATION_NAME_KEY = "operationName"


@lru_cache(maxsize=256)
def _bindings_of(document: str, operation_name: str | None):
    from fuzzlab.tools.apiop import graphql_variable_bindings
    found = graphql_variable_bindings(document, operation_name)
    return {k: tuple(v) for k, v in (found or {}).items()}


def _path(name) -> tuple | None:
    if isinstance(name, (list, tuple)):
        return tuple(name)
    return jsonbody.parse_name(name)


def bindings(point) -> tuple:
    """``((field, argument, siblings), ...)`` the point's variable feeds, or ``()``."""
    if getattr(point, "location", None) != jsonbody.LOCATION:
        return ()
    path = jsonbody.parse_name(getattr(point, "param", None) or "")
    if not path or len(path) < 2 or path[0] != VARIABLES_KEY or not isinstance(path[1], str):
        return ()
    document = operation_name = None
    for name, value in getattr(point, "base_entries", None) or ():
        p = _path(name)
        if p == (QUERY_KEY,) and isinstance(value, str):
            document = value
        elif p == (OPERATION_NAME_KEY,) and isinstance(value, str):
            operation_name = value
    if document is None:
        return ()
    return _bindings_of(document, operation_name).get(path[1], ())


def argument_names(point) -> tuple[str, ...]:
    return tuple(dict.fromkeys(arg for _f, arg, _s in bindings(point)))


def field_names(point) -> tuple[str, ...]:
    return tuple(dict.fromkeys(f for f, _a, _s in bindings(point)))


def sibling_names(point) -> tuple[str, ...]:
    return tuple(dict.fromkeys(s for _f, _a, sib in bindings(point) for s in sib))


#: GraphQL's built-in scalars whose input coercion never yields a string (GraphQL spec
#: "Input Coercion" of Int, Float and Boolean): a string payload in such a variable is
#: rejected or coerced to a number or boolean before any resolver reads it (measured on
#: DVGA's graphql-core 2, 2026-11-20: a string Int answered "could not convert string
#: to float", a string Boolean was coerced to true). ID and String carry strings;
#: enums and custom scalars are kept (a custom scalar may pass a string through).
NON_STRING_SCALARS = frozenset({"Int", "Float", "Boolean"})


@lru_cache(maxsize=256)
def _types_of(document: str, operation_name: str | None):
    from fuzzlab.tools.apiop import graphql_variable_types
    return graphql_variable_types(document, operation_name)


def _document_of(point):
    document = operation_name = None
    for name, value in getattr(point, "base_entries", None) or ():
        p = _path(name)
        if p == (QUERY_KEY,) and isinstance(value, str):
            document = value
        elif p == (OPERATION_NAME_KEY,) and isinstance(value, str):
            operation_name = value
    return document, operation_name


def not_a_data_point(point) -> str | None:
    """Why no injection rule applies to ``point``, a leaf of a GraphQL request, or None
    (FR-AUD-601): its ``query`` leaf holds an executable GraphQL document (the operation
    itself: a payload in its place is a syntax error, never data an operation reads), or
    its variable is declared with a built-in scalar that never carries a string
    (`NON_STRING_SCALARS`). Never true for a body that is not a GraphQL request (its
    ``query`` must parse as an executable document)."""
    if getattr(point, "location", None) != jsonbody.LOCATION:
        return None
    path = jsonbody.parse_name(getattr(point, "param", None) or "")
    if not path:
        return None
    document, operation_name = _document_of(point)
    if document is None:
        return None
    types = _types_of(document, operation_name)
    if types is None:
        return None                         # not an executable GraphQL document
    if path == (QUERY_KEY,):
        return "the GraphQL request's document (the operation, not a data value)"
    if len(path) == 2 and path[0] == VARIABLES_KEY and isinstance(path[1], str):
        declared = types.get(path[1])
        if declared is not None and declared[1] == 0 and declared[0] in NON_STRING_SCALARS:
            return f"a GraphQL variable declared {declared[0]} (never a string)"
    return None
