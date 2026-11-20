"""GraphQL schema discovery (FR-CRAWL-670): the bounded introspection request, the
total parser of its answer and the operations a schema's root types offer to fuzz
(`fuzzlab.tools.gqlschema`).

Every fixture is an invented API (a bookstore, a ticketing desk), built as a Python
dict and serialised: nothing here names any lab application. The authority is the
GraphQL specification (October 2021), §4 Introspection. Every generated document is
read back through the project's own GraphQL reader (`tools.apiop`).
"""

from __future__ import annotations

import json

import pytest

from fuzzlab.core.redaction import CAPTURE_MAX_BYTES
from fuzzlab.tools import apiop, gqlschema
from fuzzlab.tools.gqlschema import (
    INTROSPECTION_QUERY,
    MAX_ARGS,
    MAX_FIELDS_PER_TYPE,
    MAX_NAME_CHARS,
    MAX_RESPONSE_CHARS,
    MAX_SELECTED_FIELDS,
    MAX_TYPES,
    Schema,
    SchemaOperation,
    TypeRef,
    introspection_body,
    operations,
    operations_with_skips,
    parse_schema,
)

# --------------------------------------------------------------------------- builders

def named(kind, name):
    return {"kind": kind, "name": name, "ofType": None}


def scalar(name):
    return named("SCALAR", name)


def nn(inner):
    return {"kind": "NON_NULL", "name": None, "ofType": inner}


def lst(inner):
    return {"kind": "LIST", "name": None, "ofType": inner}


def arg(name, type_):
    return {"name": name, "type": type_}


def fld(name, type_, *args):
    return {"name": name, "args": list(args), "type": type_}


def obj(name, *fields, kind="OBJECT"):
    return {"kind": kind, "name": name, "fields": list(fields), "inputFields": None,
            "enumValues": None}


def enum(name, *values):
    return {"kind": "ENUM", "name": name, "fields": None, "inputFields": None,
            "enumValues": [{"name": v} for v in values]}


def inp(name, *fields):
    return {"kind": "INPUT_OBJECT", "name": name, "fields": None,
            "inputFields": list(fields), "enumValues": None}


def sc(name):
    return {"kind": "SCALAR", "name": name, "fields": None, "inputFields": None,
            "enumValues": None}


def answer(types, query="Query", mutation=None):
    return json.dumps({"data": {"__schema": {
        "queryType": {"name": query},
        "mutationType": {"name": mutation} if mutation else None,
        "types": types}}})


BUILTINS = [sc("String"), sc("ID"), sc("Int"), sc("Float"), sc("Boolean")]

BOOK = obj(
    "Book",
    fld("id", nn(scalar("ID"))),
    fld("title", scalar("String")),
    fld("__meta", scalar("String")),
    fld("price", scalar("Float")),
    fld("author", named("OBJECT", "Author")),
    fld("inStock", nn(scalar("Boolean"))),
    fld("related", scalar("String"), arg("limit", nn(scalar("Int")))),
    fld("excerpt", scalar("String"), arg("chars", scalar("Int"))),
    fld("genre", named("ENUM", "Genre")),
    fld("reviews", lst(named("OBJECT", "Review"))),
)

QUERY = obj(
    "Query",
    fld("book", named("OBJECT", "Book"), arg("id", nn(scalar("ID")))),
    fld("search", lst(named("UNION", "SearchResult")),
        arg("term", nn(scalar("String"))),
        arg("limit", nn(scalar("Int"))),
        arg("sort", nn(named("ENUM", "SortOrder"))),
        arg("tags", nn(lst(nn(scalar("String"))))),
        arg("exact", nn(scalar("Boolean"))),
        arg("minPrice", nn(scalar("Float"))),
        arg("cursor", scalar("String")),
        arg("page", scalar("Int"))),
    fld("authorByName", named("OBJECT", "Author"),
        arg("name", scalar("String")),
        arg("filter", nn(named("INPUT_OBJECT", "AuthorFilter")))),
    fld("count", nn(scalar("Int"))),
    fld("stats", scalar("Int"), arg("year", nn(scalar("Int")))),
    fld("__type", named("OBJECT", "__Type"), arg("name", nn(scalar("String")))),
    fld("node", named("INTERFACE", "Node"), arg("id", scalar("ID"))),
    fld("greeting", nn(scalar("String")), arg("name", scalar("String"))),
    fld("byIds", scalar("String"), arg("ids", lst(nn(scalar("ID"))))),
    fld("legacy", scalar("String"), arg("q", scalar("String")),
        arg("code", nn(scalar("Isbn")))),
    fld("shelf", named("OBJECT", "Shelf"), arg("label", scalar("String"))),
    fld("genreOf", named("ENUM", "Genre"), arg("title", scalar("String"))),
)

MUTATION = obj(
    "Mutation",
    fld("addReview", named("OBJECT", "Review"),
        arg("bookId", nn(scalar("ID"))),
        arg("text", nn(scalar("String"))),
        arg("rating", nn(scalar("Int")))),
    fld("clearCart", scalar("Boolean")),
)

BOOKSTORE = BUILTINS + [
    QUERY, MUTATION, BOOK,
    obj("Author", fld("name", scalar("String")), fld("books", lst(named("OBJECT", "Book")))),
    obj("Review", fld("id", nn(scalar("ID"))), fld("rating", scalar("Int")),
        fld("text", scalar("String"))),
    obj("Shelf", fld("books", lst(named("OBJECT", "Book")))),
    obj("Node", fld("id", nn(scalar("ID"))), kind="INTERFACE"),
    {"kind": "UNION", "name": "SearchResult", "fields": None, "inputFields": None,
     "enumValues": None},
    enum("SortOrder", "ASC", "DESC"),
    enum("Genre", "FICTION", "POETRY"),
    inp("AuthorFilter", arg("name", scalar("String"))),
    sc("Isbn"),
]


def bookstore():
    schema = parse_schema(answer(BOOKSTORE, mutation="Mutation"))
    assert schema is not None
    return schema


def by_field(ops):
    return {op.field: op for op in ops}


def assert_round_trips(op: SchemaOperation):
    """The project's own GraphQL reader reads ``op`` back: its operation and root
    field, and each target variable bound to its field argument."""
    read = apiop.graphql_operations(op.document, op.operation_name)
    assert read == [[op.kind, op.operation_name, [op.field]]], op.document
    bindings = apiop.graphql_variable_bindings(op.document, op.operation_name)
    assert bindings is not None, op.document
    for var in op.targets:
        assert [b[:2] for b in bindings[var]] == [(op.field, var)], op.document
    types = apiop.graphql_variable_types(op.document, op.operation_name)
    for var in op.targets:
        assert types[var][1] == 0 and types[var][0] in ("String", "ID")
    assert set(op.variables) == set(bindings)
    body = op.body()
    assert body == {"query": op.document, "operationName": op.operation_name,
                    "variables": dict(op.variables)}
    json.dumps(body)


# --------------------------------------------------------------------------- the request

def test_the_introspection_query_is_one_bounded_operation():
    q = INTROSPECTION_QUERY
    assert "description" not in q
    assert "directives" not in q
    assert "subscriptionType" not in q
    assert "defaultValue" not in q
    assert ":" not in q.replace("includeDeprecated: false", "")      # no aliases
    assert q.count("__schema") == 1
    assert q.count("ofType") == 3            # four levels of kind/name
    assert q.count("...T") == 3
    assert q.count("fragment T on __Type") == 1
    ops = apiop.graphql_operations(q)
    assert ops == [["query", "FuzzlabIntrospection", ["__schema"]]]
    assert len(q) < 1024
    assert introspection_body() == {"query": q, "operationName": "FuzzlabIntrospection"}


def test_the_text_filler_is_the_importers_own():
    from fuzzlab.tools import store_adapter
    assert gqlschema.TEXT_FILLER == store_adapter._TEXT_FILLER


# --------------------------------------------------------------------------- parsing

def test_the_parser_reads_roots_types_and_wrapper_chains():
    schema = bookstore()
    assert schema.query_type == "Query" and schema.mutation_type == "Mutation"
    search = by_field_list(schema.types["Query"].fields)["search"]
    tags = {a.name: a.type for a in search.args}["tags"]
    assert tags == TypeRef("String", "SCALAR", ("NON_NULL", "LIST", "NON_NULL"))
    assert tags.render() == "[String!]!" and tags.non_null and tags.is_list
    assert schema.types["SortOrder"].enum_values == ("ASC", "DESC")
    assert [a.name for a in schema.types["AuthorFilter"].input_fields] == ["name"]
    assert schema.root("query").name == "Query"
    assert schema.root("mutation").name == "Mutation"
    no_mutation = parse_schema(answer(BOOKSTORE))
    assert no_mutation.mutation_type is None and no_mutation.root("mutation") is None


def by_field_list(fields):
    return {f.name: f for f in fields}


def test_a_type_reference_deeper_than_four_levels_or_malformed_is_unreadable():
    deep = nn(lst(nn(lst(scalar("String")))))            # five levels
    double = nn(nn(scalar("String")))
    unknown = {"kind": "TUPLE", "name": "String", "ofType": None}
    nameless = {"kind": "SCALAR", "name": None, "ofType": None}
    q = obj("Query", fld("f", scalar("String"), arg("a", deep), arg("b", double),
                         arg("c", unknown), arg("d", nameless), arg("e", "String")))
    schema = parse_schema(answer(BUILTINS + [q]))
    assert all(a.type is None for a in schema.types["Query"].fields[0].args)


@pytest.mark.parametrize("text", [
    "", "not json", "[]", "null", "42", '"x"', "{", "﻿",
    json.dumps({"errors": [{"message": "introspection is disabled"}]}),
    json.dumps({"errors": [{"message": "partial"}],
                "data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}),
    json.dumps({"data": None}),
    json.dumps({"data": []}),
    json.dumps({"data": {"__schema": None}}),
    json.dumps({"data": {"__schema": []}}),
    json.dumps({"data": {"__schema": {"queryType": None, "types": []}}}),
    json.dumps({"data": {"__schema": {"queryType": {"name": 7}, "types": []}}}),
    json.dumps({"data": {"__schema": {"queryType": [], "types": {}}}}),
    json.dumps({"data": {"__schema": {"queryType": {"name": ""}}}}),
    "\ud800", '"\\ud800"', '{"data": {"__schema": {"queryType": {"name": "\\ud800"}}}}',
    "[" * 100_000 + "]" * 100_000,
    '{"a":' * 50_000 + "1" + "}" * 50_000,
    b"\xff\xfe not json",
    None, 12, ["data"], {"data": {}},
])
def test_hostile_answers_are_none_never_an_exception(text):
    assert parse_schema(text) is None


def test_an_answer_over_the_character_bound_is_none_without_parsing(monkeypatch):
    big = answer(BUILTINS + [QUERY, BOOK], ) + " " * (3 * 1024 * 1024)
    assert len(big) > MAX_RESPONSE_CHARS

    def no_parse(*_a, **_k):
        raise AssertionError("parsed text over the bound")

    monkeypatch.setattr(gqlschema.json, "loads", no_parse)
    assert parse_schema(big) is None
    assert parse_schema(json.dumps({"x": "a" * (3 * 1024 * 1024)})) is None


def test_wrong_json_types_inside_the_schema_are_skipped_not_raised():
    types = BUILTINS + [
        "Query", 7, None, [], {"kind": "OBJECT"}, {"kind": "OBJECT", "name": 5},
        {"kind": "NOPE", "name": "X"},
        {"kind": "OBJECT", "name": "Query", "fields": {"not": "a list"}},
    ]
    schema = parse_schema(answer(types))
    assert schema is not None and schema.types["Query"].fields == ()
    assert operations(schema) == []
    odd_fields = obj("Query", 1, None, "f", {"name": None}, {"name": "g", "args": "x",
                                                              "type": [1]},
                     fld("h", scalar("String"), 3, {"name": 4}, arg("q", scalar("String"))))
    schema = parse_schema(answer(BUILTINS + [odd_fields]))
    names = [f.name for f in schema.types["Query"].fields]
    assert names == ["g", "h"]
    ops, skipped = operations_with_skips(schema)
    assert [op.field for op in ops] == ["h"] and op_targets(ops) == [("q",)]
    assert skipped == [("g", "query", "no String or ID argument")]


def op_targets(ops):
    return [op.targets for op in ops]


def test_lone_surrogates_and_non_ascii_names_never_reach_a_document():
    escaped = ('{"data":{"__schema":{"queryType":{"name":"Query"},"types":['
               '{"kind":"OBJECT","name":"Query","fields":['
               '{"name":"f\\ud800","args":[{"name":"q","type":{"kind":"SCALAR",'
               '"name":"String","ofType":null}}],"type":{"kind":"SCALAR",'
               '"name":"String","ofType":null}},'
               '{"name":"g","args":[{"name":"\\udc00","type":{"kind":"SCALAR",'
               '"name":"String","ofType":null}},{"name":"q","type":{"kind":"SCALAR",'
               '"name":"String","ofType":null}}],"type":{"kind":"SCALAR",'
               '"name":"\\ud800","ofType":null}}]}]}}}')
    schema = parse_schema(escaped)
    assert schema is not None
    ops, skipped = operations_with_skips(schema)
    assert skipped[0] == ("f\ud800", "query", "field name is not a GraphQL Name")
    assert skipped[1] == ("g", "query", "return type is unreadable")
    assert ops == []
    raw = answer(BUILTINS + [obj("Query", fld("x\ud800", scalar("String"),
                                              arg("q", scalar("String"))))])
    assert parse_schema(raw) is not None
    assert operations(parse_schema(raw)) == []
    for op in operations(schema):
        op.document.encode("utf-8")


# --------------------------------------------------------------------------- operations

def test_documents_variables_and_targets_of_the_bookstore():
    ops = by_field(operations(bookstore()))
    assert list(ops) == ["book", "search", "node", "greeting", "shelf", "genreOf"]

    book = ops["book"]
    assert book.kind == "query" and book.operation_name == "FuzzlabBook"
    assert book.document == ("query FuzzlabBook($id: ID!) "
                             "{ book(id: $id) { id title price inStock excerpt genre } }")
    assert dict(book.variables) == {"id": "fuzzlab"} and book.targets == ("id",)

    search = ops["search"]
    assert search.document == (
        "query FuzzlabSearch($term: String!, $limit: Int!, $sort: SortOrder!, "
        "$tags: [String!]!, $exact: Boolean!, $minPrice: Float!, $cursor: String) "
        "{ search(term: $term, limit: $limit, sort: $sort, tags: $tags, exact: $exact, "
        "minPrice: $minPrice, cursor: $cursor) { __typename } }")
    assert dict(search.variables) == {
        "term": "fuzzlab", "limit": 1, "sort": "ASC", "tags": ["fuzzlab"],
        "exact": False, "minPrice": 1.0, "cursor": "fuzzlab"}
    assert search.targets == ("term", "cursor")
    assert "page" not in search.document

    assert ops["node"].document == "query FuzzlabNode($id: ID) { node(id: $id) { __typename } }"
    assert ops["greeting"].document == (
        "query FuzzlabGreeting($name: String) { greeting(name: $name) }")
    assert ops["shelf"].document.endswith("{ shelf(label: $label) { __typename } }")
    assert ops["genreOf"].document.endswith("{ genreOf(title: $title) }")
    for op in ops.values():
        assert_round_trips(op)


def test_unfillable_and_targetless_fields_are_skipped_with_their_reason():
    _ops, skipped = operations_with_skips(bookstore())
    reasons = {(f, k): r for f, k, r in skipped}
    assert reasons == {
        ("authorByName", "query"):
            "required argument 'filter' of type AuthorFilter! cannot be filled",
        ("count", "query"): "no String or ID argument",
        ("stats", "query"): "no String or ID argument",
        ("byIds", "query"): "no String or ID argument",
        ("legacy", "query"): "required argument 'code' of type Isbn! cannot be filled",
    }
    assert all(not f.startswith("__") for f, _k, _r in skipped)


def test_the_kinds_filter_selects_root_types():
    schema = bookstore()
    mutations = operations(schema, kinds=("mutation",))
    assert [op.field for op in mutations] == ["addReview"]
    add = mutations[0]
    assert add.document == (
        "mutation FuzzlabAddReview($bookId: ID!, $text: String!, $rating: Int!) "
        "{ addReview(bookId: $bookId, text: $text, rating: $rating) { id rating text } }")
    assert add.targets == ("bookId", "text") and add.variables["rating"] == 1
    assert_round_trips(add)
    both = operations(schema, kinds=("query", "mutation"))
    assert [op.kind for op in both] == ["query"] * 6 + ["mutation"]
    reordered = operations(schema, kinds=("mutation", "query"))
    assert reordered[0].kind == "mutation" and len(reordered) == 7
    assert operations(schema, kinds=("subscription", "bogus")) == []
    assert [op.field for op in operations(schema, kinds="mutation")] == ["addReview"]
    assert operations(parse_schema(answer(BOOKSTORE)), kinds=("mutation",)) == []


def test_max_operations_caps_and_reports_the_rest():
    ops, skipped = operations_with_skips(bookstore(), max_operations=2)
    assert [op.field for op in ops] == ["book", "search"]
    over = [f for f, _k, r in skipped if r == "over max_operations"]
    assert over == ["node", "greeting", "shelf", "genreOf"]
    assert operations(bookstore(), max_operations=0) == []
    with pytest.raises(TypeError):
        operations(bookstore(), max_operations="3")
    with pytest.raises(TypeError):
        operations(bookstore(), max_operations=True)


def test_operations_of_anything_but_a_schema_is_empty():
    for value in (None, {}, "schema", 3, []):
        assert operations_with_skips(value) == ([], [])


@pytest.mark.parametrize("bad", [
    "a){ x }", "a(b: $c)", "proéto", "ünicode", "0lead",
    "a b", "a-b","x" * (MAX_NAME_CHARS + 1), "a\nb", "a#c", "аdmin",
])
def test_names_that_are_not_graphql_names_are_never_interpolated(bad):
    q = obj("Query",
            fld(bad, scalar("String"), arg("q", scalar("String"))),
            fld("ok", named("OBJECT", "Ticket"), arg(bad, scalar("String")),
                arg("q", scalar("String"))),
            fld("req", scalar("String"), arg(bad, nn(scalar("Int"))),
                arg("q", scalar("String"))),
            fld("typed", scalar("String"), arg("t", nn(named("ENUM", bad))),
                arg("q", scalar("String"))),
            fld("ret", named("OBJECT", bad), arg("q", scalar("String"))))
    ticket = obj("Ticket", fld(bad, scalar("String")), fld("seat", scalar("String")))
    schema = parse_schema(answer(BUILTINS + [q, ticket, enum(bad, "A")]))
    ops, skipped = operations_with_skips(schema)
    for op in ops:
        assert bad not in op.document
        assert_round_trips(op)
    assert by_field(ops)["ok"].document == (
        "query FuzzlabOk($q: String) { ok(q: $q) { seat } }")
    reasons = {f: r for f, _k, r in skipped}
    assert reasons[bad] == "field name is not a GraphQL Name"
    assert reasons["req"].startswith("required argument")
    assert reasons["typed"] == "required argument 't' has an unusable name or type"
    assert reasons["ret"] == "return type is unreadable"


def test_meta_fields_and_proto_like_names():
    q = obj("Query",
            fld("__proto__", scalar("String"), arg("q", scalar("String"))),
            fld("__typename", scalar("String"), arg("q", scalar("String"))),
            fld("constructor", scalar("String"), arg("__proto__", scalar("String")),
                arg("q", scalar("ID"))),
            fld("_private", scalar("String"), arg("_x", nn(scalar("String")))))
    ops, skipped = operations_with_skips(parse_schema(answer(BUILTINS + [q])))
    assert [op.field for op in ops] == ["constructor", "_private"]
    assert ops[0].targets == ("__proto__", "q")
    assert ops[1].operation_name == "Fuzzlab_private"
    assert skipped == []
    for op in ops:
        assert_round_trips(op)


def test_a_root_field_the_project_reader_cannot_bind_is_skipped():
    q = obj("Query", fld("on", scalar("String"), arg("q", scalar("String"))))
    ops, skipped = operations_with_skips(parse_schema(answer(BUILTINS + [q])))
    assert ops == []
    assert skipped == [("on", "query",
                        "field name the project's GraphQL reader cannot bind")]
    # non-vacuity: the reader really does not bind a field named `on`
    doc = "query FuzzlabOn($q: String) { on(q: $q) }"
    assert apiop.graphql_variable_bindings(doc, "FuzzlabOn") == {}


def test_an_enum_filler_is_its_first_usable_value_and_targets_must_be_builtin_scalars():
    q = obj("Ticketing",
            fld("seat", scalar("String"), arg("cls", nn(named("ENUM", "Cls"))),
                arg("code", scalar("String"))),
            fld("noValues", scalar("String"), arg("e", nn(named("ENUM", "Empty"))),
                arg("code", scalar("String"))),
            fld("fakeString", scalar("String"), arg("code", named("OBJECT", "String"))),
            fld("intList", scalar("String"), arg("n", nn(lst(scalar("Int")))),
                arg("code", scalar("ID"))),
            fld("nestedList", scalar("String"), arg("n", nn(lst(lst(scalar("String"))))),
                arg("code", scalar("ID"))))
    types = BUILTINS + [q, enum("Cls", "bad name", "true", "FIRST", "SECOND"),
                        enum("Empty")]
    ops, skipped = operations_with_skips(parse_schema(answer(types, query="Ticketing")))
    assert [op.field for op in ops] == ["seat"]
    assert ops[0].variables["cls"] == "FIRST"
    assert {f for f, _k, _r in skipped} == {"noValues", "fakeString", "intList",
                                            "nestedList"}
    assert_round_trips(ops[0])


def test_object_selection_is_depth_one_and_capped():
    many = [fld(f"f{i}", scalar("Int")) for i in range(MAX_SELECTED_FIELDS + 5)]
    big = obj("Event", fld("venue", named("OBJECT", "Venue")), *many)
    q = obj("Query", fld("event", named("OBJECT", "Event"), arg("slug", nn(scalar("String")))))
    op, = operations(parse_schema(answer(BUILTINS + [q, big, obj("Venue")])))
    selected = op.document.split("{ event(slug: $slug) { ")[1].rstrip(" }").split()
    assert selected == [f"f{i}" for i in range(MAX_SELECTED_FIELDS)]
    assert op.document.count("{") == 2                 # never a nested selection
    assert_round_trips(op)


# --------------------------------------------------------------------------- bounds

def test_types_fields_and_args_are_truncated_at_their_bounds():
    filler = [sc(f"S{i}") for i in range(MAX_TYPES + 10)]
    late = obj("Late", fld("x", scalar("String"), arg("q", scalar("String"))))
    schema = parse_schema(answer(BUILTINS + filler + [late], query="Late"))
    assert schema is not None and len(schema.types) == MAX_TYPES
    assert "Late" not in schema.types and operations(schema) == []

    fields = [fld(f"f{i}", scalar("String"), arg("q", scalar("String")))
              for i in range(MAX_FIELDS_PER_TYPE + 10)]
    schema = parse_schema(answer(BUILTINS + [obj("Query", *fields)]))
    assert len(schema.types["Query"].fields) == MAX_FIELDS_PER_TYPE
    assert len(operations(schema, max_operations=10_000)) == MAX_FIELDS_PER_TYPE

    args = [arg(f"a{i}", scalar("String")) for i in range(MAX_ARGS + 10)]
    schema = parse_schema(answer(BUILTINS + [obj("Query", fld("f", scalar("String"), *args))]))
    assert len(schema.types["Query"].fields[0].args) == MAX_ARGS
    op, = operations(schema)
    assert len(op.targets) == MAX_ARGS


def test_the_largest_document_stays_inside_the_project_readers_bound():
    longest = "x" * MAX_NAME_CHARS
    args = [arg(f"{longest[:-3]}{i:03d}", nn(scalar("String"))) for i in range(MAX_ARGS)]
    ret = obj("R" + longest[1:], *[fld(f"{longest[:-1]}{i}", scalar("String"))
                                   for i in range(MAX_SELECTED_FIELDS)])
    q = obj("Query", fld(longest, named("OBJECT", ret["name"]), *args))
    op, = operations(parse_schema(answer(BUILTINS + [q, ret])))
    assert len(op.document) < CAPTURE_MAX_BYTES // 2
    assert len(op.targets) == MAX_ARGS
    assert_round_trips(op)


def test_duplicate_names_keep_the_first():
    q1 = obj("Query", fld("a", scalar("String"), arg("q", scalar("String")),
                          arg("q", nn(scalar("Int")))),
             fld("a", scalar("String"), arg("other", scalar("String"))))
    q2 = obj("Query", fld("never", scalar("String"), arg("q", scalar("String"))))
    ops = operations(parse_schema(answer(BUILTINS + [q1, q2])))
    assert [(op.field, op.targets) for op in ops] == [("a", ("q",))]
    assert ops[0].document == "query FuzzlabA($q: String) { a(q: $q) }"


def test_a_schema_is_frozen():
    schema = bookstore()
    assert isinstance(schema, Schema)
    with pytest.raises(TypeError):
        schema.types["X"] = None
    op = operations(schema)[0]
    with pytest.raises(TypeError):
        op.variables["id"] = "other"
    body = op.body()
    body["variables"]["id"] = "changed"
    assert op.variables["id"] == "fuzzlab"
