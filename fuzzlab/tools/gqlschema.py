"""GraphQL schema discovery: one bounded introspection request, a total parser of its
answer, and the operations a schema's root types offer to fuzz (FR-CRAWL-670).

Pure: no I/O, no network. The caller sends `introspection_body()` (lab-only, under its
own ``--authorized`` gate) and hands the answer's text to `parse_schema`.

**The only authority is the GraphQL specification** (October 2021 edition): §4
Introspection (the ``__schema`` meta-field, ``__Schema.queryType`` /
``mutationType`` / ``types``, ``__Type`` with ``kind``, ``name``, ``fields``, ``args``,
``inputFields``, ``enumValues`` and ``ofType``, and the ``__TypeKind`` enum: SCALAR,
OBJECT, INTERFACE, UNION, ENUM, INPUT_OBJECT, LIST, NON_NULL), §3.5 the built-in
scalars (Int, Float, String, Boolean, ID), §2.1.9 Names (``/[_A-Za-z][_0-9A-Za-z]*/``)
and §5.8 / §6.1.2 variables. Nothing here knows any application's field, argument or
type names: every name comes from the target's own schema, and a name that is not a
GraphQL Name is skipped, never written into a document.

**The introspection request** (`INTROSPECTION_QUERY`) is one operation, one
``__schema`` selection, no descriptions, no directives, no subscription type, no
aliases and no repeated selections. Its type-reference fragment nests ``ofType``
three times, so a reference is read to four levels: enough for every wrapper chain a
variable can be declared with here (``[String!]!`` is NON_NULL, LIST, NON_NULL,
SCALAR). A deeper chain reads as unreadable, never guessed.

**The parser** (`parse_schema`) is total: non-JSON, an ``errors`` answer, wrong JSON
types, duplicate or odd names, lone surrogates and deep nesting are None or a bounded
`Schema`, never an exception (PA-0500(1), PA-0096, PA-0454(1)). Its bounds are
enforced before or inside the loop that does the work (PA-0536): text over
`MAX_RESPONSE_CHARS` is not parsed; at most `MAX_TYPES` types, `MAX_FIELDS_PER_TYPE`
fields or input fields, `MAX_ARGS` arguments per field and `MAX_ENUM_VALUES` enum
values are read (the first ones, in schema order); a name over `MAX_NAME_CHARS` is not
a usable name. The first type of a name wins.

**The operations** (`operations`, `operations_with_skips`). Every field of a requested
root type that takes a ``String`` or ``ID`` argument (not inside a list) becomes one
request whose String/ID variables are the points to fuzz (`SchemaOperation.targets`).
A required argument of another type is filled with a neutral value (Int ``1``, Float
``1.0``, Boolean ``false``, an enum's first value, a String/ID list ``["fuzzlab"]``);
a field with a required argument that cannot be filled (an input object, a custom
scalar, any other list) is skipped with its reason. "Required" is a NON_NULL argument
type: the introspection request does not read ``defaultValue``, so a NON_NULL argument
with a default is filled too, which is valid. The selection is depth 1 only, never a
nested object selection. Every document is read back by the project's own GraphQL
reader (`tools.apiop.graphql_operations` / `graphql_variable_bindings`): a root field
that reader cannot bind (a field named ``on``) is skipped.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

#: Answer text longer than this is not parsed (None).
MAX_RESPONSE_CHARS = 2_000_000
#: At most this many types are read from ``__schema.types`` (the first ones).
MAX_TYPES = 2000
#: At most this many fields (and input fields) are read per type.
MAX_FIELDS_PER_TYPE = 500
#: At most this many arguments are read per field.
MAX_ARGS = 50
#: At most this many enum values are read per enum type.
MAX_ENUM_VALUES = 500
#: A name longer than this is not used (keeps every generated document far under the
#: project reader's `core.redaction.CAPTURE_MAX_BYTES`).
MAX_NAME_CHARS = 128
#: At most this many scalar/enum fields are selected from an object return type.
MAX_SELECTED_FIELDS = 8
#: The levels of a type reference the introspection request reads (§4: ``ofType``).
TYPE_REF_DEPTH = 4

#: The text filler String/ID variables get: the importer's own
#: (`tools.store_adapter._TEXT_FILLER`; a test pins the two equal, PA-0001).
TEXT_FILLER = "fuzzlab"

_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_NAMED_KINDS = frozenset({"SCALAR", "OBJECT", "INTERFACE", "UNION", "ENUM", "INPUT_OBJECT"})
_WRAPPERS = frozenset({"NON_NULL", "LIST"})
_TARGET_SCALARS = frozenset({"String", "ID"})
_ROOT_KINDS = ("query", "mutation")
#: Root field names the project's GraphQL reader cannot bind arguments for
#: (`tools.apiop.graphql_variable_bindings` treats ``on`` as a keyword).
_UNBINDABLE_FIELDS = frozenset({"on"})

_TYPE_REF_FRAGMENT = (
    "fragment T on __Type { kind name ofType { kind name ofType { kind name "
    "ofType { kind name } } } }"
)

#: The one bounded introspection document (GraphQL spec §4).
INTROSPECTION_QUERY = (
    "query FuzzlabIntrospection { __schema { queryType { name } mutationType { name } "
    "types { kind name fields(includeDeprecated: false) { name args { name type { ...T } } "
    "type { ...T } } inputFields { name type { ...T } } "
    "enumValues(includeDeprecated: false) { name } } } } " + _TYPE_REF_FRAGMENT
)
INTROSPECTION_OPERATION = "FuzzlabIntrospection"


def introspection_body() -> dict:
    """The JSON body of the introspection request."""
    return {"query": INTROSPECTION_QUERY, "operationName": INTROSPECTION_OPERATION}


def is_name(value) -> bool:
    """True when ``value`` is a GraphQL Name (§2.1.9) of at most `MAX_NAME_CHARS`.
    Total."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_NAME_CHARS
            and _NAME.fullmatch(value) is not None)


# --------------------------------------------------------------------------- model

@dataclass(frozen=True)
class TypeRef:
    """A type reference: the named type it unwraps to and its wrapper chain, outermost
    first (``[String!]!`` -> ``("NON_NULL", "LIST", "NON_NULL")``)."""

    name: str
    kind: str
    wrappers: tuple = ()

    @property
    def non_null(self) -> bool:
        return self.wrappers[:1] == ("NON_NULL",)

    @property
    def is_list(self) -> bool:
        return "LIST" in self.wrappers

    def render(self) -> str:
        """The reference as GraphQL type syntax, exactly as declared."""
        text = self.name
        for wrapper in reversed(self.wrappers):
            text = text + "!" if wrapper == "NON_NULL" else "[" + text + "]"
        return text


@dataclass(frozen=True)
class SchemaArg:
    """An argument or input field; ``type`` is None when its reference is unreadable."""

    name: str
    type: TypeRef | None


@dataclass(frozen=True)
class SchemaField:
    name: str
    args: tuple
    type: TypeRef | None


@dataclass(frozen=True)
class SchemaType:
    kind: str
    name: str
    fields: tuple = ()
    input_fields: tuple = ()
    enum_values: tuple = ()


@dataclass(frozen=True)
class Schema:
    query_type: str
    mutation_type: str | None
    types: Mapping[str, SchemaType]

    def root(self, kind: str) -> SchemaType | None:
        name = {"query": self.query_type, "mutation": self.mutation_type}.get(kind)
        return self.types.get(name) if name is not None else None


@dataclass(frozen=True)
class SchemaOperation:
    """One GraphQL request for one root field."""

    kind: str
    field: str
    operation_name: str
    document: str
    variables: Mapping
    targets: tuple

    def body(self) -> dict:
        return {"query": self.document, "operationName": self.operation_name,
                "variables": dict(self.variables)}


# --------------------------------------------------------------------------- parser

def _str_or_none(value):
    return value if isinstance(value, str) else None


def _type_ref(node) -> TypeRef | None:
    """A ``__Type`` reference read to `TYPE_REF_DEPTH` levels; None when it is not a
    well-formed chain ending in a named type (a NON_NULL directly inside a NON_NULL,
    an unknown kind, a missing name). Iterative and bounded."""
    wrappers: list[str] = []
    for _level in range(TYPE_REF_DEPTH):
        if not isinstance(node, dict):
            return None
        kind = node.get("kind")
        if kind in _WRAPPERS:
            if kind == "NON_NULL" and wrappers[-1:] == ["NON_NULL"]:
                return None
            wrappers.append(kind)
            node = node.get("ofType")
            continue
        if kind in _NAMED_KINDS:
            name = node.get("name")
            if not isinstance(name, str) or not name:
                return None
            return TypeRef(name=name, kind=kind, wrappers=tuple(wrappers))
        return None
    return None


def _args(nodes, limit) -> tuple:
    out: list[SchemaArg] = []
    if not isinstance(nodes, list):
        return ()
    for node in nodes[:limit]:
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        if not isinstance(name, str) or not name:
            continue
        out.append(SchemaArg(name=name, type=_type_ref(node.get("type"))))
    return tuple(out)


def _fields(nodes) -> tuple:
    out: list[SchemaField] = []
    if not isinstance(nodes, list):
        return ()
    for node in nodes[:MAX_FIELDS_PER_TYPE]:
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        if not isinstance(name, str) or not name:
            continue
        out.append(SchemaField(name=name, args=_args(node.get("args"), MAX_ARGS),
                               type=_type_ref(node.get("type"))))
    return tuple(out)


def _enum_values(nodes) -> tuple:
    if not isinstance(nodes, list):
        return ()
    out = []
    for node in nodes[:MAX_ENUM_VALUES]:
        if isinstance(node, dict) and isinstance(node.get("name"), str):
            out.append(node["name"])
    return tuple(out)


def _root_name(node):
    return _str_or_none(node.get("name")) if isinstance(node, dict) else None


def parse_schema(text) -> Schema | None:
    """The `Schema` an introspection answer (``{"data": {"__schema": ...}}``)
    describes, bounded by this module's limits; None for anything else (text over
    `MAX_RESPONSE_CHARS`, not JSON, an ``errors`` answer, no ``__schema``, a query
    type name that is not a GraphQL Name; a mutation type name that is not one reads
    as no mutation type). Total: never raises."""
    try:
        return _parse_schema(text)
    except (RecursionError, MemoryError):
        return None
    except Exception:  # noqa: BLE001 -- the contract is a sentinel, never a raise
        return None


def _parse_schema(text) -> Schema | None:
    if isinstance(text, (bytes, bytearray)):
        if len(text) > MAX_RESPONSE_CHARS * 4:
            return None
        text = bytes(text).decode("utf-8", errors="replace")
    if not isinstance(text, str) or len(text) > MAX_RESPONSE_CHARS:
        return None
    text = text.removeprefix("﻿")
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError, TypeError):
        return None
    if not isinstance(doc, dict) or doc.get("errors"):
        return None
    data = doc.get("data")
    if not isinstance(data, dict):
        return None
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return None
    query_type = _root_name(schema.get("queryType"))
    if not is_name(query_type):
        return None
    mutation_type = _root_name(schema.get("mutationType"))
    if not is_name(mutation_type):
        mutation_type = None
    nodes = schema.get("types")
    types: dict[str, SchemaType] = {}
    if isinstance(nodes, list):
        for node in nodes[:MAX_TYPES]:
            if not isinstance(node, dict):
                continue
            kind, name = node.get("kind"), node.get("name")
            if kind not in _NAMED_KINDS or not isinstance(name, str) or not name \
                    or name in types:
                continue
            types[name] = SchemaType(
                kind=kind, name=name, fields=_fields(node.get("fields")),
                input_fields=_args(node.get("inputFields"), MAX_FIELDS_PER_TYPE),
                enum_values=_enum_values(node.get("enumValues")))
    return Schema(query_type=query_type, mutation_type=mutation_type,
                  types=MappingProxyType(types))


# --------------------------------------------------------------------------- operations

def _kind_of(schema: Schema, ref: TypeRef) -> str:
    """The named type's kind: the schema's own type of that name, else the reference."""
    known = schema.types.get(ref.name)
    return known.kind if known is not None else ref.kind


def _is_target(schema: Schema, ref: TypeRef | None) -> bool:
    return (ref is not None and ref.name in _TARGET_SCALARS and not ref.is_list
            and ref.kind == "SCALAR" and _kind_of(schema, ref) == "SCALAR")


_UNFILLABLE = object()


def _filler(schema: Schema, ref: TypeRef):
    """A neutral value for a required non-target argument, or `_UNFILLABLE`."""
    kind = _kind_of(schema, ref)
    inner = tuple(w for w in ref.wrappers if w == "LIST")
    if inner == ("LIST",):
        if ref.name in _TARGET_SCALARS and kind == "SCALAR":
            return [TEXT_FILLER]
        return _UNFILLABLE
    if inner:
        return _UNFILLABLE
    if kind == "SCALAR":
        return {"Int": 1, "Float": 1.0, "Boolean": False}.get(ref.name, _UNFILLABLE)
    if kind == "ENUM":
        known = schema.types.get(ref.name)
        for value in (known.enum_values if known is not None else ()):
            if is_name(value) and value not in ("true", "false", "null"):
                return value
    return _UNFILLABLE


def _selection(schema: Schema, ref: TypeRef | None):
    """The depth-1 selection text for a return type ("" for none), or None (cannot)."""
    if ref is None or not is_name(ref.name):
        return None
    kind = _kind_of(schema, ref)
    if kind in ("SCALAR", "ENUM"):
        return ""
    if kind in ("INTERFACE", "UNION"):
        return " { __typename }"
    if kind != "OBJECT":
        return None
    known = schema.types.get(ref.name)
    chosen: list[str] = []
    for field in (known.fields if known is not None else ()):
        if len(chosen) >= MAX_SELECTED_FIELDS:
            break
        if not is_name(field.name) or field.name.startswith("__") or field.name in chosen:
            continue
        if field.type is None or _kind_of(schema, field.type) not in ("SCALAR", "ENUM"):
            continue
        if any(arg.type is None or arg.type.non_null for arg in field.args):
            continue
        chosen.append(field.name)
    return " { " + " ".join(chosen or ["__typename"]) + " }"


def _build(schema: Schema, kind: str, field: SchemaField):
    """A `SchemaOperation` for ``field``, or the reason it is skipped (a str)."""
    if not is_name(field.name):
        return "field name is not a GraphQL Name"
    if field.name in _UNBINDABLE_FIELDS:
        return "field name the project's GraphQL reader cannot bind"
    decls: list[str] = []
    uses: list[str] = []
    variables: dict = {}
    targets: list[str] = []
    seen: set = set()
    for arg in field.args:
        if arg.name in seen:
            continue
        seen.add(arg.name)
        ref = arg.type
        required = ref is not None and ref.non_null
        usable = is_name(arg.name) and ref is not None and is_name(ref.name)
        if _is_target(schema, ref) and usable:
            value = TEXT_FILLER
            targets.append(arg.name)
        elif not required:
            continue                  # optional non-target or unusable: never written
        elif not usable:
            return f"required argument {arg.name!r} has an unusable name or type"
        else:
            value = _filler(schema, ref)
            if value is _UNFILLABLE:
                return (f"required argument {arg.name!r} of type {ref.render()} "
                        "cannot be filled")
        decls.append(f"${arg.name}: {ref.render()}")
        uses.append(f"{arg.name}: ${arg.name}")
        variables[arg.name] = value
    if not targets:
        return "no String or ID argument"
    selection = _selection(schema, field.type)
    if selection is None:
        return "return type is unreadable"
    name = "Fuzzlab" + field.name[0].upper() + field.name[1:]
    document = (f"{kind} {name}({', '.join(decls)}) "
                f"{{ {field.name}({', '.join(uses)}){selection} }}")
    return SchemaOperation(kind=kind, field=field.name, operation_name=name,
                           document=document, variables=MappingProxyType(variables),
                           targets=tuple(targets))


def operations_with_skips(schema, *, kinds=("query",), max_operations=200):
    """``(operations, skipped)``: the `SchemaOperation` of every root field of each
    requested kind (``"query"``, ``"mutation"``; in that order of ``kinds``, fields in
    schema order) that takes a String or ID argument, at most ``max_operations``; and
    ``(field, kind, reason)`` for every other non-meta root field. A field whose name
    starts with ``__`` is never an operation and never listed."""
    if isinstance(max_operations, bool) or not isinstance(max_operations, int):
        raise TypeError("max_operations must be an int")
    ops: list[SchemaOperation] = []
    skipped: list[tuple] = []
    if not isinstance(schema, Schema):
        return ops, skipped
    if isinstance(kinds, str):
        kinds = (kinds,)
    for kind in dict.fromkeys(k for k in kinds if k in _ROOT_KINDS):
        root = schema.root(kind)
        if root is None:
            continue
        done: set = set()
        for field in root.fields:
            if field.name.startswith("__") or field.name in done:
                continue
            done.add(field.name)
            built = _build(schema, kind, field)
            if isinstance(built, str):
                skipped.append((field.name, kind, built))
            elif len(ops) >= max_operations:
                skipped.append((field.name, kind, "over max_operations"))
            else:
                ops.append(built)
    return ops, skipped


def operations(schema, *, kinds=("query",), max_operations=200) -> list:
    """The `SchemaOperation` list of `operations_with_skips`."""
    return operations_with_skips(schema, kinds=kinds, max_operations=max_operations)[0]
