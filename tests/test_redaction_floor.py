"""The redaction floor: every URL redaction consumer runs the pushed tree's redactor first
(BUG-0556 r6, the owner's design for audit gap 5; PA-0556 item 11; SP-17).

`fuzzlab/core/redaction_floor.py` holds 7393c90's own redaction code, verbatim, for every
consumer the batch changed; each consumer (`core.redaction.LAYERED`) runs its floor on
its input as received and the batch's walk on the floor's output only, so nothing the
pushed tree redacted can be kept again. Three guards hold the design:

1. **the floor is frozen**: each of its definitions hashes to 7393c90's text (a SHA-256
   taken from ``git show 7393c90:<file>`` when this guard was written, recorded below),
   after the recorded substitutions (a function-local import of a live module pointed at
   the floor, so the frozen code never calls a layered redactor), and the module holds
   exactly those definitions after its pinned docstring and imports;
2. **every consumer runs its floor first**: by AST, the first statement of each
   `LAYERED` function (after its docstring and imports) calls its floor on its own
   parameters as given, calls nothing else, and the function never reads its text
   parameter again;
3. **nothing runs the walk or the floor unregistered**: across ``fuzzlab/``, every call
   of the walk (`_UrlWalk`, a `WALK_HELPERS` step, a `WALK_PREDICATES` predicate) is made
   from a registered function, and every call of the floor from a `LAYERED` consumer.

Each check is proven on synthetic offenders (PA-0034(2)): an edited floor, a consumer
that skips its floor, runs the walk first, gives the floor a changed input or reads its
raw input after it (144d234's `core.trace.safe_ref`, R1), and an unregistered caller.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from fuzzlab.core import redaction as R

ROOT = Path(__file__).resolve().parent.parent
FLOOR_REL = "fuzzlab/core/redaction_floor.py"
FLOOR_MODULE = "fuzzlab.core.redaction_floor"

#: (definition, its file at 7393c90, SHA-256 of its text there), in the floor's order.
FROZEN = [
    ("SENSITIVE_TOKENS", "fuzzlab/core/redaction.py",
     "eb7c17a7191699684b73ab65b8809299b24026e7e663379d0dfff1529cf5c3f2"),
    ("_KEY_QUALIFIERS", "fuzzlab/core/redaction.py",
     "a67e10a341337d332cbc0238a087a959bbdaf0b43d94a2f77ec96de8c8c47627"),
    ("_SPLIT", "fuzzlab/core/redaction.py",
     "ad70f1c7bf680b13a6f1d71a6432ee18b007f281fbe6404f9f5f03a6cc134afd"),
    ("name_tokens", "fuzzlab/core/redaction.py",
     "3c187e9b50039628880e656430976c6db7d60d86b32c73b97de2be7d42de8f09"),
    ("_fold", "fuzzlab/core/redaction.py",
     "0342d3b5c144a3eb46cc9f406d73595ff3a45d4457ac54b3d8e1fced8edd25c1"),
    ("SENSITIVE_PAIRS", "fuzzlab/core/redaction.py",
     "685e38ffa3546ccea2d6b035afc30e8a19108435499fa18bef3f2c3fd19d7ea6"),
    ("is_sensitive_name", "fuzzlab/core/redaction.py",
     "f1d66d8fac10b246d2fc436d320c9e07a44c60fe3ef4fe77802397178c6cddbb"),
    ("_PIECE_SPLIT", "fuzzlab/core/redaction.py",
     "c1d75a310f0b68928884909fbac6b0722c125b1cee58198d9412e94d58cac19c"),
    ("_URL_PIECE_SPLIT", "fuzzlab/core/redaction.py",
     "5228efb48bc40ebd3d09c99414768ceaab149149096955be2e7e722588ee5ba1"),
    ("_ID_ALPHABET", "fuzzlab/core/redaction.py",
     "38834f59b4d340008bffd1db52810f1e1dd54473183801eeebd425b3e80fd4b0"),
    ("ID_MIN_LEN", "fuzzlab/core/redaction.py",
     "bf7bec76bae6e7298ada0b2b5ff97a4e89fc8a632d436871bc2037dffde48b11"),
    ("ID_SHORT_MIN_LEN", "fuzzlab/core/redaction.py",
     "5fdbcdcb15a94b1b5c5e16810c1d61690284d16719545803229d5ef79fd7e20b"),
    ("ID_SHORT_MIN_BITS", "fuzzlab/core/redaction.py",
     "977887c77f6c3534e97b7aab6a3e862945dfa0d99df65e69ab6daffb122c550f"),
    ("_WORD_PART", "fuzzlab/core/redaction.py",
     "0638a3c6fe4224e00dec529ffb1999cf38e2ff0602dfccaa4c97c5c41e43ee0d"),
    ("_DATE_PIECE", "fuzzlab/core/redaction.py",
     "fe181fa8dc7174a3fbd58adffe2221b29e4688bc6df2ff441681e2159aa64f35"),
    ("_shannon_bits", "fuzzlab/core/redaction.py",
     "5f7ad2def1dbf4579d784b7de0241a3f15fdb9c0ce4d22edc455cf5242061c00"),
    ("_word_shaped", "fuzzlab/core/redaction.py",
     "b77c080530c5077e3481c00b56cada447ae58c143046535aaa6d7ac869cd86b0"),
    ("_identifier_piece", "fuzzlab/core/redaction.py",
     "3c3635199dbfea17a2eafe25d169513c18e158853f43db3b2c49cbf3fcaa44d6"),
    ("looks_like_identifier", "fuzzlab/core/redaction.py",
     "5953c885f47e42d36e668f932b19c822d11559dff066863e08eea328ca67a851"),
    ("PLACEHOLDER", "fuzzlab/core/redaction.py",
     "6966a7a7551591301db20be8a252cd6d9ba7cc00d1ed1b9901fbc3755071a873"),
    ("MAX_REDACT_BYTES", "fuzzlab/core/redaction.py",
     "f3d43c37144d413497b0d8d5180fbd3d510f8efc971fb819394a25ae4aba8966"),
    ("MAX_JSON_DEPTH", "fuzzlab/core/redaction.py",
     "0fded71a94a418e3e5a728d3d36c3768c5348bb2903dde3ed1eac5ce5c0992cb"),
    ("OMIT_TOO_LARGE", "fuzzlab/core/redaction.py",
     "5d2d29b1adf8ee9b4ee410028f4a82d4b380480989d6bc54737f1a2cee7232bc"),
    ("OMIT_UNSAFE", "fuzzlab/core/redaction.py",
     "a30b2be5d7ccb9afbe249e5c75039954edd5f3f430a99826ad8e7a6a7ca571e4"),
    ("OMIT_FAILED", "fuzzlab/core/redaction.py",
     "a20560a5cf6a03aec7e0feebf0cd9abc74cf4f5a258296fca8a28f704688432c"),
    ("_WORD", "fuzzlab/core/redaction.py",
     "102ac2b75346dd8ec48819ec1c39d2c1a6d80319e019b8dad8a0045b3684fe0a"),
    ("_DQ", "fuzzlab/core/redaction.py",
     "79fb3352c9b983b41025a00d0499a9621c00cfa8d135df5f702aff1685affa2e"),
    ("_SQ", "fuzzlab/core/redaction.py",
     "9d5cf573f4876d0a7ad0d2efe1353655bbfdad2ea476b56f533ea310b82c39ab"),
    ("_FORM_SHAPE", "fuzzlab/core/redaction.py",
     "e40630f8e3857d02ed03937fb37e8611808173fd58221671868f6329dd76c670"),
    ("redact_query", "fuzzlab/core/redaction.py",
     "860f9e1366d8d1a66579aa62d3c810d9346677eabbdeed0f2ce4ecfe7a73a512"),
    ("redact_url", "fuzzlab/core/redaction.py",
     "fbe2d4110f6ac4ccc0afc36feeb611b7a6bd92e18f7ab1999af2d4f7e2c18b04"),
    ("_redact_json", "fuzzlab/core/redaction.py",
     "2a38f88f4cd91ecb41719f4a0f298dc31dc82ba4d6893cd912cfbe6f104f01d1"),
    ("_depth_ok", "fuzzlab/core/redaction.py",
     "5fb2048ee249ec8096aca09e2afac6e392e122d34c24452839cfc2bba7bf4248"),
    ("mentions_sensitive_name", "fuzzlab/core/redaction.py",
     "801a3af54bdc7d57c45e65e10fb4afeab63a9c89caead1a19dc96f3f3226990d"),
    ("_unsafe", "fuzzlab/core/redaction.py",
     "9eb0f1d206a3e84b3849879f48e4aeecb91409b59f563ec2486d60619043d320"),
    ("redact_json_body", "fuzzlab/core/redaction.py",
     "5a41ee6d4c5777f01ea44155640d7a8b562f07798bfc09e183586ab067660349"),
    ("redact_form_body", "fuzzlab/core/redaction.py",
     "b577f1b0e0440eff44625a920133cc064295db05b87a2baa3e6b9dc6f2407d30"),
    ("redact_multipart_body", "fuzzlab/core/redaction.py",
     "030ce7a87627b086515ef55beda34c03e4c945a157937499ee8f2dad65d08e72"),
    ("body_kind", "fuzzlab/core/redaction.py",
     "fcc101ec16e8c77e432ef58f00d8c9e974f5970bd606c13f0cf82e59110d9daa"),
    ("redact_body", "fuzzlab/core/redaction.py",
     "e92882c408113d0c000554ee3fca8e9601267c5d77955e9cf09cdc5091c6db68"),
    ("_redact_query_identifiers", "fuzzlab/core/redaction.py",
     "41f7b7d9d89b968cc9ab595f5ef7087f537a243193d6f35e434376619ebcceda"),
    ("redact_spa_fragment", "fuzzlab/core/redaction.py",
     "dd4b81d678dd19a9ecb237757433ed0542985f28404d6ad55b6bd053092929bd"),
    ("page_url_is_clean", "fuzzlab/core/redaction.py",
     "4f3e7bfcfb62d3183bcf91e75979843915242c575bdcb88a1a365251f33f70fd"),
    ("redact_url_identifiers", "fuzzlab/core/redaction.py",
     "9b3c88e4f0f076a930ac31fe357caa705db4bbb921ca22c66268e2fde5741d88"),
    ("_URL_USERINFO", "fuzzlab/core/redaction.py",
     "f3e7ea44e152b92acd9fb6db6ef05e98642b01283ecfa78e52a71c03acb299ce"),
    ("_BARE_USERINFO", "fuzzlab/core/redaction.py",
     "99e49c752b8df97348102456f7a95a21b6112c17378d34a4f36731504ccce93e"),
    ("_MATRIX_PARAM", "fuzzlab/core/redaction.py",
     "1268ac2ceabaa1178cfe6d0812d0eff2536f2d85c65c0c4d076367e23be23339"),
    ("USERINFO_PLACEHOLDER", "fuzzlab/core/redaction.py",
     "095e598b685ad2afbda88c7274d6b0b17c6d63b3e01fc03a0422df76cce1f2f6"),
    ("MAX_RECORD_CHARS", "fuzzlab/core/redaction.py",
     "8ec86770fa4f1832157a73001e40e73c2cf52208f7b103e1bef49d069fd20741"),
    ("redact_for_record", "fuzzlab/core/redaction.py",
     "7d8a9097bcf3c42173ec5ff2c1420b7eb38e09f407fa811ec5dee6d85305b23f"),
    ("_redact_piece", "fuzzlab/core/redaction.py",
     "874dd8ca33d0e0825036bf6195fb4f3eb31c4fbbc20f27e9c982f72db0f6c645"),
    ("SPA_ROUTE_PREFIXES", "fuzzlab/core/urls.py",
     "f94d9e4795865bdb2ecc5d3171d23cff194c5f5c8522f9b5b11f8cc3b0f9bc43"),
    ("is_spa_route_fragment", "fuzzlab/core/urls.py",
     "7f4abd818a8cc364c672f1d4b770a556fe8e5360a27877274cb1e1d1e2a0ba35"),
    ("REDACTED_SEGMENT", "fuzzlab/core/trace.py",
     "1f0d6bd98e660ce607684c71db76fb366d93cd798ee7485c11739ff0ebec5c92"),
    ("_TOKEN_RUN", "fuzzlab/core/trace.py",
     "547fb86612d0f77e4e0c611f353523bdd9b0540e906d5ac2c5e791d9a2cfcf93"),
    ("safe_ref", "fuzzlab/core/trace.py",
     "dadfd955b2a1bcfc6be1043d87a3f78777b2c6332ec96efedb5aeb8408e23901"),
    ("_blank_identifiers", "fuzzlab/core/trace.py",
     "198663fb16a0078debc2402a3c3bd3544803513691970b48108dd3e2202292c8"),
    ("redact_sibling", "fuzzlab/tools/store_adapter.py",
     "3e963d4f80302dcd42fa302130944beab59428bd4645275b3ddc352e3ca4c656"),
    ("CRLF", "fuzzlab/proxy/message.py",
     "f72694721d609ab0bd37e853d2ae0d380dcc06bfef47b2880178a7ff523952ca"),
    ("_HEAD_SEPS", "fuzzlab/proxy/message.py",
     "e7d6f2d97066c0db2601e5b7b910ac0262fd8a12bdf04a5d38dfdb5661b173f0"),
    ("_split_head_body", "fuzzlab/proxy/message.py",
     "7fafeb5d371ea8d93747a96ccd307b0567be18809bcb12cc0fdf02e7dee1f606"),
    ("RawMessage", "fuzzlab/proxy/message.py",
     "85537f5044cfa1bd50a3908a664bb3c93a81ffb1d57f8ed1d087097fc515964d"),
    ("_as_bytes", "fuzzlab/proxy/message.py",
     "5d0487bb9b88bc353b29e088d5f3559cecc64147e053df201927aea9a9b31166"),
    ("REDACTED", "fuzzlab/proxy/redact.py",
     "0cf3ab043fd9bb7f4a2b19e655c5c7aa289d6cab286919b677e80e1be27e1ddf"),
    ("SENSITIVE_HEADERS", "fuzzlab/proxy/redact.py",
     "27853fa912caa9fd4fdd9d25c71d341739e5610f6223bcb165d9929b4692cbe4"),
    ("_URL_HEADERS", "fuzzlab/proxy/redact.py",
     "89bd931e8df1c2931d1b3512218dc377a5344e25cef5521c3d6b373dae94c997"),
    ("_dechunk", "fuzzlab/proxy/redact.py",
     "aaed3f0b7587d7baf02ad8b5d25edb661645d46037b38cc0fc8c845ae99dbfbb"),
    ("_decompress", "fuzzlab/proxy/redact.py",
     "f9d8054ec92c150b873d25e8ba77627c7aaa179a2ad43ef82f534a372bb6e07c"),
    ("_framed_payload", "fuzzlab/proxy/redact.py",
     "adb43328e46de6bbdd84ae3ab221f1bfe1834a103522eee807ca3f1e8d206ab0"),
    ("_framed_body_unsafe", "fuzzlab/proxy/redact.py",
     "aeb8e4adab5c07afa2c692a3138dc9c8f726d7fcda0e2d14148baa74a160620b"),
    ("_original_name", "fuzzlab/proxy/redact.py",
     "6c11298acb61742e31f4bb124c9b39f94b2d5cd95e6dcd4614b4361b13ed8d67"),
    ("_header", "fuzzlab/proxy/redact.py",
     "f7b569f5924e33c0d669170b226e74a9db7bd0ede7cf466448eb349c65ff8d01"),
    ("redact", "fuzzlab/proxy/redact.py",
     "d9ede21400c00479ad1efb2060b918f7cddf6231f16e51b0134d643177a05187"),
]
#: The floor's docstring and imports (every statement before its first definition).
HEAD_SHA = "ae2642a99a84889cd40b1d7acfe99636f54a27958858f5ab6c128948c223bba9"
#: The only edits: a function-local import of a live module, pointed at the floor
#: ``(text in the floor, text at 7393c90)``; each must occur exactly once.
SUBS = {
    "redact_spa_fragment": [(f"from {FLOOR_MODULE} import is_spa_route_fragment",
                             "from fuzzlab.core.urls import is_spa_route_fragment")],
    "safe_ref": [(f"from {FLOOR_MODULE} import redact_for_record, redact_url_identifiers",
                  "from fuzzlab.core.redaction import redact_for_record, "
                  "redact_url_identifiers")],
    "_blank_identifiers": [(f"from {FLOOR_MODULE} import looks_like_identifier",
                            "from fuzzlab.core.redaction import looks_like_identifier")],
    "redact_sibling": [(f"from {FLOOR_MODULE} import is_sensitive_name, looks_like_identifier",
                        "from fuzzlab.core.redaction import is_sensitive_name, "
                        "looks_like_identifier")],
}
#: Every consumer the batch changed in a redaction path, and its floor: a consumer
#: removed from `LAYERED` fails here, so none leaves the registry to escape guard 2.
EXPECTED_LAYERED = {
    ("fuzzlab/core/redaction.py", "redact_url"),
    ("fuzzlab/core/redaction.py", "redact_url_identifiers"),
    ("fuzzlab/core/redaction.py", "redact_spa_fragment"),
    ("fuzzlab/core/redaction.py", "page_url_is_clean"),
    ("fuzzlab/core/redaction.py", "redact_for_record"),
    ("fuzzlab/core/redaction.py", "stored_value"),
    ("fuzzlab/core/trace.py", "safe_ref"),
    ("fuzzlab/proxy/redact.py", "redact"),
}
#: The floor's consumers: every public 7393c90 redactor it freezes is some consumer's
#: floor.
FLOOR_CONSUMERS = {"redact_url", "redact_url_identifiers", "redact_spa_fragment",
                   "page_url_is_clean", "redact_for_record", "redact_sibling", "safe_ref",
                   "redact"}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _defined(node) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


# --- guard 1: the floor is the pushed tree's code, verbatim ------------------------------
def frozen_problems(text: str) -> list[str]:
    """How a floor module's ``text`` differs from the pinned 7393c90 code: ``[]`` when
    every definition is 7393c90's (after `SUBS`), they are exactly `FROZEN`'s in order,
    and nothing but the pinned head precedes them or follows."""
    tree = ast.parse(text)
    problems = []
    body = list(tree.body)
    first = next((i for i, n in enumerate(body) if _defined(n)), len(body))
    head = "\n".join(ast.get_source_segment(text, n) for n in body[:first])
    if _sha(head) != HEAD_SHA:
        problems.append("the docstring or imports changed")
    rest = body[first:]
    names = [_defined(n) for n in rest]
    if names != [name for name, _path, _sha256 in FROZEN]:
        extra = [n if n else type(node).__name__ for n, node in zip(names, rest)
                 if n not in {f[0] for f in FROZEN}]
        problems.append(f"the definitions are not the frozen list (extra: {extra})")
    expected = {name: digest for name, _path, digest in FROZEN}
    for node in rest:
        name = _defined(node)
        if name not in expected:
            continue
        seg = ast.get_source_segment(text, node)
        for floor_text, pushed_text in SUBS.get(name, ()):
            if seg.count(floor_text) != 1:
                problems.append(f"{name}: its import of the floor changed")
            seg = seg.replace(floor_text, pushed_text)
        if _sha(seg) != expected[name]:
            problems.append(f"{name}: not 7393c90's text")
    return problems


def test_the_floor_is_the_pushed_trees_code_verbatim():
    """Guard 1: the floor is 7393c90's code for every consumer the batch changed, and
    nothing else: never edited (a redactor is fixed in its live owner, layered on it)."""
    text = (ROOT / FLOOR_REL).read_text(encoding="utf-8")
    assert len(FROZEN) == 73 and len({f[0] for f in FROZEN}) == 73
    assert frozen_problems(text) == []


def test_the_frozen_check_flags_an_edited_floor():
    """Guard 1 on synthetic offenders: a changed constant, a changed line of a frozen
    function, a statement added after the definitions (a monkeypatch), a definition
    removed, an import pointed back at the live (layered) module, a docstring edit."""
    text = (ROOT / FLOOR_REL).read_text(encoding="utf-8")
    offenders = {
        "constant": text.replace('PLACEHOLDER = "__REDACTED__"', 'PLACEHOLDER = "__R__"'),
        "function": text.replace("    if not query:\n        return query\n",
                                 "    if not query or len(query) > 9:\n        return query\n",
                                 1),
        "appended": text + "\nredact_url = str\n",
        "removed": text.replace("def _as_bytes(", "def _as_bytes_gone(", 1),
        "live import": text.replace(
            f"from {FLOOR_MODULE} import redact_for_record, redact_url_identifiers",
            "from fuzzlab.core.redaction import redact_for_record, redact_url_identifiers"),
        "docstring": text.replace("NEVER EDITED", "edited", 1),
    }
    for label, edited in offenders.items():
        assert edited != text, label
        assert frozen_problems(edited) != [], label


# --- guard 2: every consumer runs its floor first ----------------------------------------
def _floor_aliases(tree: ast.AST) -> set[str]:
    """Names bound to the floor module (``from fuzzlab.core import redaction_floor as X``,
    ``import fuzzlab.core.redaction_floor as X``) anywhere in ``tree``."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "fuzzlab.core":
            out |= {a.asname or a.name for a in node.names if a.name == "redaction_floor"}
        elif isinstance(node, ast.Import):
            out |= {a.asname for a in node.names if a.name == FLOOR_MODULE and a.asname}
    return out


def _is_floor_call(node, aliases: set[str], floors) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id in aliases
            and node.func.attr in floors)


def layering_problems(source: str, func: str, floors, text_param) -> list[str]:
    """How the function ``func`` of ``source`` breaks the layering: ``[]`` when its first
    statement (after its docstring and imports) calls one of ``floors`` (of the floor
    module) on the function's own leading parameters as received -- ``x = floor(...)``,
    ``x = floor_a(...) if flag else floor_b(...)``, or ``if not floor(...): return
    False`` -- and calls nothing else, and ``text_param`` (when given) is never read
    after that statement, so the walk sees only the floor's output."""
    tree = ast.parse(source)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func),
              None)
    if fn is None:
        return [f"{func}: not defined"]
    aliases = _floor_aliases(tree)
    if not aliases:
        return [f"{func}: the module binds no floor"]
    params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    while body and isinstance(body[0], (ast.Import, ast.ImportFrom)):
        body = body[1:]
    if not body:
        return [f"{func}: empty"]
    first, after = body[0], body[1:]
    problems = []
    calls = [n for n in ast.walk(first) if isinstance(n, ast.Call)]
    floor_calls = [c for c in calls if _is_floor_call(c, aliases, floors)]
    if not floor_calls:
        problems.append(f"{func}: its first statement calls no floor")
    if len(floor_calls) != len(calls):
        problems.append(f"{func}: its first statement calls something besides its floor")
    for call in floor_calls:
        got = [a.id if isinstance(a, ast.Name) else None for a in call.args]
        if call.keywords or None in got or got != params[:len(got)] or not got:
            problems.append(f"{func}: its floor is not given its parameters as received")
    shape_ok = False
    if isinstance(first, ast.Assign) and len(first.targets) == 1 \
            and isinstance(first.targets[0], ast.Name):
        value = first.value
        shape_ok = (_is_floor_call(value, aliases, floors)
                    or (isinstance(value, ast.IfExp)
                        and _is_floor_call(value.body, aliases, floors)
                        and _is_floor_call(value.orelse, aliases, floors)))
    elif isinstance(first, ast.If) and isinstance(first.test, ast.UnaryOp) \
            and isinstance(first.test.op, ast.Not) \
            and _is_floor_call(first.test.operand, aliases, floors) \
            and len(first.body) == 1 and isinstance(first.body[0], ast.Return) \
            and isinstance(first.body[0].value, ast.Constant) \
            and first.body[0].value.value is False and not first.orelse:
        shape_ok = True
    if not shape_ok:
        problems.append(f"{func}: its first statement is not a floor call's result")
    if text_param is not None:
        if text_param not in params:
            problems.append(f"{func}: has no parameter {text_param}")
        for stmt in after:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and node.id == text_param:
                    problems.append(f"{func}: reads {text_param} after its floor (line "
                                    f"{node.lineno}): the walk would see the raw input")
                    break
    return problems


def test_every_url_redaction_consumer_runs_its_floor_first():
    """Guard 2: each `LAYERED` consumer runs the pushed tree's redactor on its input as
    received, then the walk on the floor's output only; the registry holds every
    consumer the batch changed and names every floor consumer."""
    assert set(R.LAYERED) == EXPECTED_LAYERED
    assert {f for floors, _p in R.LAYERED.values() for f in floors} == FLOOR_CONSUMERS
    from fuzzlab.core import redaction_floor as F
    for floors, _param in R.LAYERED.values():
        assert all(callable(getattr(F, f, None)) for f in floors), floors
    problems = []
    for (rel, func), (floors, param) in sorted(R.LAYERED.items()):
        source = (ROOT / rel).read_text(encoding="utf-8")
        problems += [f"{rel}: {p}" for p in layering_problems(source, func, floors, param)]
    assert problems == []


def test_the_layering_check_flags_a_consumer_that_skips_its_floor():
    """Guard 2 on synthetic offenders, each a way a consumer can keep what the pushed
    tree removed: no floor (144d234's `safe_ref`: the walk, then the record rule -- R1),
    the walk first, the floor given a changed input, the raw input read after the floor,
    a call before the floor; and the accepted shapes pass."""
    head = "from fuzzlab.core import redaction_floor as _floor\n"
    offenders = {
        "no floor": "def safe_ref(url):\n    text = redact_for_record('', "
                    "redact_url_identifiers(url))\n    return _blank(text)\n",
        "walk first": "def redact_url(url):\n    out = _walk_url(url, identifiers=False)\n"
                      "    return _floor.redact_url(out)\n",
        "changed input": "def redact_url(url):\n    out = _floor.redact_url(url.strip())\n"
                         "    return _walk_url(out, identifiers=False)\n",
        "raw read after": "def redact_url(url):\n    out = _floor.redact_url(url)\n"
                          "    return _walk_url(url, identifiers=False)\n",
        "call before": "def redact_url(url):\n    out = _floor.redact_url(_walk_url(url))\n"
                       "    return out\n",
        "floor discarded": "def redact_url(url):\n    _floor.redact_url(url)\n"
                           "    return _walk_url(url, identifiers=False)\n",
    }
    for label, src in offenders.items():
        func = src.split("(", 1)[0][4:]
        assert layering_problems(head + src, func, ("redact_url", "safe_ref"), "url"), label
    good = {
        "assign": "def redact_url(url):\n    out = _floor.redact_url(url)\n"
                  "    return _walk_url(out, identifiers=False)\n",
        "choice": "def rui(url, *, placeholder=False):\n    \"\"\"Doc.\"\"\"\n"
                  "    out = _floor.redact_url(url) if placeholder else "
                  "_floor.redact_url_identifiers(url)\n    return _walk_url(out)\n",
        "verdict": "def clean(url):\n    if not _floor.page_url_is_clean(url):\n"
                   "        return False\n    return _walk_url(url) == url\n",
    }
    floors = ("redact_url", "redact_url_identifiers", "page_url_is_clean")
    assert layering_problems(head + good["assign"], "redact_url", floors, "url") == []
    assert layering_problems(head + good["choice"], "rui", floors, "url") == []
    assert layering_problems(head + good["verdict"], "clean", floors, None) == []


# --- guard 3: nothing runs the walk or the floor unregistered ----------------------------
def _dotted(rel: str) -> str:
    return rel[:-3].replace("/", ".")


def unregistered_calls(files: dict[str, str]) -> list[str]:
    """Every call, in ``files`` (``{path: source}``, the floor itself left out), of the
    walk -- `_UrlWalk`, a `WALK_HELPERS` step or a `WALK_PREDICATES` predicate, by name in
    its own module, imported from it, or through an alias of it -- from a function that
    no registry names (`LAYERED`, `WALK_HELPERS`, `WALK_PREDICATES`, `FLOORLESS`), and
    of the floor from a function that is not `LAYERED`; module-level calls of either."""
    walk_defs: dict[str, set[str]] = {}
    for rel, name in list(R.WALK_HELPERS) + list(R.WALK_PREDICATES):
        walk_defs.setdefault(rel, set()).add(name)
    walk_defs.setdefault("fuzzlab/core/redaction.py", set()).add("_UrlWalk")
    registered = (set(R.LAYERED) | set(R.WALK_HELPERS) | set(R.WALK_PREDICATES)
                  | set(R.FLOORLESS))
    by_dotted = {_dotted(rel): names for rel, names in walk_defs.items()}
    problems = []
    for rel, source in sorted(files.items()):
        if rel == FLOOR_REL:
            continue
        tree = ast.parse(source)
        walk_names = set(walk_defs.get(rel, ()))
        module_aliases: dict[str, set[str]] = {}
        floor_names, floor_aliases = set(), _floor_aliases(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module in by_dotted:
                    walk_names |= {a.asname or a.name for a in node.names
                                   if a.name in by_dotted[node.module]}
                if node.module == FLOOR_MODULE:
                    floor_names |= {a.asname or a.name for a in node.names}
                for a in node.names:
                    full = f"{node.module}.{a.name}"
                    if full in by_dotted:
                        module_aliases[a.asname or a.name] = by_dotted[full]
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in by_dotted and a.asname:
                        module_aliases[a.asname] = by_dotted[a.name]

        def kind(call: ast.Call) -> str | None:
            f = call.func
            if isinstance(f, ast.Name):
                if f.id in walk_names:
                    return "walk"
                if f.id in floor_names:
                    return "floor"
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                if f.value.id in floor_aliases:
                    return "floor"
                if f.attr in module_aliases.get(f.value.id, ()):
                    return "walk"
            return None

        def visit(node, owner):
            for child in ast.iter_child_nodes(node):
                here = owner
                if owner is None and isinstance(child, (ast.FunctionDef,
                                                        ast.AsyncFunctionDef)):
                    here = child.name
                elif owner is None and isinstance(child, ast.ClassDef):
                    visit(child, None)
                    continue
                if isinstance(child, ast.Call):
                    k = kind(child)
                    if k == "walk" and (rel, here) not in registered:
                        problems.append(f"{rel}:{child.lineno}: {here or '<module>'} runs "
                                        "the walk unregistered")
                    if k == "floor" and (rel, here) not in R.LAYERED:
                        problems.append(f"{rel}:{child.lineno}: {here or '<module>'} calls "
                                        "the floor and is not a LAYERED consumer")
                visit(child, here)
        visit(tree, None)
    return problems


def _package_sources() -> dict[str, str]:
    return {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((ROOT / "fuzzlab").rglob("*.py"))
            if "__pycache__" not in p.parts}


def test_no_function_runs_the_walk_or_the_floor_unregistered():
    """Guard 3 (whole package): the walk runs only inside a registered function -- a
    `LAYERED` consumer after its floor, a walk step only those call, or a predicate --
    and the floor only inside a `LAYERED` consumer; every registry entry is defined."""
    sources = _package_sources()
    for registry in (R.LAYERED, R.WALK_HELPERS, R.WALK_PREDICATES, R.FLOORLESS):
        for rel, name in registry:
            tree = ast.parse(sources[rel])
            assert any(isinstance(n, ast.FunctionDef) and n.name == name
                       for n in tree.body), (rel, name)
    assert unregistered_calls(sources) == []


def test_the_registry_scan_flags_an_unregistered_walk_or_floor_call():
    """Guard 3 on synthetic offenders: a new consumer running the walk directly (by
    name, imported, or through a module alias), one calling a walk step, one calling the
    floor itself, and a module-level walk; a function of the same name in an unrelated
    module is not the walk."""
    offenders = {
        "fuzzlab/tools/a.py": "from fuzzlab.core.redaction import _walk_url\n"
                              "def leak(u):\n    return _walk_url(u, identifiers=True)\n",
        "fuzzlab/tools/b.py": "from fuzzlab.core import redaction as R\n"
                              "def leak(u):\n    return R._UrlWalk(True).value(u, 1, True)\n",
        "fuzzlab/tools/c.py": "from fuzzlab.core.redaction import _walk_record\n"
                              "def leak(u):\n    return _walk_record('', u)\n",
        "fuzzlab/tools/d.py": "from fuzzlab.core import redaction_floor as _floor\n"
                              "def leak(u):\n    return _floor.redact_url(u)\n",
        "fuzzlab/tools/e.py": "from fuzzlab.proxy.redact import _walk\nX = _walk(b'')\n",
    }
    found = unregistered_calls(offenders)
    assert [p.split(":", 1)[0] for p in found] == sorted(offenders), found
    unrelated = {"fuzzlab/tools/f.py": "def _walk(t):\n    return t\n"
                                       "def use(t):\n    return _walk(t)\n"}
    assert unregistered_calls(unrelated) == []
