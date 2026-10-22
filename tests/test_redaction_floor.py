"""The redaction floor: every URL redaction consumer runs the pushed tree's redactor first
(BUG-0556 r6, the owner's design for audit gap 5; PA-0556 item 11; SP-17).

`fuzzlab/core/redaction_floor.py` holds 7393c90's own redaction code, verbatim, for every
consumer the batch changed; each consumer (`core.redaction.LAYERED`) runs its floor on
its input as received and the batch's walk on the floor's output only, so nothing the
pushed tree redacted can be kept again. Three guards hold the design:

1. **the floor is frozen**: each of its definitions -- from its first decorator's ``@``
   (r6 review, R1: a decorator was never hashed) to its end -- hashes to 7393c90's text
   (a SHA-256 taken from ``git show 7393c90:<file>`` when this guard was written,
   recorded below), after the recorded substitutions (a function-local import of a live
   module pointed at the floor, so the frozen code never calls a layered redactor), and
   the module holds exactly those definitions after its pinned docstring and imports;
2. **every consumer runs its floor first**: by AST, each `LAYERED` function is bound
   once in its module, by its undecorated ``def``, and never re-bound there (r6 review,
   R2: a module-level ``redact_url = _walk_names`` or a decorator replaced it unseen);
   a name the module binds to the floor is bound to nothing else; the function's first
   statement (after its docstring and imports) calls its floor on its own parameters as
   given and calls nothing else; and the function reads none of its positional text
   parameters (every one, R2: `stored_value`'s three; a keyword-only one is not read,
   see the limits) again, except as the argument of a call by a predicate's name
   (``isinstance``, `is_sensitive_name`, a `WALK_PREDICATES` one), which returns no text
   while that name is bound to the predicate;
3. **nothing uses the walk or the floor unregistered**: across ``fuzzlab/``, every use
   of the walk (`_UrlWalk`, a `WALK_HELPERS` step, a `WALK_PREDICATES` predicate) is made
   from a registered function, and every use of the floor from a `LAYERED` consumer. A
   use is any reference, not only a call (R2: ``map(_walk_names, …)``,
   ``functools.partial(_walk_url, …)``, ``filter(looks_like_identifier, …)``), reached
   by a name the module imports or defines, an alias, or an unaliased dotted chain
   (``import fuzzlab.core.redaction`` then ``fuzzlab.core.redaction._walk_names``), a
   relative import, or ``getattr`` with a literal name; a module-level use, and an
   assignment to a `LAYERED`, walk or floor attribute from another module, are flagged.

**The stated limits** (completed at the merge: BUG-0556, "At the merge", R1 and R2; no
guard rule was added for them, the owner's decision). The guards are lexical: they read
the source text of ``fuzzlab/`` and of the floor's file, not what Python binds when it
runs, so "every use" and "every binding" above mean every one written in a form they
read. They do not see:

- a same-name rebinding in another scope: guard 3 keeps one name map per file
  (`_bound_paths`, the last binding found wins), so a function-local import or
  assignment of an alias's name (``def other(): import os.path as w``) hides the walk
  alias ``w`` another function uses -- 3615cfb's guard caught that one, this one does not;
- a rebinding of a trusted predicate's name: guard 2 exempts a call by the name
  (``isinstance``, `is_sensitive_name`, a `WALK_PREDICATES` one), not by what the name
  is bound to, so ``value_holds_secret = lambda v: v`` (local or module level, or a
  local ``isinstance``) followed by ``return value_holds_secret(raw_value)`` passes;
- a star import of the floor or the owner (``from fuzzlab.core.redaction_floor import
  *`` then ``redact_url(u)`` or ``filter(looks_like_identifier, …)``): guard 3 skips
  ``*``, and neither module defines ``__all__``;
- a keyword-only text parameter: `_text_params` reads positional parameters only, so
  ``redact_url(url, *, raw='')`` returning ``raw`` passes guard 2;
- literal-name reflection: ``R.__dict__['_walk_names']``,
  ``operator.attrgetter('_walk_names')(R)``, an assignment through ``R.__dict__``;
- a shadow package: guard 1 hashes the file ``fuzzlab/core/redaction_floor.py``, not the
  module Python imports, and a package ``fuzzlab/core/redaction_floor/`` takes
  precedence over that file (one re-exporting an edited copy passes all six tests);
- a name computed at run time: ``getattr`` / ``setattr`` with a computed name,
  ``globals()``, ``vars()``, ``sys.modules``, ``importlib`` / ``__import__`` of a
  computed or literal module name, ``exec`` and ``eval``.

None of these is checked here (nor anywhere else); review is the only control for them.

Each check is proven on synthetic offenders (PA-0034(2)): an edited floor (a decorator
added, removed or changed among them), a consumer that skips its floor, runs the walk
first, gives the floor a changed input, reads its raw input after it (144d234's
`core.trace.safe_ref`, R1), is decorated, re-bound or returns a text parameter it only
judged, and an unregistered use of each kind above.
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
    ("RawMessage", "fuzzlab/proxy/message.py",                 # with its @dataclass
     "0602e7781a3d8eb90d91b72239378208741a0cdbf1930cee331ae8d56a598baa"),
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
#: The floor's docstring and imports (every statement before its first definition): the
#: lane's own text, not 7393c90's (the floor module is new). Retaken at the merge, when
#: the docstring's claim that every caller withholds a value the floor rejects was
#: corrected (BUG-0556, "At the merge", R3(a)).
HEAD_SHA = "e73c8f97955e8fa3f4c05c1293a0f91977e37b56806e6f9bb5297aed45c6c4c2"
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
#: A consumer's positional parameters that hold no text (r6 review, R2): every other one is
#: a text parameter its `LAYERED` entry must name, so no entry checks fewer than all its
#: positional ones (`stored_value`'s named only ``value``, and returning ``raw_value``
#: passed); a keyword-only parameter is not read (a stated limit).
NOT_TEXT = {("fuzzlab/proxy/redact.py", "redact"): {"extra_headers"}}   # header names


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _defined(node) -> str | None:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign) and len(node.targets) == 1 \
            and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _offset(text: str, lineno: int, col: int) -> int:
    """The character offset of an AST position (``col`` counts UTF-8 bytes), lines split
    as `ast.get_source_segment` splits them."""
    start = 0
    for _ in range(lineno - 1):
        start = text.index("\n", start) + 1
    line = text[start:text.find("\n", start) if "\n" in text[start:] else len(text)]
    return start + len(line.encode("utf-8")[:col].decode("utf-8"))


def _segment(text: str, node) -> str:
    """A definition's text as guard 1 hashes it: from its first decorator's ``@`` to its
    end (r6 review, R1: `ast.get_source_segment` starts at ``def`` / ``class``, so an
    added, removed or edited decorator was never hashed -- ``@dataclass(frozen=True)``
    made ``@dataclass``, or ``@lambda f: (lambda url: url)`` above ``def redact_url``,
    passed while the floor stopped redacting)."""
    decorators = getattr(node, "decorator_list", None)
    if not decorators:
        return ast.get_source_segment(text, node)
    first = min(decorators, key=lambda d: (d.lineno, d.col_offset))
    start = text.rfind("@", 0, _offset(text, first.lineno, first.col_offset))
    return text[start:_offset(text, node.end_lineno, node.end_col_offset)]


# --- guard 1: the floor is the pushed tree's code, verbatim ------------------------------
def frozen_problems(text: str) -> list[str]:
    """How a floor module's ``text`` differs from the pinned 7393c90 code: ``[]`` when
    every definition, its decorators included (`_segment`), is 7393c90's (after `SUBS`),
    they are exactly `FROZEN`'s in order, and nothing but the pinned head precedes them
    or follows. **Limit:** it judges the file's text, not the module Python imports: a
    package ``fuzzlab/core/redaction_floor/`` shadowing the file is not seen."""
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
        seg = _segment(text, node)
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
    removed, an import pointed back at the live (layered) module, a docstring edit; and
    (r6 review, R1) a decorator changed (``RawMessage`` no longer frozen), removed, or
    added above a frozen function so that it stops redacting (``redact_url``,
    ``safe_ref``) -- each passed the check that hashed from ``def`` / ``class``."""
    text = (ROOT / FLOOR_REL).read_text(encoding="utf-8")
    identity = "@lambda f: (lambda url: url)\n"
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
        "decorator changed": text.replace("@dataclass(frozen=True)\nclass RawMessage",
                                          "@dataclass\nclass RawMessage", 1),
        "decorator removed": text.replace("@dataclass(frozen=True)\nclass RawMessage",
                                          "class RawMessage", 1),
        "decorator added (redact_url)": text.replace("\ndef redact_url(",
                                                     "\n" + identity + "def redact_url(", 1),
        "decorator added (safe_ref)": text.replace("\ndef safe_ref(",
                                                   "\n" + identity + "def safe_ref(", 1),
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


def _is_floor_import(node, name: str) -> bool:
    """Whether the import ``node`` binds ``name`` to the floor module."""
    if isinstance(node, ast.ImportFrom):
        return node.module == "fuzzlab.core" and any(
            a.name == "redaction_floor" and (a.asname or a.name) == name for a in node.names)
    return isinstance(node, ast.Import) and any(
        a.name == FLOOR_MODULE and a.asname == name for a in node.names)


def _import_binds(node, name: str) -> bool:
    """Whether the import ``node`` binds ``name`` (a star import may bind any name)."""
    if isinstance(node, ast.Import):
        return any((a.asname or a.name.split(".")[0]) == name for a in node.names)
    return any(a.name == "*" or (a.asname or a.name) == name for a in node.names)


def _module_scope(tree: ast.Module):
    """Every node evaluated in the module's own namespace: not inside a function, lambda
    or class body (a definition's decorators and defaults, a class's bases, are)."""
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            stack += list(getattr(node, "decorator_list", [])) + list(args.defaults) \
                + [d for d in args.kw_defaults if d is not None]
        elif isinstance(node, ast.ClassDef):
            stack += list(node.decorator_list) + list(node.bases) \
                + [k.value for k in node.keywords]
        else:
            stack += list(ast.iter_child_nodes(node))


def _module_bindings(tree: ast.Module, name: str) -> list[int]:
    """The line of every binding of ``name`` in the module's namespace: a definition, an
    assignment, augmented or annotated assignment, ``for`` / ``with`` / walrus / ``except``
    / ``match`` target, ``del``, an import (a star import too), and any function's
    ``global`` declaration of it."""
    lines = []
    for node in _module_scope(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            hit = node.name == name
        elif isinstance(node, ast.Name):
            hit = node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            hit = _import_binds(node, name)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            hit = node.name == name
        elif isinstance(node, ast.MatchMapping):
            hit = node.rest == name
        else:
            hit = False
        if hit:
            lines.append(node.lineno)
    lines += [n.lineno for n in ast.walk(tree)
              if isinstance(n, ast.Global) and name in n.names]
    return sorted(lines)


def _alias_rebindings(tree: ast.Module, aliases: set[str]) -> list[str]:
    """Each binding, anywhere in the module (any scope), of a name the module binds to
    the floor, to anything but the floor: then ``_floor.redact_url(url)`` would not be
    the floor."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            bad = [a for a in aliases if _import_binds(node, a) and not _is_floor_import(node, a)]
        elif isinstance(node, ast.Name):
            bad = [node.id] if node.id in aliases and not isinstance(node.ctx, ast.Load) else []
        elif isinstance(node, ast.arg):
            bad = [node.arg] if node.arg in aliases else []
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                               ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            bad = [node.name] if node.name in aliases else []
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bad = [n for n in node.names if n in aliases]
        else:
            bad = []
        out += [f"{a}: bound to something besides the floor (line {node.lineno})"
                for a in bad]
    return out


def _is_floor_call(node, aliases: set[str], floors) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id in aliases
            and node.func.attr in floors)


def _predicates() -> set[str]:
    """What a consumer may call on a text parameter after its floor: predicates, which
    return no text -- ``isinstance``, the name rule both trees share
    (`is_sensitive_name`, identical in 7393c90) and the walk's own `WALK_PREDICATES`."""
    return {"isinstance", "is_sensitive_name"} | {name for _rel, name in R.WALK_PREDICATES}


def layering_problems(source: str, func: str, floors, text_params) -> list[str]:
    """How the function ``func`` of ``source`` breaks the layering: ``[]`` when

    - ``func`` is bound once in the module, by its own ``def``, undecorated, and never
      re-bound (no later assignment, import, ``global`` or second ``def``: r6 review,
      R2), and every name the module binds to the floor is bound to nothing else;
    - its first statement (after its docstring and imports, which bind none of its
      parameters) calls one of ``floors`` (of the floor module) on the function's own
      leading parameters as received -- ``x = floor(...)``, ``x = floor_a(...) if flag
      else floor_b(...)``, or ``if not floor(...): return False`` -- and calls nothing
      else;
    - after that statement no parameter in ``text_params`` (a name, or every name in a
      tuple; ``None`` for a verdict) is read, except as a positional argument of a
      `_predicates` call, so the walk sees only the floor's output.

    **Limits** (lexical; the module docstring's list): a `_predicates` call is trusted by
    its name, not by what the name is bound to (a local or module-level rebinding of
    ``value_holds_secret``, ``is_sensitive_name`` or ``isinstance`` passes), and a
    keyword-only parameter is never a text parameter here (`_text_params`)."""
    tree = ast.parse(source)
    problems = []
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == func),
              None)
    if fn is None:
        return [f"{func}: not defined"]
    bindings = _module_bindings(tree, func)
    if bindings != [fn.lineno]:
        problems.append(f"{func}: bound more than once in its module (lines {bindings}): a "
                        "re-binding replaces the layered consumer")
    if fn.decorator_list:
        problems.append(f"{func}: decorated (line {fn.decorator_list[0].lineno}): a "
                        "decorator replaces the layered consumer")
    aliases = _floor_aliases(tree)
    if not aliases:
        return problems + [f"{func}: the module binds no floor"]
    problems += _alias_rebindings(tree, aliases)
    params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    while body and isinstance(body[0], (ast.Import, ast.ImportFrom)):
        problems += [f"{func}: an import before its floor binds its parameter {p}"
                     for p in params if _import_binds(body[0], p)]
        body = body[1:]
    if not body:
        return problems + [f"{func}: empty"]
    first, after = body[0], body[1:]
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
    texts = (text_params,) if isinstance(text_params, str) else tuple(text_params or ())
    problems += [f"{func}: has no parameter {p}" for p in texts if p not in params]
    allowed = _predicates()
    for stmt in after:
        parent = {c: n for n in ast.walk(stmt) for c in ast.iter_child_nodes(n)}
        for node in ast.walk(stmt):
            if not (isinstance(node, ast.Name) and node.id in texts):
                continue
            up = parent.get(node)
            if isinstance(up, ast.Call) and any(a is node for a in up.args) \
                    and isinstance(up.func, ast.Name) and up.func.id in allowed:
                continue                                    # a predicate: no text out
            problems.append(f"{func}: reads {node.id} after its floor (line {node.lineno}): "
                            "the walk or the result would see the raw input")
    return problems


def _text_params(rel: str, func: str, source: str) -> tuple[str, ...]:
    """A consumer's positional parameters that hold text: all but `NOT_TEXT`'s."""
    fn = next(n for n in ast.parse(source).body
              if isinstance(n, ast.FunctionDef) and n.name == func)
    skip = NOT_TEXT.get((rel, func), set())
    return tuple(a.arg for a in fn.args.posonlyargs + fn.args.args if a.arg not in skip)


def test_every_url_redaction_consumer_runs_its_floor_first():
    """Guard 2: each `LAYERED` consumer is bound once, undecorated, runs the pushed
    tree's redactor on its input as received, then the walk on the floor's output only;
    the registry holds every consumer the batch changed, names every floor consumer, and
    names every positional text parameter of each (r6 review, R2)."""
    assert set(R.LAYERED) == EXPECTED_LAYERED
    assert {f for floors, _p in R.LAYERED.values() for f in floors} == FLOOR_CONSUMERS
    from fuzzlab.core import redaction_floor as F
    for floors, _param in R.LAYERED.values():
        assert all(callable(getattr(F, f, None)) for f in floors), floors
    problems = []
    for (rel, func), (floors, params) in sorted(R.LAYERED.items()):
        source = (ROOT / rel).read_text(encoding="utf-8")
        if params is not None and tuple(params) != _text_params(rel, func, source):
            problems.append(f"{rel}: {func}: LAYERED names {params}, its text parameters "
                            f"are {_text_params(rel, func, source)}")
        problems += [f"{rel}: {p}" for p in layering_problems(source, func, floors, params)]
    assert problems == []


def test_the_layering_check_flags_a_consumer_that_skips_its_floor():
    """Guard 2 on synthetic offenders, each a way a consumer can keep what the pushed
    tree removed: no floor (144d234's `safe_ref`: the walk, then the record rule -- R1),
    the walk first, the floor given a changed input, the raw input read after the floor,
    a call before the floor; and (r6 review, R2) the consumer re-bound after its ``def``
    (``redact_spa_fragment = _walk_spa_fragment``, ``redact_url = _walk_names``, a second
    ``def``, an import, a ``global`` assignment), decorated, its floor alias re-bound, a
    text parameter it only judged returned (`stored_value` returning ``raw_value``), an
    import before the floor shadowing its parameter. Each re-binding, decorator and
    ``raw_value`` offender passed the check before the r6 review. The accepted shapes
    pass."""
    head = "from fuzzlab.core import redaction_floor as _floor\n"
    url_floors = ("redact_url", "safe_ref")
    good_url = ("def redact_url(url):\n    out = _floor.redact_url(url)\n"
                "    return _walk_names(out)\n")
    good_sv = ("def stored_value(name, raw_value, value):\n"
               "    kept = _floor.redact_sibling(name, raw_value, value)\n"
               "    if (isinstance(name, str) and is_sensitive_name(name)) "
               "or value_holds_secret(raw_value):\n        return ''\n    return kept\n")
    offenders = {
        "no floor": (head + "def safe_ref(url):\n    text = redact_for_record('', "
                     "redact_url_identifiers(url))\n    return _blank(text)\n", "url"),
        "walk first": (head + "def redact_url(url):\n    out = _walk_url(url, "
                       "identifiers=False)\n    return _floor.redact_url(out)\n", "url"),
        "changed input": (head + "def redact_url(url):\n    out = _floor.redact_url("
                          "url.strip())\n    return _walk_url(out, identifiers=False)\n",
                          "url"),
        "raw read after": (head + "def redact_url(url):\n    out = _floor.redact_url(url)\n"
                           "    return _walk_url(url, identifiers=False)\n", "url"),
        "call before": (head + "def redact_url(url):\n    out = _floor.redact_url("
                        "_walk_url(url))\n    return out\n", "url"),
        "floor discarded": (head + "def redact_url(url):\n    _floor.redact_url(url)\n"
                            "    return _walk_url(url, identifiers=False)\n", "url"),
        "re-bound to the walk": (head + good_url + "redact_url = _walk_names\n", "url"),
        "re-bound in a block": (head + good_url + "if True:\n    redact_url = _walk_names\n",
                                "url"),
        "defined twice": (head + good_url + "def redact_url(url):\n    return url\n", "url"),
        "re-bound by an import": (head + good_url
                                  + "from fuzzlab.core.redaction import _walk_names as "
                                    "redact_url\n", "url"),
        "re-bound by a global": (head + good_url + "def _swap():\n    global redact_url\n"
                                 "    redact_url = _walk_names\n", "url"),
        "decorated": (head + "@lambda f: (lambda url: _walk_names(url))\n" + good_url,
                      "url"),
        "floor alias re-bound": (head + good_url + "_floor = _identity_module\n", "url"),
        "floor alias as a parameter": (head + "def redact_url(url, _floor=None):\n"
                                       "    out = _floor.redact_url(url)\n"
                                       "    return _walk_names(out)\n", "url"),
        "import shadows the parameter": (head + "def redact_url(url):\n"
                                         "    from os import sep as url\n"
                                         "    out = _floor.redact_url(url)\n"
                                         "    return _walk_names(out)\n", "url"),
        "a judged parameter returned": (head + good_sv.replace(
            "    return kept\n", "    return raw_value if kept else kept\n"),
            ("name", "raw_value", "value")),
        "a judged parameter walked": (head + good_sv.replace(
            "    return kept\n", "    return _walk_names(raw_value)\n"),
            ("name", "raw_value", "value")),
    }
    floors = url_floors + ("redact_sibling",)
    for label, (src, params) in offenders.items():
        func = src.split("\ndef ", 1)[1].split("(", 1)[0]
        assert layering_problems(src, func, floors, params), label
    good = {
        "assign": (good_url, "redact_url", ("url",)),
        "choice": (("def rui(url, *, placeholder=False):\n    \"\"\"Doc.\"\"\"\n"
                    "    out = _floor.redact_url(url) if placeholder else "
                    "_floor.redact_url_identifiers(url)\n    return _walk_url(out)\n"),
                   "rui", ("url",)),
        "verdict": (("def clean(url):\n    if not _floor.page_url_is_clean(url):\n"
                     "        return False\n    return _walk_url(url) == url\n"), "clean",
                    None),
        "predicates": (good_sv, "stored_value", ("name", "raw_value", "value")),
    }
    floors = ("redact_url", "redact_url_identifiers", "page_url_is_clean", "redact_sibling")
    for label, (src, func, params) in good.items():
        assert layering_problems(head + src, func, floors, params) == [], label


# --- guard 3: nothing uses the walk or the floor unregistered ----------------------------
def _dotted(rel: str) -> str:
    return rel[:-3].replace("/", ".")


def _bound_paths(rel: str, tree: ast.Module) -> dict[str, str]:
    """Each name the module ``rel`` binds to a dotted path: its module-level definitions
    (``fuzzlab.core.redaction._walk_names`` in that module), and every import anywhere in
    the file (``import a.b`` binds ``a``; ``import a.b as x`` and ``from a import b as
    x`` bind ``x``; a relative import resolved against the module's package)."""
    own = _dotted(rel)
    package = own.rsplit(".", 1)[0]          # a module's package; an __init__'s own one
    out = {n.name: f"{own}.{n.name}" for n in tree.body
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    out[top] = top
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                parts = parts[:len(parts) - (node.level - 1)]
                base = ".".join(parts + ([node.module] if node.module else []))
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{base}.{a.name}"
    return out


def _resolve(node, names: dict[str, str]) -> str | None:
    """The dotted path a ``Name`` or attribute chain refers to, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and node.id in names:
        return ".".join([names[node.id]] + parts[::-1])
    return None


def unregistered_uses(files: dict[str, str]) -> list[str]:
    """Every use, in ``files`` (``{path: source}``, the floor itself left out), of the
    walk -- `_UrlWalk`, a `WALK_HELPERS` step or a `WALK_PREDICATES` predicate -- from a
    function or class that no registry names (`LAYERED`, `WALK_HELPERS`,
    `WALK_PREDICATES`, `FLOORLESS`, the walk's own class), and of the floor (the module or
    anything in it) from one that is not `LAYERED`; a module-level use of either (a
    definition's decorators and defaults are module level); and an assignment, from any
    module, to a `LAYERED` consumer, a walk step or anything in the floor.

    A use is any reference, not only a call (r6 review, R2): ``map(_walk_names, …)``,
    ``functools.partial(_walk_url, …)``, ``filter(looks_like_identifier, …)`` with the
    floor's predicate, a name imported, aliased, defined in the walk's own module, an
    unaliased dotted chain (``fuzzlab.core.redaction_floor.looks_like_identifier``), a
    relative import, and ``getattr`` / ``setattr`` with a literal name on such a module.
    **Limits** (lexical; the module docstring's list): a name computed at run time
    (``getattr(R, name)``, ``globals()``, ``vars()``, ``sys.modules``, ``importlib``,
    ``exec``), a same-name rebinding in another scope (one name map per file: a
    function-local ``import os.path as w`` hides a walk alias ``w`` used elsewhere), a
    star import (skipped), and literal-name reflection (``R.__dict__[...]``,
    ``operator.attrgetter``) are not visible to this scan."""
    walk_defs = {f"{_dotted(rel)}.{name}"
                 for rel, name in list(R.WALK_HELPERS) + list(R.WALK_PREDICATES)}
    walk_defs.add("fuzzlab.core.redaction._UrlWalk")
    layered = {f"{_dotted(rel)}.{name}" for rel, name in R.LAYERED}
    registered = (set(R.LAYERED) | set(R.WALK_HELPERS) | set(R.WALK_PREDICATES)
                  | set(R.FLOORLESS) | {("fuzzlab/core/redaction.py", "_UrlWalk")})

    def kind(dotted: str | None) -> str | None:
        if dotted is None:
            return None
        if dotted == FLOOR_MODULE or dotted.startswith(FLOOR_MODULE + "."):
            return "floor"
        if any(dotted == w or dotted.startswith(w + ".") for w in walk_defs):
            return "walk"
        return None

    problems = []
    for rel, source in sorted(files.items()):
        if rel == FLOOR_REL:
            continue
        tree = ast.parse(source)
        names = _bound_paths(rel, tree)

        def report(node, k, owner):
            if k == "walk" and (rel, owner) not in registered:
                problems.append(f"{rel}:{node.lineno}: {owner or '<module>'} uses the walk "
                                "unregistered")
            if k == "floor" and (rel, owner) not in R.LAYERED:
                problems.append(f"{rel}:{node.lineno}: {owner or '<module>'} uses the floor "
                                "and is not a LAYERED consumer")

        def stored(node, target: str | None):
            if target is not None and (target in layered or kind(target)):
                problems.append(f"{rel}:{node.lineno}: assigns {target} from outside")

        def visit(node, owner):
            if isinstance(node, (ast.Name, ast.Attribute)):
                dotted = _resolve(node, names)
                if isinstance(node.ctx, ast.Load):
                    k = kind(dotted)
                    if k:
                        report(node, k, owner)
                        return                          # its chain is this one use
                elif isinstance(node, ast.Attribute):
                    stored(node, dotted)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in ("getattr", "setattr", "delattr") \
                    and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                base = _resolve(node.args[0], names)
                if base is not None:
                    target = f"{base}.{node.args[1].value}"
                    if node.func.id == "getattr":
                        k = kind(target)
                        if k:
                            report(node, k, owner)
                    else:
                        stored(node, target)
            for child in ast.iter_child_nodes(node):
                visit(child, owner)

        for top in tree.body:
            if owner_of := (top.name if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                         ast.ClassDef)) else None):
                outer = list(top.decorator_list)
                if isinstance(top, ast.ClassDef):
                    outer += list(top.bases) + [k.value for k in top.keywords]
                    inner = list(top.body)
                else:
                    a = top.args
                    outer += list(a.defaults) + [d for d in a.kw_defaults if d is not None]
                    inner = list(top.body)
                for node in outer:
                    visit(node, None)
                for node in inner:
                    visit(node, owner_of)
            else:
                visit(top, None)
    return problems


def _package_sources() -> dict[str, str]:
    return {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted((ROOT / "fuzzlab").rglob("*.py"))
            if "__pycache__" not in p.parts}


def test_no_function_runs_the_walk_or_the_floor_unregistered():
    """Guard 3 (whole package): the walk is used only inside a registered function -- a
    `LAYERED` consumer after its floor, a walk step only those use, or a predicate -- and
    the floor only inside a `LAYERED` consumer; every registry entry is defined."""
    sources = _package_sources()
    for registry in (R.LAYERED, R.WALK_HELPERS, R.WALK_PREDICATES, R.FLOORLESS):
        for rel, name in registry:
            tree = ast.parse(sources[rel])
            assert any(isinstance(n, ast.FunctionDef) and n.name == name
                       for n in tree.body), (rel, name)
    assert unregistered_uses(sources) == []


def test_the_registry_scan_flags_an_unregistered_walk_or_floor_call():
    """Guard 3 on synthetic offenders: a new consumer running the walk directly (by
    name, imported, or through a module alias), one calling a walk step, one calling the
    floor itself, and a module-level walk; and (r6 review, R2) each use the scan of calls
    missed -- ``map(_walk_names, …)``, ``functools.partial(_walk_url, …)``, an unaliased
    ``import fuzzlab.core.redaction`` then ``fuzzlab.core.redaction._walk_names(u)``, an
    unaliased import of the floor, ``filter(looks_like_identifier, …)`` from the floor, a
    relative import, ``getattr`` with a literal name, the floor module passed on, a walk
    in a decorator or a default, an assignment to a `LAYERED` consumer from another
    module. A function of the same name in an unrelated module is not the walk."""
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
        # r6 review, R2: each passed the scan of calls
        "fuzzlab/tools/m.py": "from fuzzlab.core.redaction import _walk_names\n"
                              "def leak(urls):\n    return list(map(_walk_names, urls))\n",
        "fuzzlab/tools/n.py": "import functools\nfrom fuzzlab.core.redaction import _walk_url\n"
                              "def leak(u):\n    return functools.partial(_walk_url, "
                              "identifiers=True)(u)\n",
        "fuzzlab/tools/o.py": "import fuzzlab.core.redaction\n"
                              "def leak(u):\n    return fuzzlab.core.redaction._walk_names(u)\n",
        "fuzzlab/tools/p.py": "import fuzzlab.core.redaction_floor\n"
                              "def leak(v):\n    return fuzzlab.core.redaction_floor."
                              "looks_like_identifier(v)\n",
        "fuzzlab/tools/q.py": "from fuzzlab.core.redaction_floor import looks_like_identifier\n"
                              "def leak(vs):\n    return list(filter(looks_like_identifier, "
                              "vs))\n",
        "fuzzlab/core/r.py": "from .redaction import _walk_names\n"
                             "def leak(u):\n    return _walk_names(u)\n",
        "fuzzlab/tools/s.py": "from fuzzlab.core import redaction\n"
                              "def leak(u):\n    return getattr(redaction, '_walk_names')(u)\n",
        "fuzzlab/tools/t.py": "from fuzzlab.core import redaction_floor\n"
                              "def leak():\n    return redaction_floor\n",
        "fuzzlab/tools/u.py": "from fuzzlab.core.redaction import _walk_names\n"
                              "@lambda f: _walk_names\ndef leak(u):\n    return u\n",
        "fuzzlab/tools/v.py": "from fuzzlab.core.redaction import _walk_names\n"
                              "def leak(u, w=_walk_names):\n    return w(u)\n",
        "fuzzlab/tools/w.py": "from fuzzlab.core import redaction as R\n"
                              "def swap():\n    R.redact_url = R.redact_query\n",
        "fuzzlab/tools/x.py": "import fuzzlab.core.redaction\n"
                              "def swap(f):\n    setattr(fuzzlab.core.redaction, "
                              "'stored_value', f)\n",
    }
    found = unregistered_uses(offenders)
    assert sorted({p.split(":", 1)[0] for p in found}) == sorted(offenders), found
    unrelated = {"fuzzlab/tools/f.py": "def _walk(t):\n    return t\n"
                                       "def use(t):\n    return _walk(t)\n",
                 "fuzzlab/tools/g.py": "from fuzzlab.core import redaction as R\n"
                                       "def use(u):\n    return R.redact_url(u)\n"}
    assert unregistered_uses(unrelated) == []
