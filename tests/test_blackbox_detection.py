"""The black-box rule (PA-0660, BUG-0660): detection code names no lab.

All detection logic must work against a black-box target: no rule, strategy or
heuristic may depend on a name, path, parameter name or value taken from a lab or
its source. Lab knowledge belongs only in fixtures and answer keys.

The guard builds the lab-identifier set from the answer keys themselves -- every
parameter name and path segment of every ``lab/ground-truth*/`` key
(``injection-points.json``, ``labels.json``), every route segment and parameter of
every ``lab/manifests/*.yaml`` labgen manifest, every key's target id, every key's
and every external lab's directory name, and the labs' own product names -- then
subtracts a public common-web vocabulary (SecLists' Burp parameter names and
``common.txt``, ``tests/data/common_web_vocabulary/``) and a small table of words
justified by an independent source (``CITED``). What remains is vocabulary only a
lab supplied. The guard fails if any of it appears, as a whole word, in a rules-data
file or in a non-docstring string literal of a detection module.

A new lab's answer key enlarges the set automatically.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VOCAB_DIR = ROOT / "tests" / "data" / "common_web_vocabulary"

#: Where detection decides what to probe or what counts as a finding (BBOX scope):
#: the audit rules and their engine, the oracle, session detection and login
#: discovery, the run-mode category plans, and the crawler/probe heuristics.
DETECTION_GLOBS = (
    "fuzzlab/audit/*.py",
    "fuzzlab/audit/rules_data/*.json",
    "fuzzlab/oracle/*.py",
    "fuzzlab/session/detect.py",
    "fuzzlab/session/browserlogin.py",
    "fuzzlab/session/manager.py",
    "fuzzlab/core/runmode.py",
    "fuzzlab/core/urls.py",
    "fuzzlab/tools/apiop.py",
    "fuzzlab/tools/blind_sqli_fuzzer.py",
    "fuzzlab/tools/composed.py",
    "fuzzlab/tools/fetcher.py",
    "fuzzlab/tools/formnav.py",
    "fuzzlab/tools/observe.py",
    "fuzzlab/tools/probesender.py",
    "fuzzlab/tools/spa.py",
    "fuzzlab/tools/spider.py",
)

#: The labs' own product names, which no answer key spells as a token.
LAB_PRODUCT_NAMES = frozenset({
    "bwapp", "juice-shop", "juiceshop", "mutillidae", "nodegoat", "dvga",
    "vulnerableapp", "secdevlabs", "puppy-fort-factory", "puppyfort", "labgen",
    "webgoat", "dvwa",
})

#: Lab-key words that detection code may use, each with its independent source
#: (never a lab). A word here is not lab-specific: a public spec or corpus shows a
#: real target uses it.
CITED: dict[str, str] = {
    "user-agent": "RFC 9110 §10.1.5 (User-Agent request header)",
    "true-client-ip": "Akamai / Cloudflare client-IP header (Cloudflare docs: True-Client-IP)",
    "__proto__": "ECMA-262 Annex B §B.2.2.1 Object.prototype.__proto__; PortSwigger "
                 "Web Security Academy, 'Prototype pollution'",
    "webhook": "OWASP SSRF Prevention Cheat Sheet ('webhooks' as an SSRF entry point); "
               "PortSwigger Web Security Academy, 'SSRF'",
    "webhooks": "as 'webhook'",
    # CC-LAB-0432: vulnerability-class names (the labels schema's own vuln_class
    # spellings) that a lab also uses as path segments
    "sqli": "PortSwigger Web Security Academy, 'SQL injection (SQLi)'; OWASP Top 10 "
            "2021 A03 Injection ('SQLi')",
    "open_redirect": "CWE-601 'URL Redirection to Untrusted Site (Open Redirect)'; "
                     "PayloadsAllTheThings 'Open Redirect'",
    "expr": "OWASP WSTG-INPV-09 (XPath injection) / Spring Expression Language docs "
            "('expr' as an expression parameter); MDN XPathEvaluator",
    "cell": "HTML Living Standard autocomplete: 'tel' family -- 'cell' is the common "
            "English label of a mobile phone field (phone-name hints, not a lab path)",
    "return_to": "PayloadsAllTheThings 'Open Redirect' README, common injection "
                 "parameters ('?return_to=', '?returnTo=')",
    "account_id": "OWASP API Security Top 10 2023, API1 (BOLA) example "
                  "'/shops/{shopName}/revenue_data.json' and 'account id' object IDs; "
                  "AWS / Stripe public APIs ('account_id')",
    "order_id": "OWASP API Security Top 10 2023, API1 (BOLA): object IDs such as order "
                "ids; Shopify Admin REST API ('order_id')",
    "product_id": "OWASP API Security Top 10 2023, API1 (BOLA); Shopify Admin REST "
                  "API ('product_id')",
    "user_id": "WordPress core database schema: wp_usermeta.user_id (and the user_id "
               "argument of get_user_meta / update_user_meta); OWASP API Security Top 10 "
               "2023, API1 (BOLA) and API3 (object property level authorization): user ids "
               "as object / property identifiers. Added at the HOLDOUT merge: a held-out "
               "key named it; the detection use (fetcher.PRIVILEGED_FIELDS) predates it",
    "graphql": "GraphQL over HTTP specification (graphql/graphql-over-http, 'URL': "
               "the conventional endpoint path is /graphql) and graphql.org 'Serving over "
               "HTTP' (\"respond at a single endpoint, typically /graphql\")",
}

_TOKEN_SPLIT = re.compile(r"[/{}:.<>?#]+")


def _segments(url: str) -> list[str]:
    url = url.split("?", 1)[0]
    return [s for s in _TOKEN_SPLIT.split(url) if s]


def _add(out: dict[str, set[str]], token, source: str) -> None:
    if not isinstance(token, str):
        return
    t = token.strip().lower()
    if len(t) < 3 or t.isdigit():
        return
    out.setdefault(t, set()).add(source)


def lab_tokens(root: Path = ROOT) -> dict[str, set[str]]:
    """Every identifier a lab's answer key or manifest names, with where it came from."""
    out: dict[str, set[str]] = {}
    keys = sorted(root.glob("lab/ground-truth*/injection-points.json")) + sorted(
        root.glob("lab/ground-truth*/labels.json"))
    for f in keys:
        src = str(f.relative_to(root))
        data = json.loads(f.read_text(encoding="utf-8"))
        _add(out, data.get("target"), src)
        if f.parent.name != "ground-truth":
            _add(out, f.parent.name.removeprefix("ground-truth-"), src)
        for p in data.get("points", []) + data.get("cases", []):
            _add(out, p.get("param"), src)
            for seg in _segments(str(p.get("url", ""))):
                _add(out, seg, src)
    for f in sorted(root.glob("lab/manifests/*.yaml")):
        src = str(f.relative_to(root))
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for cell in data.get("cells", []) or []:
            route = cell.get("route") or {}
            for seg in _segments(str(route.get("path", ""))):
                _add(out, seg, src)
            param = cell.get("param")
            _add(out, param.get("name") if isinstance(param, dict) else param, src)
    ext = root / "lab" / "external"
    if ext.is_dir():
        for d in sorted(ext.iterdir()):
            if d.is_dir():
                _add(out, d.name, f"lab/external/{d.name}")
    for name in LAB_PRODUCT_NAMES:
        _add(out, name, "LAB_PRODUCT_NAMES")
    holdout = root / "lab" / "HOLDOUT.md"
    if holdout.is_file():
        # held-out labs' product names, read from their list (SP-140): this file may not
        # name them (lab/HOLDOUT.md rule 4)
        from fuzzlab.lab_fixtures.heldout import parse_holdout_table
        for lab in parse_holdout_table(holdout.read_text(encoding="utf-8")):
            for name in lab.names:
                _add(out, name, "lab/HOLDOUT.md")
    return out


def test_the_held_out_labs_names_are_lab_identifiers():
    """Every name lab/HOLDOUT.md lists is in the lab-only vocabulary, so detection code
    can never contain one (CC-LAB-0428)."""
    from fuzzlab.lab_fixtures.heldout import held_out_labs
    tokens = lab_tokens()
    for lab in held_out_labs():
        assert set(lab.names) <= set(tokens), lab.name


def common_vocabulary(vocab_dir: Path = VOCAB_DIR) -> set[str]:
    words: set[str] = set()
    for f in sorted(vocab_dir.glob("*.txt")):
        words |= {w.strip().lower() for w in f.read_text(encoding="utf-8").splitlines() if w.strip()}
    return words


def lab_unique(root: Path = ROOT) -> dict[str, set[str]]:
    vocab = common_vocabulary()
    return {t: s for t, s in lab_tokens(root).items()
            if t not in vocab and t not in CITED}


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
        # A bare string statement (an attribute docstring such as `#:`'s sibling) is
        # documentation, not data.
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            ids.add(id(node.value))
        # A command-line option's help text is documentation too.
        if isinstance(node, ast.keyword) and node.arg in ("help", "description", "epilog"):
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Constant):
                    ids.add(id(sub))
    return ids


def _strings(path: Path):
    """(line, text) of every string a detection file can act on."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        for i, line in enumerate(text.splitlines(), 1):
            yield i, line
        return
    tree = ast.parse(text, filename=str(path))
    docs = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            yield node.lineno, node.value


def _pattern(token: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(token) + r"(?![A-Za-z0-9_\-])", re.I)


def offenders(files, tokens: dict[str, set[str]], root: Path = ROOT) -> list[str]:
    pats = {t: _pattern(t) for t in tokens}
    out = []
    for f in files:
        rel = f.relative_to(root) if f.is_relative_to(root) else f
        for line, s in _strings(f):
            for t, p in pats.items():
                if p.search(s):
                    srcs = ", ".join(sorted(tokens[t])[:3])
                    out.append(f"{rel}:{line}: lab identifier {t!r} (from {srcs})")
    return out


def detection_files(root: Path = ROOT) -> list[Path]:
    files: list[Path] = []
    for g in DETECTION_GLOBS:
        files.extend(sorted(root.glob(g)))
    return files


def test_detection_code_names_no_lab_identifier():
    files = detection_files()
    assert len(files) >= 20, files
    found = offenders(files, lab_unique())
    assert not found, (
        "detection code names an identifier only a lab supplied (PA-0660). Remove or "
        "generalise it; or, if an independent source (RFC, published schema, OWASP / "
        "PortSwigger / vendor docs, a second target) shows it, add it to CITED with "
        "that citation:\n" + "\n".join(found))


def test_the_lab_identifier_set_reads_every_answer_key_and_manifest():
    tokens = lab_tokens()
    sources = {s for srcs in tokens.values() for s in srcs}
    keys = list(ROOT.glob("lab/ground-truth*/injection-points.json"))
    manifests = list(ROOT.glob("lab/manifests/*.yaml"))
    assert len(keys) >= 20 and manifests
    for k in keys:
        assert str(k.relative_to(ROOT)) in sources, k
    uniq = lab_unique()
    # Known lab-only names stay in the set; common web words never do.
    for lab_word in ("xss_stored_1", "huddlehub", "juice-shop"):
        assert lab_word in uniq, lab_word
    for common in ("id", "q", "search", "url", "redirect", "username", "password"):
        assert common not in uniq, common


def test_every_cited_word_names_an_independent_source():
    for word, source in CITED.items():
        assert source.strip(), word
        low = source.lower()
        for lab in LAB_PRODUCT_NAMES | {"lab/", "ground-truth", "twitch", "netflix"}:
            assert lab not in low, (word, source)


@pytest.fixture
def synthetic_tree(tmp_path):
    (tmp_path / "lab" / "ground-truth-acme").mkdir(parents=True)
    (tmp_path / "lab" / "ground-truth-acme" / "injection-points.json").write_text(json.dumps({
        "version": 1, "target": "acme_shop_v1",
        "points": [{"url": "/api/zorblax/search", "method": "GET", "param": "frobnicate_id",
                    "location": "query", "rendering": "server"}],
    }))
    (tmp_path / "lab" / "manifests").mkdir()
    (tmp_path / "lab" / "manifests" / "m.yaml").write_text(
        "cells:\n  - cell_id: X\n    route: {method: GET, path: /quuxify/run}\n    param: wibble_token\n")
    return tmp_path


def test_the_guard_catches_synthetic_offenders(synthetic_tree, tmp_path):
    root = synthetic_tree
    vocab = common_vocabulary()
    tokens = {t: s for t, s in lab_tokens(root).items() if t not in vocab and t not in CITED}
    for t in ("frobnicate_id", "zorblax", "quuxify", "wibble_token", "acme_shop_v1", "acme"):
        assert t in tokens, t
    assert "search" not in tokens and "api" not in tokens

    mod = root / "detector.py"
    mod.write_text(
        '"""Mentions zorblax in a docstring: documentation, never flagged."""\n'
        'NAMES = {"frobnicate_id", "id"}\n'
        'def f():\n'
        '    """quuxify in a docstring is fine."""\n'
        '    return r"^/quuxify/"\n'
        'OK = "zorblaxian"  # a longer word is not the token\n'
        'p.add_argument("--x", help="help text naming zorblax is documentation")\n'
    )
    rules = root / "rules.json"
    rules.write_text('{"rules": [{"name_regex": "url|wibble_token"}]}\n')
    found = offenders([mod, rules], tokens, root)
    joined = "\n".join(found)
    assert "detector.py:2: lab identifier 'frobnicate_id'" in joined
    assert "detector.py:5: lab identifier 'quuxify'" in joined
    assert "rules.json:1: lab identifier 'wibble_token'" in joined
    assert "zorblax'" not in joined and ":1: lab identifier 'zorblax'" not in joined
    assert len(found) == 3, found
