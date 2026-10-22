"""FR-CORE-30: one shared "this value looks like a secret identifier" predicate.

Forms phase 2 lane A redacts identifier-like values in link sets and header-point URLs;
lane B treats equal identifier-like cookie values as "not distinct". Both import
``core.redaction.looks_like_identifier`` (PA-0003): this table pins it once.
"""

import ast
import base64
from pathlib import Path

import pytest

from fuzzlab.core import redaction
from fuzzlab.core.redaction import looks_like_identifier

ROOT = Path(__file__).resolve().parents[1]

IDENTIFIERS = [
    "0123456789abcdef0123456789abcdef",                     # 32-hex id
    "550e8400-e29b-41d4-a716-446655440000",                 # UUID
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",            # JWT (segment)
    base64.b64encode(bytes(range(7, 39))).decode(),         # base64 secret
    base64.urlsafe_b64encode(bytes(range(200, 232))).decode().rstrip("="),
    "kT9/aB3xQ7zLm2Pq/Rs8vW1yN4cE6gH0jK5uF2dS9oI",          # base64 with two '/'
    "8f3a9c1e7b2d",                                         # short random hex (R2)
    "Bearer eyJhbGciOiJIUzI1NiJ9",                          # split on whitespace
    "dGhpcyBpcyBh/c2VjcmV0",                                # standard base64 with '/'
    "Zm9vYmFyYmF6cXV4/x+y=",
    "kTQaBxQzLmPqRsvWyNcEgHjKuFdSoI",                       # mixed case, no digit (R1)
    "user_123456789012",                                    # a digit run over four
    "Abcdefghijklmnop1234567",
]
NOT_IDENTIFIERS = [
    "", "0", "en", "lang", "bee", "bug", "fuzzlab", "password", "Submit",
    "security_level", "www.nsa.gov", "sqli_1.php", "lang_en.php", "portal.php",
    "img2024", "1a2b3c4d", "Hello World!", "Iron Man", "The Incredible Hulk",
    "https://example.com/assets/img2024/banner_large.png",
    "/app/v1/users/12345/profile", "/bWAPP/portal.php", "images/2024/10/photo_1.jpg",
    "dir/sub_dir_2/file.txt", "text/html", "application/x-www-form-urlencoded",
    "The+Fellowship+of+the+Ring", "hello+world+2024",       # raw query: '+' is a space
    "fuzzlab@example.invalid", "https://fuzzlab.invalid/",  # the importer's fillers
    "abcdefghijklmnopqrstuvwxyz",                           # one case, no digit
    # word-shaped names (reviewer B): R1/R2 alone would call these identifiers
    "directory_traversal_1.php", "insecure_direct_object_ref_1.php",
    "ba_insecure_login_1", "owasp_top10_2017_a1", "ProductDetailsPage",
    "xss_ajax_2-1.php", "Welcome123", "2026-10-14T10:15:00Z", "2026-10-14",
    ".", ":" * 10_000, "\uff10\uff11\uff12\uff13\uff14\uff15\uff16\uff17" * 3,  # fullwidth
    "u=bob&t=8f3a9c1e7b2d4a6f",     # a whole query is not a value: callers test values
]


@pytest.mark.parametrize("value", IDENTIFIERS)
def test_identifier_like_values(value):
    assert looks_like_identifier(value) is True


@pytest.mark.parametrize("value", NOT_IDENTIFIERS)
def test_ordinary_values_are_not_identifiers(value):
    assert looks_like_identifier(value) is False


def test_the_importer_fillers_are_not_identifiers():
    from fuzzlab.tools.store_adapter import _FILLERS
    for value in _FILLERS.values():
        assert looks_like_identifier(value) is False, value


@pytest.mark.parametrize("value", [None, 123, 1.5, b"0123456789abcdef0123", [], {},
                                   object(), "\x00" * 64, "a" * 100_000])
def test_total_never_raises(value):
    assert looks_like_identifier(value) is False


def test_linear_time_on_long_values():
    """PA-0095: a 1 MB value is classified quickly, whatever its shape."""
    import time
    for value in ("a" * 1_000_000, "a_" * 500_000, "aA1" * 333_333, ".:" * 500_000,
                  "0123456789abcdef" * 65_536,
                  # a long word then a non-matching character: catastrophic
                  # backtracking in a nested word pattern (reviewer B)
                  "a" * 1_000_000 + "=", "Ab" * 500_000 + "=", "aB" * 500_000 + "+",
                  "a" * 40 + "=", "a" * 60 + "+", "a" * 100_000 + "+",
                  "Ab" * 50_000 + "=", "a_" * 50_000 + "+"):
        start = time.perf_counter()
        looks_like_identifier(value)
        assert time.perf_counter() - start < 2.0, value[:20]


def test_an_internal_error_is_false_not_raised(monkeypatch):
    """PA-0096: whatever goes wrong inside, the predicate answers False."""
    def boom(piece):
        raise ValueError("internal")
    monkeypatch.setattr(redaction, "_identifier_piece", boom)
    assert looks_like_identifier("0123456789abcdef0123456789abcdef") is False


def test_boundaries():
    assert looks_like_identifier("abcdef0123456789") is True       # 16: R1 (digit run over 4)
    assert looks_like_identifier("kTQaBxQzLmPqRsvW") is True       # 16: R1 only (no digit)
    assert looks_like_identifier("kTQaBxQzLmPqRsv") is False       # 15: R2 needs a digit
    assert looks_like_identifier("8f3a9c1e7b") is True             # R2: 33.2 bits >= 32
    assert looks_like_identifier("8f3a9c1e7") is False             # R2: 28.5 bits
    assert looks_like_identifier("abcdef012345678") is True        # 15: R2, 15 distinct
    assert looks_like_identifier("aaaaaaa1") is False              # R2: low entropy
    assert looks_like_identifier("aaaaaaaaaaaaaaa1") is False      # word-shaped
    assert looks_like_identifier("abcdefghijklmnop") is False      # R1: no digit, one case
    assert looks_like_identifier("abcdefghijklmnop1234") is False  # word + 4 digits
    assert looks_like_identifier("abcdefghijklmnop12345") is True  # word + 5 digits


def test_defined_once():
    """PA-0003: no second identifier or entropy helper elsewhere in the package. The one
    exception is the redaction floor: the pushed tree's redactors frozen at 7393c90
    (BUG-0556 r6), which only the owner's layered consumers call and which
    `tests/test_redaction_floor.py` pins verbatim -- not a second rule anyone may use."""
    owner = Path(redaction.__file__).resolve()
    floor = (ROOT / "fuzzlab" / "core" / "redaction_floor.py").resolve()
    for path in (ROOT / "fuzzlab").rglob("*.py"):
        if path.resolve() in (owner, floor):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef):
                assert node.name not in ("looks_like_identifier", "is_identifier_like",
                                         "_shannon_bits"), f"{path}: {node.name}"
