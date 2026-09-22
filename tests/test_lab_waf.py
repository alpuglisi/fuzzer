"""Lab WAF (D16): the configurable request prefilter and its ruleset.

Exercises the actual PHP filter logic offline via the committed self-test driver, using
the same PHP the container runs. Skips (does not fail) where the `php` CLI is absent, so
the suite stays green on machines without PHP.

`L-P3.3c-CUT`: re-points at `lab/waf-rules.json` (moved from the retired
`puppy-fort-factory/config/waf-rules.json`) and the `FzlWaf` Laravel middleware /
`WafFilter` support class (the php_laravel scaffold's successor to `includes/waf.php`),
via the standalone driver at `tests/php/waf_selftest.php`.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STACK_DIR = ROOT / "fuzzlab" / "labgen" / "emitters" / "php_laravel" / "stack" / "skeleton"
RULES = ROOT / "lab" / "waf-rules.json"
DRIVER = ROOT / "tests" / "php" / "waf_selftest.php"
PHP = shutil.which("php")


def _scan(cases: dict) -> dict:
    out = subprocess.run([PHP, str(DRIVER)], input=json.dumps(cases),
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# --- ruleset (no PHP needed) -------------------------------------------------
def test_ruleset_is_wellformed_json():
    data = json.loads(RULES.read_text())
    assert data["version"] >= 1 and data["rules"]
    for r in data["rules"]:
        assert {"id", "category", "pattern"} <= set(r)
    ids = [r["id"] for r in data["rules"]]
    assert len(ids) == len(set(ids))                    # unique rule ids


def test_waf_is_default_off_in_config():
    # the app is unchanged unless PFF_WAF is enabled (preserves ground truth)
    assert "PFF_WAF=off" in (ROOT / "lab" / ".env.example").read_text()
    assert "getenv('PFF_WAF')" in (
        STACK_DIR / "app" / "Http" / "Middleware" / "FzlWaf.php"
    ).read_text()
    # wired globally without editing routes/pages
    assert "FzlWaf::class" in (STACK_DIR / "bootstrap" / "app.php").read_text()


# --- filter behavior (needs the php CLI) -------------------------------------
@pytest.mark.skipif(PHP is None, reason="php CLI not available")
def test_naive_payloads_are_caught():
    res = _scan({
        "sqli": "1 UNION SELECT password FROM users",
        "quote_or": "admin' or 1=1",
        "xss": "<script>alert(1)</script>",
        "traversal": "../../etc/passwd",
        "cmdi": "1; cat /etc/passwd",
    })
    assert "sqli-union-select" in res["sqli"]["hits"]
    assert "sqli-quote-or" in res["quote_or"]["hits"]
    assert "xss-script-tag" in res["xss"]["hits"]
    assert "path-traversal" in res["traversal"]["hits"]
    assert "cmd-metachar" in res["cmdi"]["hits"]


@pytest.mark.skipif(PHP is None, reason="php CLI not available")
def test_classic_bypasses_evade_the_naive_rules():
    # the whole point: a realistic-but-bypassable filter the mutation engine defeats
    res = _scan({
        "sqli": "1 UNION/**/SELECT password FROM users",
        "quote_or": "admin'/**/or/**/1=1",
        "xss": "<svg onfocus=alert(1)>",
        "traversal": "%252e%252e%252fetc%252fpasswd",
    })
    assert res["sqli"]["hits"] == []
    assert res["quote_or"]["hits"] == []
    assert res["xss"]["hits"] == []
    assert res["traversal"]["hits"] == []


@pytest.mark.skipif(PHP is None, reason="php CLI not available")
def test_benign_input_passes_and_sanitize_strips_the_match():
    res = _scan({"benign": "golden retriever fort", "x": "<script>hi</script>ok"})
    assert res["benign"]["hits"] == [] and res["benign"]["clean"] == "golden retriever fort"
    # 'clean' is what sanitize mode would let through — the signature removed
    assert "<script>" not in res["x"]["clean"] and res["x"]["clean"].endswith("ok")
