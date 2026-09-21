"""Tests for the fewer-requests trio: fingerprint (T2.5), dedup (T2.6), hybrid (T2.7)."""

from fuzzlab.core.dedup import TemplateClusterer, minhash, similarity
from fuzzlab.core.fingerprint import Fingerprint, fingerprint
from fuzzlab.core.hybrid import needs_browser


# --- T2.5 fingerprint --------------------------------------------------------
def test_fingerprint_php_mysql_from_headers_and_error():
    fp = fingerprint(
        headers={"Server": "Apache/2.4", "X-Powered-By": "PHP/8.3",
                 "Set-Cookie": "PHPSESSID=abc; Path=/"},
        body="You have an error in your SQL syntax; check the MariaDB manual",
    )
    assert fp.server.startswith("Apache")
    assert fp.framework == "PHP/8.3"
    assert fp.dbms == "MySQL"          # first matching error signature


def test_fingerprint_framework_from_cookie_when_no_powered_by():
    fp = fingerprint(headers={"Set-Cookie": "JSESSIONID=xyz"}, body="")
    assert fp.framework == "Java"


def test_fingerprint_waf_and_merge():
    fp = fingerprint(headers={"CF-RAY": "abc", "Server": "cloudflare"})
    assert fp.waf == "Cloudflare"
    merged = Fingerprint(server="nginx").merge(Fingerprint(dbms="PostgreSQL"))
    assert merged.server == "nginx" and merged.dbms == "PostgreSQL"


# --- T2.6 template dedup -----------------------------------------------------
_PRODUCT = "<html><body><h1>{name}</h1><p>{desc}</p><span>${price}</span></body></html>"


def test_same_template_different_data_clusters_together():
    a = _PRODUCT.format(name="Fort A", desc="cozy", price="10")
    b = _PRODUCT.format(name="Fort ZZZ", desc="huge deluxe castle", price="9999")
    assert similarity(minhash(a), minhash(b)) >= 0.9
    clusterer = TemplateClusterer(threshold=0.7)
    assert clusterer.cluster_id(a) == clusterer.cluster_id(b)
    assert clusterer.cluster_count == 1


def test_different_templates_get_different_clusters():
    product = _PRODUCT.format(name="x", desc="y", price="1")
    blog = "<html><body><article><h2>t</h2><div><p>a</p><p>b</p></div></article></body></html>"
    clusterer = TemplateClusterer(threshold=0.7)
    assert clusterer.cluster_id(product) != clusterer.cluster_id(blog)
    assert clusterer.cluster_count == 2


def test_cluster_ids_are_stable_and_reused():
    clusterer = TemplateClusterer(threshold=0.7)
    pages = [_PRODUCT.format(name=f"p{i}", desc="d" * i, price=str(i)) for i in range(5)]
    ids = [clusterer.cluster_id(p) for p in pages]
    assert set(ids) == {"T0001"}          # all one template -> audited once


# --- T2.7 hybrid crawl -------------------------------------------------------
def test_needs_browser_for_spa_shell():
    assert needs_browser('<html><body><div id="root"></div><script src="/app.js"></script></body></html>')
    assert needs_browser('<html><body><div id="app"></div><script>boot()</script></body></html>')


def test_needs_browser_for_noscript_gate():
    assert needs_browser("<html><body><noscript>Please enable JavaScript</noscript>"
                         "<script>run()</script></body></html>")


def test_static_page_does_not_need_browser():
    page = "<html><body>" + "<p>Real server-rendered content here. </p>" * 40 + "</body></html>"
    assert not needs_browser(page)


def test_empty_html_does_not_need_browser():
    assert not needs_browser("")
