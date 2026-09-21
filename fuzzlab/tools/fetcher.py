import argparse
import logging
import os
import re
import sqlite3
import sys
from urllib.parse import urlparse, urljoin, parse_qsl

import requests
from bs4 import BeautifulSoup

from fuzzlab.core import get_logger
from fuzzlab.tools import paths

logging.basicConfig(level=logging.INFO, format='%(message)s')

# Optional JavaScript rendering. When Playwright is available the auditor can
# render a page in a headless browser and inspect the resulting DOM, so forms
# and inputs that are built by JavaScript are audited too. Without it, the
# auditor falls back to fetching the raw HTML.
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


# --------------------------------------------------------------------------
# Parameter-name vocabularies.
#
# Naming is the cheapest reliable signal for what a parameter reaches: a field
# called `url` is an SSRF candidate, one called `page` is a file-inclusion
# candidate. These lists are deliberately conservative — a name that is too
# generic (`data`, `action`, `do`) buries the signal in noise.
# --------------------------------------------------------------------------
FILTER_PARAMS = {
    'sort', 'order', 'orderby', 'order_by', 'dir', 'direction', 'by',
    'limit', 'offset', 'page', 'per_page', 'perpage', 'start', 'count',
    'filter', 'category', 'cat', 'tag', 'type', 'status', 'view',
}
FILE_PATH_PARAMS = {
    'file', 'filename', 'file_name', 'filepath', 'file_path', 'path', 'page',
    'include', 'inc', 'doc', 'document', 'folder', 'dir', 'directory',
    'download', 'read', 'load', 'pdf', 'report', 'log', 'module', 'lang',
    'locale', 'attachment', 'image', 'img', 'photo', 'style', 'conf', 'config',
}
SSRF_URL_PARAMS = {
    'url', 'uri', 'link', 'src', 'source', 'target', 'dest', 'destination',
    'callback', 'webhook', 'fetch', 'proxy', 'host', 'domain', 'site', 'feed',
    'image_url', 'imageurl', 'avatar_url', 'remote', 'endpoint', 'api',
    'redirect_uri', 'return_uri',
}
REDIRECT_PARAMS = {
    'redirect', 'redirect_url', 'redirect_uri', 'redir', 'next', 'next_url',
    'return', 'returnurl', 'return_url', 'returnto', 'return_to', 'goto',
    'continue', 'dest', 'destination', 'url', 'u', 'r', 'back', 'forward',
    'out', 'success_url', 'cancel_url', 'checkout_url', 'location',
}
COMMAND_PARAMS = {
    'cmd', 'command', 'exec', 'execute', 'run', 'ping', 'host', 'ip', 'addr',
    'address', 'shell', 'code', 'system', 'process', 'script', 'binary',
    'tool', 'util', 'traceroute', 'nslookup', 'dns',
}
# Deliberately narrow: `username` appears on every login form and would flag
# every app as an LDAP target. Only distinctly directory-shaped names qualify.
LDAP_PARAMS = {
    'uid', 'cn', 'dn', 'ou', 'dc', 'sn', 'givenname', 'memberof', 'ldap',
    'basedn', 'base_dn', 'ldapfilter', 'ldap_filter', 'principal',
    'distinguishedname', 'samaccountname', 'objectclass',
}
XPATH_PARAMS = {
    'xpath', 'xquery', 'node', 'nodename', 'select', 'expression', 'expr',
}
XML_INPUT_NAMES = {
    'xml', 'xmldata', 'xml_data', 'soap', 'wsdl', 'feed', 'rss', 'svg',
    'xsl', 'xslt', 'dtd', 'sitemap', 'opml',
}
TEMPLATE_PARAMS = {
    'template', 'tpl', 'theme', 'layout', 'view', 'render', 'preview',
    'skin', 'format', 'partial', 'block',
}
EXPORT_PARAMS = {'export', 'format', 'output', 'download', 'csv', 'xls', 'report'}
PRIVILEGED_FIELDS = {
    'role', 'roles', 'is_admin', 'isadmin', 'admin', 'user_role', 'userrole',
    'level', 'permission', 'permissions', 'priv', 'privilege', 'owner',
    'owner_id', 'user_id', 'userid', 'account_id', 'price', 'amount', 'cost',
    'total', 'discount', 'balance', 'credit', 'status', 'state', 'approved',
    'verified', 'active', 'is_active', 'enabled', 'group_id',
}
CSRF_TOKEN_HINTS = ('csrf', 'token', 'nonce', 'authenticity', 'xsrf', '_token')

# Field types that carry no user-controlled value worth fuzzing.
SKIP_INPUT_TYPES = {'submit', 'button', 'reset', 'image'}

# Passive signatures of a database error surfacing in a response body.
SQL_ERROR_SIGNATURES = [
    (re.compile(r"You have an error in your SQL syntax", re.I), 'MySQL'),
    (re.compile(r"\bmysqli?_(?:query|fetch|num_rows|real_escape)", re.I), 'MySQL'),
    (re.compile(r"\bWarning:\s*mysql", re.I), 'MySQL'),
    (re.compile(r"\bunclosed quotation mark after the character string", re.I), 'MSSQL'),
    (re.compile(r"\bMicrosoft OLE DB Provider for (?:ODBC|SQL Server)", re.I), 'MSSQL'),
    (re.compile(r"\bPG::SyntaxError|\bpg_query\(\)|\bPostgreSQL query failed", re.I), 'PostgreSQL'),
    (re.compile(r"\bORA-\d{5}", re.I), 'Oracle'),
    (re.compile(r"\bSQLite3?::|\bsqlite3\.OperationalError|\bunrecognized token", re.I), 'SQLite'),
]

# fetch('...') / $.ajax({url: '...'}) / new XMLHttpRequest().open('GET','...')
AJAX_URL_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\.open\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\burl\s*:\s*['"]([^'"]+)['"]""", re.I),
]

# DOM-based XSS needs an attacker-controlled source reaching a dangerous sink.
# Requiring both in the same script keeps this from flagging every page that
# merely happens to use innerHTML with static markup.
DOM_SOURCES = [
    (re.compile(r"location\.hash"), 'location.hash'),
    (re.compile(r"location\.search"), 'location.search'),
    (re.compile(r"location\.href"), 'location.href'),
    (re.compile(r"document\.URL\b"), 'document.URL'),
    (re.compile(r"document\.referrer"), 'document.referrer'),
    (re.compile(r"URLSearchParams"), 'URLSearchParams'),
    (re.compile(r"window\.name"), 'window.name'),
    (re.compile(r"postMessage|onmessage"), 'postMessage'),
    (re.compile(r"localStorage|sessionStorage"), 'web storage'),
]
DOM_SINKS = [
    (re.compile(r"\.innerHTML\s*[+]?="), 'innerHTML'),
    (re.compile(r"\.outerHTML\s*[+]?="), 'outerHTML'),
    (re.compile(r"insertAdjacentHTML\s*\("), 'insertAdjacentHTML'),
    (re.compile(r"document\.write(?:ln)?\s*\("), 'document.write'),
    (re.compile(r"\beval\s*\("), 'eval'),
    (re.compile(r"new\s+Function\s*\("), 'new Function'),
    (re.compile(r"\.setAttribute\s*\(\s*['\"]src['\"]"), 'setAttribute(src)'),
    (re.compile(r"\$\([^)]*\)\.html\s*\("), 'jQuery .html()'),
]
# Only genuine pollution primitives: recursive merges and path-setting helpers.
# JSON.parse and Object.assign are not primitives on their own and flagging them
# turns every page that reads JSON into a finding.
PROTO_POLLUTION_SINKS = [
    (re.compile(r"\$\.extend\s*\(\s*true"), '$.extend(true, ...)'),
    (re.compile(r"\b_\.(?:merge|mergeWith|defaultsDeep|set|setWith)\s*\("), 'lodash merge/set'),
    (re.compile(r"\b(?:deepMerge|deepExtend|mergeDeep|deepAssign|extendDeep)\s*\("), 'deep merge helper'),
    (re.compile(r"\[\s*(?:key|k|prop|p)\s*\]\s*=.*\bfor\b|\bfor\b.*\[\s*(?:key|k|prop|p)\s*\]\s*="), 'property copy loop'),
]

SERIALIZED_TOKEN_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*"), 'JWT'),
    (re.compile(r"O:\d+:\"[A-Za-z_][A-Za-z0-9_]*\":\d+:\{"), 'PHP serialized object'),
    (re.compile(r"\brO0AB[A-Za-z0-9+/=]{4,}"), 'Java serialized object'),
    (re.compile(r"\bgASV[A-Za-z0-9+/=]{4,}"), 'Python pickle'),
]

NOSQL_OPERATORS = ('$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', '$in', '$nin', '$or')
SSI_EXTENSIONS = ('.shtml', '.shtm', '.stm')
XML_CONTENT_TYPES = ('xml', 'soap', 'xslt', 'svg')


def load_urls(spider_db="spider_results.db"):
    """Extracts the mapped URLs from the spider's database.

    Returns a list of (url, source) where source is 'link' or 'xhr'. Older
    spider databases have no source column; those rows default to 'link'.
    """
    try:
        conn = sqlite3.connect(spider_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(discovered_pages)")
        has_source = any(row[1] == 'source' for row in cursor.fetchall())
        if has_source:
            cursor.execute("SELECT url, IFNULL(source, 'link') FROM discovered_pages ORDER BY depth ASC")
            rows = cursor.fetchall()
        else:
            cursor.execute("SELECT url FROM discovered_pages ORDER BY depth ASC")
            rows = [(row[0], 'link') for row in cursor.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        logging.error(f"Spider DB error: {e}")
        return []


def load_indicators(indicator_db="php_indicators.db"):
    """Extracts the audit rules from the indicators database.

    Returns a list of (indicator_type, category, reference). Older rule stores
    have no reference column; those rows get None.
    """
    try:
        conn = sqlite3.connect(indicator_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(indicators)")
        has_reference = any(row[1] == 'reference' for row in cursor.fetchall())
        if has_reference:
            cursor.execute("SELECT indicator_type, category, reference FROM indicators")
            indicators = cursor.fetchall()
        else:
            cursor.execute("SELECT indicator_type, category FROM indicators")
            indicators = [(row[0], row[1], None) for row in cursor.fetchall()]
        conn.close()
        return indicators
    except sqlite3.Error as e:
        logging.error(f"Indicator DB error: {e}")
        return []


def setup_results_db(db_name="audit_results.db", append=False):
    """Initializes the findings database.

    Findings are keyed on (category, transaction_type, target_identifier) so the
    same form or parameter reached from 40 pages is one row with an occurrence
    count, not 40 near-identical rows. Unless append=True the table is cleared,
    so re-running never inflates the results.
    """
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_url TEXT NOT NULL,
            category TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            target_identifier TEXT NOT NULL,
            html_context TEXT,
            occurrences INTEGER NOT NULL DEFAULT 1,
            reference TEXT
        )
    ''')
    # Upgrade databases written by earlier versions.
    for col, decl in (("occurrences", "INTEGER NOT NULL DEFAULT 1"), ("reference", "TEXT")):
        try:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        except sqlite3.OperationalError:
            pass

    if append:
        # Collapse any duplicates left by an older run so the unique index applies.
        cursor.execute('''
            UPDATE findings SET occurrences = (
                SELECT COUNT(*) FROM findings f2
                WHERE f2.category = findings.category
                  AND f2.transaction_type = findings.transaction_type
                  AND f2.target_identifier = findings.target_identifier
            )
        ''')
        cursor.execute('''
            DELETE FROM findings WHERE id NOT IN (
                SELECT MIN(id) FROM findings
                GROUP BY category, transaction_type, target_identifier
            )
        ''')
    else:
        cursor.execute('DELETE FROM findings')

    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_target
        ON findings (category, transaction_type, target_identifier)
    ''')
    conn.commit()
    return conn


def log_finding(cursor, url, category, trans_type, target, context="", reference=None):
    """Records a finding, or bumps its occurrence count if already seen."""
    cursor.execute('''
        INSERT INTO findings
            (page_url, category, transaction_type, target_identifier, html_context, reference)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (category, transaction_type, target_identifier)
        DO UPDATE SET occurrences = occurrences + 1
    ''', (url, category, trans_type, target, context, reference))


class ContentFetcher:
    """Fetches page HTML, optionally rendering JavaScript with a headless browser.

    Use as a context manager so the browser is started once and reused:

        with ContentFetcher(engine="playwright") as fetcher:
            status, content_type, html, xhr = fetcher.fetch(url)
    """

    def __init__(self, engine="auto", timeout_ms=10000, identity=None, seam_client=None):
        self.timeout_ms = timeout_ms
        self.session = requests.Session()
        # When an identity + seam client are given, the static-fetch path routes
        # through the core HTTP seam so pages are fetched authenticated (Option A).
        # The Playwright (browser) path is migrated separately (cookie injection).
        self._identity = identity
        self._seam = seam_client

        if engine == "auto":
            engine = "playwright" if _PLAYWRIGHT_AVAILABLE else "requests"
        if engine == "playwright" and not _PLAYWRIGHT_AVAILABLE:
            logging.warning(
                "Playwright is not installed; falling back to the static 'requests' engine "
                "(JavaScript-built forms/inputs will NOT be audited). Install with: "
                "pip install playwright && playwright install chromium"
            )
            engine = "requests"
        self.engine = engine

        self._pw = None
        self._browser = None
        self._page = None
        self._xhr_urls = []

    def __enter__(self):
        if self.engine == "playwright":
            self._pw = sync_playwright().start()
            launch_kwargs = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
            exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
            if exe:
                launch_kwargs["executable_path"] = exe
            self._browser = self._pw.chromium.launch(**launch_kwargs)
            self._page = self._browser.new_page()
            self._page.on("request", self._on_request)
        logging.info(f"Auditor engine: {self.engine}")
        return self

    def _on_request(self, request):
        try:
            if request.resource_type in ("xhr", "fetch"):
                self._xhr_urls.append(request.url)
        except Exception:
            pass

    def __exit__(self, exc_type, exc, tb):
        if self.engine == "playwright":
            try:
                if self._browser:
                    self._browser.close()
            finally:
                if self._pw:
                    self._pw.stop()
        return False

    def fetch(self, url):
        """Returns (status_code, content_type, html, xhr_urls). html is the
        RENDERED DOM when the Playwright engine is active, otherwise the raw
        response body. xhr_urls are the fetch/XHR calls the page made while
        rendering (always empty for the static engine)."""
        if self.engine == "playwright":
            self._xhr_urls = []
            try:
                response = self._page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                status = response.status if response else 0
                ct = (response.headers or {}).get('content-type', '') if response else ''
                # Let JavaScript-driven DOM updates settle (best effort).
                try:
                    self._page.wait_for_load_state("networkidle", timeout=self.timeout_ms)
                except Exception:
                    pass
                html = self._page.content()
                return status, ct, html, list(dict.fromkeys(self._xhr_urls))
            except Exception as e:
                # Chromium refuses to render some responses (downloads,
                # application/octet-stream). Those URLs are still audit targets,
                # so fall back to a plain request rather than losing the page.
                logging.info(f"    browser could not render {url} ({str(e).splitlines()[0][:80]}); "
                             f"falling back to a static request")

        return self._static_fetch(url)

    def _static_fetch(self, url):
        """Static (non-browser) fetch: via the auth seam if configured, else raw."""
        if self._seam is not None:
            from fuzzlab.core.http import Request
            resp = self._seam.send(Request("GET", url, identity=self._identity or "anonymous",
                                           component="auditor"))
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html = resp.body.decode("utf-8", errors="replace")
            return resp.status, headers.get("content-type", ""), html, []
        resp = self.session.get(url, timeout=self.timeout_ms / 1000)
        return resp.status_code, resp.headers.get('Content-Type', ''), resp.text, []


def _form_target(page_url, form):
    """Resolves a form's action to a stable identifier for the fuzzer."""
    action = (form.get('action') or '').strip()
    if action in ('', '#'):
        # An empty action posts back to the page itself.
        return urlparse(page_url).path.lstrip('/') or 'index.php'
    return urlparse(urljoin(page_url, action)).path.lstrip('/')


class PageContext:
    """Everything the rules need about one audited page, parsed once."""

    def __init__(self, url, source, status, content_type, html, xhr_urls):
        self.url = url
        self.source = source
        self.status = status
        self.content_type = content_type or ''
        self.html = html or ''
        self.xhr_urls = xhr_urls or []

        parsed = urlparse(url)
        self.path = parsed.path.lstrip('/') or 'index.php'
        self.params = parse_qsl(parsed.query, keep_blank_values=True)

        self.is_html = 'text/html' in self.content_type
        self.soup = BeautifulSoup(self.html, 'html.parser') if self.is_html else None
        self.fields = self._extract_fields()
        self.scripts = self._extract_scripts()

    def _extract_fields(self):
        """Every named field on the page, whether or not it sits in a form."""
        fields = []
        if not self.soup:
            return fields
        for form in self.soup.find_all('form'):
            action = _form_target(self.url, form)
            method = (form.get('method') or 'GET').upper()
            for el in form.find_all(['input', 'textarea', 'select']):
                field = self._field(el, action, method, in_form=True)
                if field:
                    fields.append(field)
        for el in self.soup.find_all(['input', 'textarea', 'select']):
            if el.find_parent('form') is not None:
                continue
            field = self._field(el, self.path, 'GET', in_form=False)
            if field:
                fields.append(field)
        return fields

    def _field(self, el, action, method, in_form):
        # JavaScript-built forms often address their fields by id alone, with no
        # name attribute. Those are still user input, so fall back to the id.
        name = el.get('name') or el.get('id')
        if not name:
            return None
        ftype = (el.get('type') or el.name).lower()
        return {
            'name': name,
            'value': el.get('value') or '',
            'ftype': ftype,
            'action': action,
            'method': method,
            'in_form': in_form,
            'keyed_by': 'name' if el.get('name') else 'id',
            'target': f"{action}:{name}",
            'html': str(el)[:150],
            'el': el,
        }

    def _extract_scripts(self):
        if not self.soup:
            return ''
        return "\n".join((s.string or s.get_text() or '') for s in self.soup.find_all('script'))

    def candidates(self):
        """All user-controllable inputs as (target, name, value, where) tuples.

        Query parameters and form fields are treated alike: a field called `url`
        is an SSRF candidate whether it arrives in the query string or a form.
        """
        out = [(f"{self.path}?{name}", name, value, 'query parameter')
               for name, value in self.params]
        out += [(f['target'], f['name'], f['value'], f"{f['ftype']} field")
                for f in self.fields if f['ftype'] not in SKIP_INPUT_TYPES]
        return out


# --------------------------------------------------------------------------
# Rules. Each takes (ctx, emit) and calls emit(target, context) per finding.
# Registered under the indicator_type stored in php_indicators.db.
# --------------------------------------------------------------------------

def _by_name(ctx, emit, vocabulary, label):
    """Shared helper: flag any input whose name is in a vocabulary."""
    for target, name, value, where in ctx.candidates():
        if name.lower() in vocabulary:
            emit(target, f"{label} ({where}), example value: {value[:60]}")


def rule_query_strings(ctx, emit):
    for name, value in ctx.params:
        emit(f"{ctx.path}?{name}", f"example value: {value[:80]}")


def rule_predictable_ids(ctx, emit):
    for name, value in ctx.params:
        if value.isdigit():
            emit(f"{ctx.path}?{name}", f"numeric value: {value[:80]}")


def rule_action_attributes(ctx, emit):
    for form in (ctx.soup.find_all('form') if ctx.soup else []):
        target = _form_target(ctx.url, form)
        method = (form.get('method') or 'GET').upper()
        emit(target, f"method={method} {str(form)[:150]}")


def rule_input_names(ctx, emit):
    for f in ctx.fields:
        if f['ftype'] in SKIP_INPUT_TYPES:
            continue
        emit(f['target'], f"type={f['ftype']} keyed_by={f['keyed_by']} {f['html']}")


def rule_ajax_live_search(ctx, emit):
    endpoints = set()
    for endpoint in ctx.xhr_urls:
        endpoints.add(urlparse(endpoint).path.lstrip('/') or endpoint)
    for pattern in AJAX_URL_PATTERNS:
        for hit in pattern.findall(ctx.scripts):
            if hit.startswith(('http:', 'https:', '/')) or '.php' in hit:
                endpoints.add(urlparse(urljoin(ctx.url, hit)).path.lstrip('/'))
    if ctx.source == 'xhr':
        endpoints.add(ctx.path)
    for endpoint in sorted(endpoints):
        emit(endpoint, f"called from {ctx.url}")


def rule_filtered_views(ctx, emit):
    for name, value in ctx.params:
        if name.lower() in FILTER_PARAMS:
            emit(f"{ctx.path}?{name}", f"filter/sort parameter, example: {value[:80]}")


def rule_sql_syntax_errors(ctx, emit):
    for pattern, engine_name in SQL_ERROR_SIGNATURES:
        match = pattern.search(ctx.html)
        if match:
            emit(f"{ctx.path} [{engine_name}]", f"matched: {match.group(0)[:120]}")
            return


def rule_reflected_values(ctx, emit):
    """A parameter echoed verbatim into the response is the precondition for
    reflected XSS. Short values are skipped: they match by coincidence."""
    for name, value in ctx.params:
        if len(value) >= 3 and value in ctx.html:
            where = 'inside <script>' if value in ctx.scripts else 'in page body'
            emit(f"{ctx.path}?{name}", f"value '{value[:40]}' reflected {where}")


def rule_dom_sinks(ctx, emit):
    if not ctx.scripts:
        return
    sources = [label for pattern, label in DOM_SOURCES if pattern.search(ctx.scripts)]
    if not sources:
        return
    for pattern, sink in DOM_SINKS:
        if pattern.search(ctx.scripts):
            emit(f"{ctx.path} [{sink}]",
                 f"sink '{sink}' with attacker-reachable source(s): {', '.join(sources[:4])}")


def rule_prototype_pollution(ctx, emit):
    for target, name, value, where in ctx.candidates():
        lowered = name.lower()
        if '__proto__' in lowered or 'constructor' in lowered or 'prototype' in lowered:
            emit(target, f"parameter name reaches Object.prototype ({where})")
    if ctx.scripts:
        sources = [label for pattern, label in DOM_SOURCES if pattern.search(ctx.scripts)]
        if sources:
            for pattern, sink in PROTO_POLLUTION_SINKS:
                if pattern.search(ctx.scripts):
                    emit(f"{ctx.path} [{sink}]",
                         f"recursive-merge/parse sink with source(s): {', '.join(sources[:4])}")


def rule_file_path_parameters(ctx, emit):
    _by_name(ctx, emit, FILE_PATH_PARAMS, "names a file or path")


def rule_upload_fields(ctx, emit):
    for f in ctx.fields:
        if f['ftype'] == 'file':
            accept = f['el'].get('accept', 'any')
            emit(f['target'], f"file upload, accept={accept} {f['html']}")


def rule_ssrf_url_parameters(ctx, emit):
    _by_name(ctx, emit, SSRF_URL_PARAMS, "carries a URL the server may fetch")


def rule_redirect_parameters(ctx, emit):
    _by_name(ctx, emit, REDIRECT_PARAMS, "controls the next location")


def rule_command_parameters(ctx, emit):
    _by_name(ctx, emit, COMMAND_PARAMS, "suggests a shell or system utility")


def rule_ldap_parameters(ctx, emit):
    _by_name(ctx, emit, LDAP_PARAMS, "resembles a directory attribute")


def rule_xpath_parameters(ctx, emit):
    _by_name(ctx, emit, XPATH_PARAMS, "names an XML node or query")


def rule_xml_inputs(ctx, emit):
    if any(x in ctx.content_type.lower() for x in XML_CONTENT_TYPES):
        emit(f"{ctx.path} [{ctx.content_type.split(';')[0]}]",
             "endpoint serves XML; check entity and stylesheet handling")
    for target, name, value, where in ctx.candidates():
        if name.lower() in XML_INPUT_NAMES:
            emit(target, f"accepts XML ({where})")
    for f in ctx.fields:
        accept = (f['el'].get('accept') or '').lower()
        if f['ftype'] == 'file' and any(x in accept for x in XML_CONTENT_TYPES):
            emit(f['target'], f"file upload accepting XML/SVG (accept={accept})")


def rule_nosql_operators(ctx, emit):
    for target, name, value, where in ctx.candidates():
        if '[' in name and ']' in name:
            emit(target, f"bracketed parameter reaches a document query as an operator ({where})")
        elif any(op in value for op in NOSQL_OPERATORS):
            emit(target, f"value already contains a document-store operator ({where})")


def rule_template_parameters(ctx, emit):
    _by_name(ctx, emit, TEMPLATE_PARAMS, "selects a template or view")


def rule_ssi_enabled_pages(ctx, emit):
    if ctx.path.lower().endswith(SSI_EXTENSIONS):
        emit(ctx.path, "served with an SSI-processed extension")
    for link in (ctx.soup.find_all('a', href=True) if ctx.soup else []):
        href = urlparse(urljoin(ctx.url, link['href'])).path
        if href.lower().endswith(SSI_EXTENSIONS):
            emit(href.lstrip('/'), f"SSI-processed page linked from {ctx.path}")


def rule_export_endpoints(ctx, emit):
    for target, name, value, where in ctx.candidates():
        if name.lower() in EXPORT_PARAMS:
            emit(target, f"selects an export format ({where}), example: {value[:40]}")
    for link in (ctx.soup.find_all('a', href=True) if ctx.soup else []):
        href = urljoin(ctx.url, link['href'])
        path = urlparse(href).path
        if re.search(r'(export|csv|xlsx?|download)', path, re.I):
            emit(path.lstrip('/'), f"export/download endpoint linked from {ctx.path}")


def rule_graphql_endpoints(ctx, emit):
    if re.search(r'graphi?ql', ctx.path, re.I):
        emit(ctx.path, "GraphQL endpoint (check introspection and query depth)")
    for hit in re.findall(r"""['"]([^'"]*graphi?ql[^'"]*)['"]""", ctx.scripts, re.I):
        emit(urlparse(urljoin(ctx.url, hit)).path.lstrip('/'),
             f"GraphQL endpoint referenced from {ctx.path}")
    for link in (ctx.soup.find_all('a', href=True) if ctx.soup else []):
        path = urlparse(urljoin(ctx.url, link['href'])).path
        if re.search(r'graphi?ql', path, re.I):
            emit(path.lstrip('/'), f"GraphQL endpoint linked from {ctx.path}")


def rule_serialized_tokens(ctx, emit):
    haystacks = [('response body', ctx.html)]
    haystacks += [(f"parameter {name}", value) for name, value in ctx.params]
    haystacks += [(f"field {f['name']}", f['value']) for f in ctx.fields if f['value']]
    for where, text in haystacks:
        for pattern, kind in SERIALIZED_TOKEN_PATTERNS:
            match = pattern.search(text or '')
            if match:
                emit(f"{ctx.path} [{kind}]", f"{kind} found in {where}: {match.group(0)[:60]}...")


def rule_privileged_hidden_fields(ctx, emit):
    for f in ctx.fields:
        if f['name'].lower() in PRIVILEGED_FIELDS:
            emit(f['target'],
                 f"privileged-looking {f['ftype']} field, value='{f['value'][:40]}' {f['html']}")


def rule_duplicated_parameters(ctx, emit):
    seen = {}
    for name, value in ctx.params:
        seen.setdefault(name, []).append(value)
    for name, values in seen.items():
        if len(values) > 1:
            emit(f"{ctx.path}?{name}", f"supplied {len(values)}x: {', '.join(v[:20] for v in values)}")


def rule_unprotected_forms(ctx, emit):
    for form in (ctx.soup.find_all('form') if ctx.soup else []):
        if (form.get('method') or 'GET').upper() != 'POST':
            continue
        names = [(el.get('name') or el.get('id') or '').lower()
                 for el in form.find_all(['input', 'textarea', 'select'])]
        if not any(hint in n for n in names for hint in CSRF_TOKEN_HINTS):
            target = _form_target(ctx.url, form)
            emit(target, f"POST form with no anti-CSRF token; fields: {', '.join(n for n in names if n)[:100]}")


def rule_unsafe_target_blank(ctx, emit):
    for link in (ctx.soup.find_all('a', href=True) if ctx.soup else []):
        if (link.get('target') or '').lower() != '_blank':
            continue
        rel = ' '.join(link.get('rel') or []).lower()
        if 'noopener' in rel or 'noreferrer' in rel:
            continue
        emit(link['href'][:120], f"target=_blank without rel=noopener on {ctx.path}")


RULES = {
    "Query Strings": rule_query_strings,
    "Predictable IDs": rule_predictable_ids,
    "Action Attributes": rule_action_attributes,
    "Input Names": rule_input_names,
    "AJAX Live Search": rule_ajax_live_search,
    "Filtered Views": rule_filtered_views,
    "SQL Syntax Errors": rule_sql_syntax_errors,
    "Reflected Values": rule_reflected_values,
    "DOM Sinks": rule_dom_sinks,
    "Prototype Pollution Vectors": rule_prototype_pollution,
    "File Path Parameters": rule_file_path_parameters,
    "Upload Fields": rule_upload_fields,
    "URL Parameters": rule_ssrf_url_parameters,
    "Redirect Parameters": rule_redirect_parameters,
    "Command Parameters": rule_command_parameters,
    "LDAP Parameters": rule_ldap_parameters,
    "XPath Parameters": rule_xpath_parameters,
    "XML Inputs": rule_xml_inputs,
    "NoSQL Operators": rule_nosql_operators,
    "Template Parameters": rule_template_parameters,
    "SSI Enabled Pages": rule_ssi_enabled_pages,
    "Export Endpoints": rule_export_endpoints,
    "GraphQL Endpoints": rule_graphql_endpoints,
    "Serialized Tokens": rule_serialized_tokens,
    "Privileged Hidden Fields": rule_privileged_hidden_fields,
    "Duplicated Parameters": rule_duplicated_parameters,
    "Unprotected Forms": rule_unprotected_forms,
    "Unsafe Target Blank": rule_unsafe_target_blank,
}


def audit_page(url, source, fetcher, indicators, db_conn, unhandled, verbose=True):
    """Fetches the page (rendering JS if enabled) and applies every rule to it."""
    if verbose:
        print(f"\n--- Auditing: {url} ---")
    cursor = db_conn.cursor()

    try:
        status, content_type, html, xhr_urls = fetcher.fetch(url)
        ctx = PageContext(url, source, status, content_type, html, xhr_urls)

        for ind_type, category, reference in indicators:
            handler = RULES.get(ind_type)
            if handler is None:
                # Surface it once instead of silently dropping it, so the rule
                # store can't overstate coverage.
                unhandled.add(ind_type)
                continue

            def emit(target, context="", _t=ind_type, _c=category, _r=reference):
                if verbose:
                    print(f"[!] {_t}: {target}")
                log_finding(cursor, url, _c, _t, target, context, _r)

            try:
                handler(ctx, emit)
            except Exception as e:
                logging.warning(f"    rule '{ind_type}' failed on {url}: {e}")

        db_conn.commit()

    except Exception as e:
        print(f"[-] Fetch failed for {url}: {e}")


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit spidered pages for injection points, mapped to the "
                    "payload categories in references/. Renders JavaScript with "
                    "a headless browser when Playwright is available."
    )
    p.add_argument("--spider-db", default="spider_results.db", help="Spider results database")
    p.add_argument("--indicator-db", default=str(paths.INDICATOR_DB),
                   help="Indicator rules database (default: packaged php_indicators.db)")
    p.add_argument("--out", default="audit_results.db", help="Output findings database")
    p.add_argument(
        "--engine", choices=["auto", "playwright", "requests"], default="auto",
        help="auto (default): render JS with Playwright if installed, else static requests.",
    )
    p.add_argument("--timeout", type=int, default=10000, help="Per-page timeout in ms (default: 10000)")
    p.add_argument(
        "--append", action="store_true",
        help="Keep findings already in the output database. By default each run "
             "starts from an empty findings table.",
    )
    p.add_argument("--quiet", action="store_true", help="Only print the closing summary.")
    p.add_argument("--store", default=None,
                   help="Also consolidate candidates into the unified fuzzlab store at this path.")
    p.add_argument("--identity", default=None,
                   help="Audit authenticated as this identity via the session manager "
                        "(needs saved credentials and --base-url). Static engine only for now.")
    p.add_argument("--base-url", default=None,
                   help="Target base URL for authentication (required with --identity), "
                        "e.g. http://localhost:8080")
    return p.parse_args()


def print_summary(conn, out_name):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), IFNULL(SUM(occurrences), 0) FROM findings")
    distinct, total = cursor.fetchone()
    print(f"\nAudit complete. {distinct} distinct finding(s) from {total} observation(s). "
          f"Results saved to {out_name}.")

    cursor.execute('''
        SELECT IFNULL(reference, '(unmapped)'), COUNT(*), SUM(occurrences)
        FROM findings GROUP BY 1 ORDER BY 2 DESC
    ''')
    rows = cursor.fetchall()
    if rows:
        print("\nInjection points by reference category:")
        for reference, count, obs in rows:
            print(f"  {count:3d} target(s)  references/{reference}/  ({obs} observation(s))")


if __name__ == "__main__":
    args = parse_args()
    log = get_logger("auditor")
    log.info("auditor starting", extra={"indicator_db": args.indicator_db,
                                        "spider_db": args.spider_db})
    seam = None
    if args.identity:
        if not args.base_url:
            sys.exit("--identity requires --base-url (the target base URL for login).")
        from fuzzlab.tools.authhttp import make_authenticated_client
        seam = make_authenticated_client(args.base_url, args.identity,
                                         timeout=args.timeout / 1000)
        log.info("auditing authenticated", extra={"identity": args.identity})

    targets = load_urls(args.spider_db)
    rules = load_indicators(args.indicator_db)

    if not targets or not rules:
        print("Missing required databases. Ensure spider and indicator DBs are populated.")
    else:
        print(f"Loaded {len(targets)} targets and {len(rules)} rules. Beginning audit...")

        unhandled = set()
        results_db = setup_results_db(args.out, append=args.append)
        with ContentFetcher(engine=args.engine, timeout_ms=args.timeout,
                            identity=args.identity, seam_client=seam) as fetcher:
            for target, source in targets:
                audit_page(target, source, fetcher, rules, results_db, unhandled,
                           verbose=not args.quiet)

        if unhandled:
            print(f"\n[!] {len(unhandled)} indicator rule(s) have no handler and were "
                  f"skipped: {', '.join(sorted(unhandled))}")

        print_summary(results_db, args.out)
        results_db.close()

        if args.store:
            from fuzzlab.core.config import load_config
            from fuzzlab.core.store import Store
            from fuzzlab.tools import store_adapter
            with Store(args.store) as store:
                run_id = store.start_run("auditor", load_config().hash())
                # Bring discovered pages/params over first if the spider DB is present.
                store_adapter.import_spider(args.spider_db, store, run_id)
                counts = store_adapter.import_audit(args.out, store, run_id)
            log.info("consolidated into store", extra=counts)
