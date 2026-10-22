"""Consolidate the tools' native outputs into the unified store (T0.8).

Phase 0 keeps each tool independently runnable with its own native output
(spider_results.db, audit_results.db, a fuzzer CSV) and adds a thin adapter that
imports those into the one shared store — the integration bus (D5) the harness and
later phases read. When a tool is given ``--store``, it calls the matching import
here after its run.

URLs are normalized to path form (``/product.php``) so pages, endpoints,
parameters, and findings line up with the ground-truth contract, which is written
in paths.

The fuzzer's confirmed *timing* detections are written as ``finding`` rows here so
the harness can score a live run in Phase 0. The deterministic oracle that will
own finding labels arrives in Phase 2; until then these are timing-only
confirmations, flagged as such in the finding confidence.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_plus, urlparse

from fuzzlab.core.forms import LINK_SET_ENCTYPE
from fuzzlab.core.store import Store
from fuzzlab.core.urls import canonical_origin, store_url


def _upsert_endpoint(store: Store, run_id: int, url_path: str, method: str,
                     source: str | None) -> int:
    row = store.conn.execute(
        "SELECT id FROM endpoint WHERE run_id=? AND url=? AND method=?",
        (run_id, url_path, method),
    ).fetchone()
    if row:
        return int(row["id"])
    cur = store.conn.execute(
        "INSERT INTO endpoint (run_id, url, method, source) VALUES (?,?,?,?)",
        (run_id, url_path, method, source),
    )
    return int(cur.lastrowid)


def _get_parameter(store: Store, run_id: int, endpoint_id: int, name: str,
                   location: str, form_id: int | None) -> int | None:
    """The parameter row of one request context (FR-AUD-31, BUG-0530): a name at a
    location of an endpoint, in one sibling set (``form_id``; None for a lone
    parameter). A name in the query and in the body, or in two sibling sets, is two
    rows: never one row per (endpoint, name), which kept the first context only."""
    row = store.conn.execute(
        "SELECT id FROM parameter WHERE run_id=? AND endpoint_id=? AND name=? AND "
        "location=? AND form_id IS ?",
        (run_id, endpoint_id, name, location, form_id),
    ).fetchone()
    return int(row["id"]) if row else None


def _insert_parameter(store: Store, run_id: int, endpoint_id: int, name: str,
                      location: str, example, form_id: int | None, counts: dict) -> bool:
    """Write one context's parameter row unless it exists; True when written."""
    if _get_parameter(store, run_id, endpoint_id, name, location, form_id) is not None:
        return False
    store.conn.execute(
        "INSERT INTO parameter (run_id, endpoint_id, name, location, example, form_id) "
        "VALUES (?,?,?,?,?,?)", (run_id, endpoint_id, name, location, example, form_id))
    counts["parameter"] += 1
    return True


def _insert_sibling_set(store: Store, run_id: int, endpoint_id: int, enctype, entries,
                        *, source_page: str | None, fresh, password_fields="[]") -> int:
    """Write one stored sibling set (a `form` row) with its replay recipe (FR-FUZZ-67,
    migration 25): ``fresh`` names the entries whose stored value is a placeholder
    (blanked by redaction), ``source_page`` the page a fresh value is bound from. Names
    and a page only, never a value (D12)."""
    cur = store.conn.execute(
        "INSERT INTO form (run_id, endpoint_id, enctype, entries, password_fields, "
        "source_page, fresh) VALUES (?,?,?,?,?,?,?)",
        (run_id, endpoint_id, enctype, entries, password_fields, source_page,
         json.dumps(list(dict.fromkeys(fresh)))))
    return int(cur.lastrowid)


def query_pairs(raw_query: str) -> list[tuple[str, str, str]]:
    """``(name, raw value, value)`` for each pair of a URL's raw query, in order,
    blanks kept. *raw value* is percent-decoded only -- what
    `core.redaction.looks_like_identifier` must be given (form decoding turns base64's
    ``+`` into a space); *value* is form-decoded, as `parse_qsl` and a server see it."""
    out = []
    for part in (raw_query or "").split("&"):
        if not part:
            continue
        name, _eq, raw = part.partition("=")
        out.append((unquote_plus(name), unquote(raw), unquote_plus(raw)))
    return out


def redact_sibling(name: str, raw_value: str, value: str) -> str:
    """A crawled link's sibling value as it may be stored and sent: ``""`` when its
    name is sensitive or its raw value holds a secret anywhere -- it looks like an
    identifier (a token, an id), or a URL, query string or ``;`` pair nested in it holds
    a sensitively named or identifier-like value (BUG-0556) -- else ``value`` (forms
    phase 2, FR-FUZZ-43; PA-0100). The owner's rule, `core.redaction.stored_value`."""
    from fuzzlab.core.redaction import stored_value
    return stored_value(name, raw_value, value)


def entries_refusal(entries, *, credential_names: bool = False) -> str | None:
    """Why an entry list must never be sent as siblings, or None: any name or value
    tokenises destructive; with ``credential_names``, any name carries a credential
    token. The one check for forms and link sets (PA-0003)."""
    from fuzzlab.core.redaction import is_credential_name
    from fuzzlab.core.urls import text_destructive_reason
    for name, value in entries:
        for text in (name, value):
            reason = text_destructive_reason(text)          # never via a URL (BUG-0131)
            if reason:
                return f"destructive entry {name}={value!r} ({reason!r})"
        if credential_names and is_credential_name(name):
            return f"credential entry {name!r}"
    return None


def import_spider(spider_db: str | Path, store: Store, run_id: int, *,
                  fuzz_json_writes: bool = False,
                  base_url: str | None = None) -> dict[str, int]:
    """Import discovered pages -> page/endpoint/parameter rows, crawled forms, each
    query-bearing URL's query as a link set (forms phase 2), each SPA hash route's query
    as ``fragment`` parameters, and the app's own captured requests (forms phase 3,
    FR-AUD-22; PUT/PATCH only with ``fuzz_json_writes``). A SPA query seed that blocked
    a write (``source = 'spa-query-writes'``, FR-CRAWL-17) is a page only: no endpoint,
    parameter or link set comes from it (counted ``write_seed_skipped``).

    A URL keeps its origin when it is not the run's main one (``base_url``'s, else the
    first crawled URL's): stored as an absolute URL, never as a bare path that would be
    re-rooted at the base (`core.urls.store_url`, FR-AUD-27)."""
    from fuzzlab.tools.observe import observe_spider
    observe_spider(spider_db)              # FR-AUD-28: what the crawl observed, as events
    src = sqlite3.connect(str(spider_db))
    src.row_factory = sqlite3.Row
    counts = {"page": 0, "endpoint": 0, "parameter": 0}
    seen_pages: set[tuple[str, str]] = set()
    # stored link sets by (endpoint, redacted entries): one row each (FR-AUD-31)
    link_sets: dict[tuple[int, str], int] = {}
    for key in ("link_set", "link_set_refused", "link_set_bound"):
        counts[key] = 0
    try:
        # crawl order: the order points are built and confirmed in
        rows = src.execute(
            "SELECT * FROM discovered_pages ORDER BY rowid").fetchall()
    except sqlite3.Error:
        rows = []
    main = _main_origin(base_url, (r["url"] for r in rows))
    path_urls = []
    for row in rows:
        keys = row.keys()
        source = row["source"] if "source" in keys else "link"
        # FR-FUZZ-67: the page the link was found on, where a fresh value of a blanked
        # sibling is bound from (FR-CRAWL-29; absent in an older spider DB)
        found_from = row["found_from"] if "found_from" in keys else None
        _import_page_url(store, run_id, row["url"], row["status_code"], source, counts,
                         seen_pages, link_sets, main, source_page=found_from)
        if source != _write_seed_source() and _answered(row["status_code"]):
            path_urls.append(row["url"])
    try:                              # FR-CRAWL-28; absent in older spider DBs
        code = frozenset(r[0] for r in src.execute("SELECT segment FROM script_segments"))
    except sqlite3.Error:
        code = frozenset()
    _import_path_templates(store, run_id, path_urls, "link", counts, main, code=code)
    _import_forms(src, store, run_id, counts, main)
    _import_requests(src, store, run_id, counts, fuzz_json_writes=fuzz_json_writes,
                     main=main)
    store.conn.commit()
    src.close()
    return counts


def _main_origin(base_url: str | None, urls, *, origin_of=canonical_origin) -> str | None:
    """The run's main origin: ``base_url``'s, else the first crawled URL's that has one
    (each read by ``origin_of``; `import_audit` passes `_readable_origin`)."""
    if base_url:
        return canonical_origin(base_url)
    return next((o for o in map(origin_of, urls) if o is not None), None)


def _import_page_url(store: Store, run_id: int, raw: str, status, source: str,
                     counts: dict, seen_pages: set, link_sets: dict,
                     main: str | None = None, *, source_page: str | None = None) -> None:
    """One visited URL -> its page row, its query as a link set (whose ``query``
    parameters `_import_link_set` writes, one row per context), its SPA hash route's
    query as ``fragment`` parameters (`import_spider`, `import_disco`). Stored as
    `store_url` gives it (another origin kept). ``source_page``: the page the link was
    found on (FR-FUZZ-67)."""
    path = store_url(raw, main)
    if (path, "GET") not in seen_pages:
        store.conn.execute(
            "INSERT OR IGNORE INTO page (run_id, url, method, status, source) "
            "VALUES (?,?,?,?,?)",
            (run_id, path, "GET", status, source),
        )
        seen_pages.add((path, "GET"))
        counts["page"] += 1
    if source == _write_seed_source():
        # a SPA query seed whose load blocked a write (FR-CRAWL-17, review A-M1): a
        # page, never a point -- an M6 load of it would send that write unguarded
        counts["write_seed_skipped"] = counts.get("write_seed_skipped", 0) + 1
        return
    # blank values are parameters too (`?title=`), forms phase 1
    pairs = query_pairs(urlparse(raw).query)
    if pairs:
        endpoint_id = _upsert_endpoint(store, run_id, path, "GET", source)
        counts["endpoint"] += 1
        _import_link_set(store, run_id, endpoint_id, pairs,
                         _source_page(source_page, main), counts, link_sets)
    _import_route_query(store, run_id, raw, source, counts, main)


def _source_page(url, main: str | None) -> str | None:
    """A sibling set's source page as stored (FR-FUZZ-67): an absolute crawled URL kept
    with its query (`core.urls.store_url`), only when the strongest URL redactor
    (`core.redaction.redact_url_identifiers`: sensitive names, identifier-like values, an
    SPA route's query; PA-0514(1)) leaves it unchanged. A page whose URL holds such a
    value is never stored (PA-0100, D12) and never fetched with a placeholder in it: None,
    so its sibling set has no page and a test needing it is inconclusive."""
    from fuzzlab.core.redaction import page_url_is_clean
    if not isinstance(url, str) or "://" not in url or not page_url_is_clean(url):
        return None
    return store_url(url, main, keep_query=True)


def _answered(status) -> bool:
    """A crawled URL that answered (no status recorded counts): a broken link is no
    evidence of a route."""
    try:
        return status is None or int(status) < 400
    except (TypeError, ValueError):
        return False


def _import_path_templates(store: Store, run_id: int, urls, source: str,
                           counts: dict, main: str | None = None, *,
                           code=frozenset()) -> None:
    """The run's URLs -> ``path`` parameters (FR-AUD-26): each `core.pathtemplate`
    template is an endpoint (its path with one ``{param}`` segment, GET) with one
    ``path`` parameter whose example is the crawled value, blanked when it looks like
    an identifier (PA-0100). ``code`` is the path segments the app's scripts hold, as
    the crawl recorded them (FR-CRAWL-28): a value among them names a route, not data.
    Both importers call it once, after their URLs."""
    from fuzzlab.core.pathtemplate import path_templates
    from fuzzlab.core.redaction import stored_value, strip_secret_path_params
    for t in path_templates(urls, code=code):
        path = strip_secret_path_params(t.path)          # as `store_url` (BUG-0556)
        stored = path if main is None or t.origin == main else t.origin + path
        endpoint_id = _upsert_endpoint(store, run_id, stored, "GET", source)
        if _get_parameter(store, run_id, endpoint_id, t.param, "path", None) is not None:
            continue
        counts["endpoint"] += 1
        example = stored_value("", t.example, t.example)     # the owner's rule
        store.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
            "VALUES (?,?,?,?,?)", (run_id, endpoint_id, t.param, "path", example))
        counts["parameter"] += 1
        counts["path_parameter"] = counts.get("path_parameter", 0) + 1


#: The ``source`` of rows imported from a disco run (D70).
DISCO_SOURCE = "disco"
#: Response media types whose GET is a page (not an asset) in a disco run.
_PAGE_MEDIA = ("text/html", "application/xhtml+xml")


def import_disco(run_dir: str | Path, store: Store, run_id: int, *,
                 fuzz_json_writes: bool = False,
                 base_url: str | None = None) -> dict[str, int]:
    """Import a ``fuzzlab disco capture`` run directory (D70, FR-AUD-23) as
    `import_spider` imports a crawl, so `fuzzlab auto` confirms what disco found:

    - every GET exchange of ``capture.jsonl`` with a query string, or an HTML answer ->
      `_import_page_url` (page, ``query`` parameters, link set);
    - every other HTTP exchange -> the captured-request import (`captured_request`
      then `_store_request`: every FR-AUD-22 refusal and redaction applies, PUT/PATCH
      only with ``fuzz_json_writes``); a truncated body is refused;
    - every page URL of ``actions.jsonl`` -> `_import_page_url`, which gives an SPA
      hash route's query as ``fragment`` parameters: the browser never sends a
      fragment, so only the explorer's own log holds it.

    WebSocket messages and exchanges without a response are skipped. The capture was
    redacted when written (`disco.capture`), the store's own redaction runs again."""
    from fuzzlab.disco.capture import read_capture
    run_dir = Path(run_dir)
    read = read_capture(run_dir / "capture.jsonl")
    from fuzzlab.tools.observe import observe_disco
    observe_disco(run_dir, read.records)   # FR-AUD-28: what the capture observed
    counts = {"page": 0, "endpoint": 0, "parameter": 0, "quarantined": read.quarantined}
    for key in ("request", "request_json", "request_form", "request_refused"):
        counts.setdefault(key, 0)
    seen_pages: set[tuple[str, str]] = set()
    link_sets: dict[tuple[int, str], int] = {}       # FR-AUD-31
    bodies: dict = {}                                # identical stored bodies are one
    for key in ("link_set", "link_set_refused", "link_set_bound"):
        counts[key] = 0
    page_urls, visible = _disco_actions(run_dir / "actions.jsonl", counts)
    main = _main_origin(base_url, [r.url for r in read.records if r.kind == "http"]
                        + page_urls)
    path_urls = []
    for rec in read.records:
        if rec.kind != "http" or rec.status is None:
            continue
        referer = rec.req_headers.get("referer") or rec.req_headers.get("Referer")
        if rec.method == "GET":
            if _answered(rec.status):
                path_urls.append(rec.url)      # an API GET's path too (FR-AUD-26)
            media = (rec.res_ctype or "").split(";", 1)[0].strip().lower()
            if urlparse(rec.url).query or media in _PAGE_MEDIA:
                _import_page_url(store, run_id, rec.url, rec.status, DISCO_SOURCE,
                                 counts, seen_pages, link_sets, main, source_page=referer)
            continue
        counts["request"] += 1
        body = rec.req_body
        if body and _body_kind(rec.req_ctype) == "form":
            # the capture holds the wire: its ordered pairs, a repeated name kept in order
            # (FR-AUD-31; a `dict` kept its last value only)
            body = json.dumps([[n, v] for n, v in parse_qsl(body, keep_blank_values=True)])
        row = {"url": rec.url, "method": rec.method, "content_type": rec.req_ctype,
               "body_json": body, "page_url": referer}
        if rec.req_truncated:
            counts["request_refused"] += 1
            continue
        reason, kind, leaves = captured_request(row, fuzz_json_writes=fuzz_json_writes)
        if reason is not None:
            counts["request_refused"] += 1
            continue
        _store_request(store, run_id, counts, kind, rec.method.upper(), rec.url, leaves,
                       visible=visible.get(rec.action_id or "", frozenset()), main=main,
                       page=row["page_url"], bodies=bodies)
    for url in page_urls:
        _import_page_url(store, run_id, url, None, DISCO_SOURCE, counts, seen_pages,
                         link_sets, main)
    _import_path_templates(store, run_id, path_urls + page_urls, DISCO_SOURCE, counts,
                           main, code=_disco_code_segments(run_dir))
    store.conn.commit()
    return counts


def _disco_code_segments(run_dir: Path) -> frozenset[str]:
    """A disco run's ``script_segments.json`` (FR-CRAWL-28): the path segments its
    app's scripts hold; nothing for an older run or a malformed file."""
    try:
        doc = json.loads((run_dir / "script_segments.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    if not isinstance(doc, list):
        return frozenset()
    return frozenset(s for s in doc if isinstance(s, str))


def _disco_actions(path: Path, counts: dict) -> tuple[list[str], dict[str, frozenset]]:
    """A disco ``actions.jsonl``: the page URLs in order, and per action id
    (``act-<seq>``) the names of the visible (non-hidden) controls its form step
    filled. A malformed line is counted ``quarantined``; no file is no actions."""
    urls: list[str] = []
    visible: dict[str, frozenset] = {}
    if not path.exists():
        return urls, visible
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                doc = json.loads(line)
                url, fields, seq = doc.get("url"), doc.get("fields"), doc.get("seq")
            except (ValueError, AttributeError):
                counts["quarantined"] += 1
                continue
            if isinstance(url, str) and "://" in url:
                urls.append(url)
            if isinstance(fields, list) and isinstance(seq, int):
                visible[f"act-{seq}"] = frozenset(
                    f[0] for f in fields if isinstance(f, list) and len(f) == 2
                    and isinstance(f[0], str) and f[1] != "hidden")
    return urls, visible


def _write_seed_source() -> str:
    from fuzzlab.tools.spa import WRITE_SEED_SOURCE        # the one definition (PA-0003)
    return WRITE_SEED_SOURCE


def _import_link_set(store: Store, run_id: int, endpoint_id: int, pairs, page,
                     counts: dict, stored_ids: dict) -> None:
    """One crawled link's query, at its page's turn in crawl order (forms phase 2,
    FR-FUZZ-43; one context each since FR-AUD-31, BUG-0530):

    - a set with a destructive or credential entry is refused (not stored), and so is
      a set with one name: its names are lone ``query`` parameters (one row per
      endpoint and name, the first crawled value its example). A one-name set is still
      stored, as the page's representative query for header points;
    - a set with two or more names is its own `form` row (``enctype`` NULL,
      `core.forms.LINK_SET_ENCTYPE`) and its own parameter rows, one per name -- never
      bound to another set's rows ("the first crawled link wins" merged contexts).
      Identical sets after redaction are one. Its values pass `redact_sibling`; each
      value that blanks is named in the row's replay recipe (``fresh``) with the page
      the link was found on (``source_page``, FR-FUZZ-67)."""
    for key in ("link_set", "link_set_refused", "link_set_bound"):
        counts.setdefault(key, 0)
    refused = entries_refusal([(n, v) for n, _r, v in pairs], credential_names=True)
    names = list(dict.fromkeys(name for name, _r, _v in pairs))
    if refused or len(names) < 2:
        counts["link_set_refused"] += 1 if refused else 0
        for name, raw, value in pairs:                   # lone points, as crawled
            # the example is a stored value: through the owner's rule (BUG-0556)
            _insert_parameter(store, run_id, endpoint_id, name, "query",
                              redact_sibling(name, raw, value), None, counts)
        if refused:
            return
    entries = [(name, redact_sibling(name, raw, value)) for name, raw, value in pairs]
    key = (endpoint_id, json.dumps(entries))
    form_id = stored_ids.get(key)
    if form_id is None:
        fresh = [name for (name, _r, value), (_n, kept) in zip(pairs, entries)
                 if kept != value]
        form_id = stored_ids[key] = _insert_sibling_set(
            store, run_id, endpoint_id, LINK_SET_ENCTYPE, key[1], source_page=page,
            fresh=fresh)
        counts["link_set"] += 1
    if len(names) < 2:
        return
    for name, kept in entries:                       # the example as the entry is stored
        if _insert_parameter(store, run_id, endpoint_id, name, "query", kept, form_id,
                             counts):
            counts["link_set_bound"] += 1


#: Hidden fields that pick an object or a user (``login``, ``user_id``): never fuzzed,
#: sent with their default, so probes cannot rewrite another user's rows (reviewer B-S8).
_OBJECT_SELECTOR_TOKENS = frozenset({"login", "user", "username", "uid", "owner"})


def _object_selector(name: str) -> bool:
    from fuzzlab.core.redaction import name_tokens
    toks = [t.lower() for t in name_tokens(name)]
    return bool(set(toks) & _OBJECT_SELECTOR_TOKENS) or (len(toks) > 1 and toks[-1] == "id")


#: A benign value a user would type into an empty free-text field, by control kind.
#: Many handlers ignore a request with an empty required field (bWAPP's xss_get needs
#: both names), so empty text siblings are filled as a user would (forms phase 1).
#: URL and e-mail fillers use reserved names that never resolve (RFC 2606/6761): no
#: server-side fetch or mail is triggered by a filler (reviewers A/B).
_FILLERS = {"email": "fuzzlab@example.invalid", "number": "1", "range": "1",
            "tel": "5555550100", "url": "http://fuzzlab.invalid/", "date": "2020-01-01",
            "datetime-local": "2020-01-01T00:00", "month": "2020-01", "week": "2020-W01",
            "time": "12:00", "color": "#000000"}
_TEXT_FILLER = "fuzzlab"
_FILLED_KINDS = frozenset({"text", "search", "textarea", *_FILLERS})


# --- the constraint-aware ladder (FR-CRAWL-15, G1a; reviewer B7) --------------------
#: Digit strings the crawler's constraint-aware filling may type: a run of one repeated
#: digit (``7``, ``11``, ``5555555555``) or the ascending run ``1234567890…`` cut to a
#: length, at most this many digits long. 16 or more digits would look like an
#: identifier (`core.redaction.looks_like_identifier` R1), so the ladder stops at 15.
LADDER_MAX_DIGITS = 15
_LADDER_SEQUENCE = "1234567890" * 2
#: Documented constants of the ladder: a year.
LADDER_CONSTANTS = frozenset({"2000"})
#: Text the ladder may type: the text filler, padded with ``x`` (lower case only, so
#: never identifier-like), or cut to a prefix of at least `LADDER_MIN_PREFIX`
#: characters; and two case variants (for a ``pattern``), never padded.
LADDER_TEXT = _TEXT_FILLER
LADDER_TEXT_VARIANTS = ("Fuzzlab", "FUZZLAB")
LADDER_PAD = "x"
LADDER_MIN_PREFIX = 3
LADDER_MAX_TEXT = 64


def ladder_digits(length: int) -> list[str]:
    """The ladder's digit strings of ``length`` (1..`LADDER_MAX_DIGITS`): each repeated
    digit (``1``…``9``, then ``0``), then the ascending run, deduplicated, in order."""
    if not 1 <= length <= LADDER_MAX_DIGITS:
        return []
    out = [d * length for d in "1234567890"] + [_LADDER_SEQUENCE[:length]]
    return list(dict.fromkeys(out))


def is_ladder_value(value) -> bool:
    """True when ``value`` is one the constraint-aware ladder generates (FR-CRAWL-15):
    a ladder digit string (`ladder_digits`), a `LADDER_CONSTANTS` member, the text
    filler padded with ``x`` or cut to a prefix, or a `LADDER_TEXT_VARIANTS` member.
    Total: a non-string is False."""
    if not isinstance(value, str) or not value or len(value) > LADDER_MAX_TEXT:
        return False
    if value.isascii() and value.isdigit():
        return value in LADDER_CONSTANTS or (
            len(value) <= LADDER_MAX_DIGITS
            and (len(set(value)) == 1 or _LADDER_SEQUENCE.startswith(value)))
    if value in LADDER_TEXT_VARIANTS:
        return True
    if value.startswith(LADDER_TEXT):
        return set(value[len(LADDER_TEXT):]) <= {LADDER_PAD}
    return len(value) >= LADDER_MIN_PREFIX and LADDER_TEXT.startswith(value)


def is_filler(value) -> bool:
    """True when ``value`` is one of the importer's own fillers, or a value of the
    crawler's constraint-aware ladder (`is_ladder_value`, FR-CRAWL-15; the single
    source, reviewer B7): it says nothing about the app, and it is sent as is (its URL
    never resolves)."""
    return value == _TEXT_FILLER or value in _FILLERS.values() or is_ladder_value(value)


def _filled(entries, kinds) -> list:
    """``entries`` with each empty free-text field given a benign value; secrets,
    passwords, hidden fields and selects are left exactly as they are."""
    from fuzzlab.core.redaction import is_sensitive_name
    out = []
    for name, value in entries:
        kind = kinds.get(name)
        if value == "" and kind in _FILLED_KINDS and not is_sensitive_name(name):
            value = _FILLERS.get(kind, _TEXT_FILLER)
        out.append((name, value))
    return out


#: A password control whose lower-cased name contains one of these belongs to a
#: credential-change form. A bare substring on purpose (PA-0022's "specifically
#: intended" case): a false match only *excludes* a form, the safe direction, and it
#: catches run-together names (``newpassword``) that `name_tokens` cannot split.
_CHANGE_SUBSTRINGS = ("new", "conf", "change", "reset", "old", "curr", "repeat", "retype",
                      "verify", "again")
#: Anchored tokens (`core.redaction.name_tokens`) of a password form's action path, its
#: sent submitter's name or value, or a hidden field's name, that mark it as one that
#: changes or manages an account rather than logging in (FR-FUZZ-44, reviewer B-R3).
#: Accepted false positives (a real login form excluded; a missed finding, never a
#: safety risk): Rails ``/sessions/new``, Devise ``/users/sign_in``, ``/admin/login``,
#: ``/account/login``, ``/my-account``, a login button valued ``Save``.
_CHANGE_TOKENS = frozenset({
    "change", "new", "set", "reset", "update", "edit", "modify", "register", "signup",
    "create", "forgot", "recover", "activate", "password", "passwd", "pwd", "pass",
    "save", "admin", "manage", "account", "profile", "users"})
#: Control kinds a login form may have besides its one password and one user field.
_LOGIN_EXTRA_KINDS = frozenset({"hidden", "submit", "select", "checkbox", "radio",
                                "reset", "button", "image"})
_LOGIN_USER_KINDS = frozenset({"text", "email", "tel"})


def credential_change_reason(form: dict) -> str | None:
    """Why a form with a password control changes a credential or manages an account
    (never imported, even with an isolated session: it changes the account, not the
    session), or None. Reviewers A/B (FR-FUZZ-44)."""
    kinds = dict(form["controls"])
    return credential_change_rule(
        [n for n, k in form["controls"] if k == "password"], form["action_url"],
        submitters=[t for n, v in form["entries"] if kinds.get(n) == "submit"
                    for t in (n, v)],
        hidden=[n for n, k in form["controls"] if k == "hidden"])


def credential_change_rule(passwords, action_url: str, *, submitters=(), hidden=(),
                           what: str = "form", field: str = "password control") -> str | None:
    """The one credential-change rule (PA-0003), for crawled forms and captured
    requests alike (forms phase 3, FR-AUD-22): given a request's password fields (a
    form's password controls, a body's credential-named leaves), why it changes a
    credential or manages an account, or None. Two or more password fields; a password
    field whose name has a change word (new, confirm, repeat, current, old, ...); or an
    account-management token in the action path, a submitter, or a hidden field name."""
    from urllib.parse import urlsplit

    from fuzzlab.core.redaction import name_tokens
    passwords = list(passwords)
    if not passwords:
        return None
    if len(passwords) >= 2:
        return f"credential-change {what} ({len(passwords)} {field}s)"
    for name in passwords:
        hit = next((sub for sub in _CHANGE_SUBSTRINGS if sub in name.lower()), None)
        if hit:
            return f"credential-change {what} ({field} {name!r} has {hit!r})"
    texts = [("action", urlsplit(action_url).path)]
    texts += [("submitter", t) for t in submitters]
    texts += [("hidden field", n) for n in hidden]
    for where, text in texts:
        hit = next((t for t in name_tokens(text or "") if t in _CHANGE_TOKENS), None)
        if hit:
            return f"credential-change {what} ({where} has {hit!r})"
    for name in hidden:
        if _object_selector(name):
            return f"credential-change {what} (hidden object selector {name!r})"
    return None


def login_shaped(form: dict) -> bool:
    """An in-app login form: exactly one password control, exactly one user field
    (text, email or tel), and nothing else a user types (hidden fields, selects,
    checkboxes and buttons are allowed). FR-FUZZ-44."""
    kinds = [k for _n, k in form["controls"]]
    others = [k for k in kinds if k != "password"]
    users = [k for k in others if k in _LOGIN_USER_KINDS]
    return (kinds.count("password") == 1 and len(users) == 1
            and all(k in _LOGIN_EXTRA_KINDS or k in _LOGIN_USER_KINDS for k in others))


def password_fields(form: dict) -> list[str]:
    """The names of ``form``'s password controls (stored in `form.password_fields`)."""
    return [n for n, k in form["controls"] if k == "password"]


#: A POST selector whose select name is this short or shorter cannot be judged by its
#: name (``t``, ``v``, ``tz``): it is skipped (forms phase 2, reviewer B-R4).
MIN_JUDGEABLE_SELECT_NAME = 3


def form_skip_reason(form: dict) -> str | None:
    """Why a crawled form is never fuzzed (reported), or None. The whole form is
    skipped when submitting it could change a credential, an account, or something
    destructive (forms phase 1, reviewers A/B). A form with a password control is
    imported only when it is an in-app login form; its points are then probed on an
    isolated session, never the run's (FR-FUZZ-44).

    A **POST selector** form (one ``<select>`` and buttons) is fuzzed since forms phase
    2 (FR-FUZZ-43) unless a control name carries a settings word
    (`formnav.settings_word`), its select name is too short to judge, or the crawler
    saw it act as a settings form (``form["verdict"]``, FR-CRAWL-10). GET selector
    forms are not subject to that rule (GET is safe)."""
    from fuzzlab.core.urls import destructive_reason
    from fuzzlab.tools.formnav import VERDICT_SETTINGS, settings_word
    if (form.get("enctype") or "").startswith("multipart/"):
        return "multipart form (not sent as multipart in phase 1)"
    if form["selector"] and form["method"] == "POST":
        for name, _kind in form["controls"]:
            word = settings_word(name)
            if word:
                return f"POST selector with a settings control {name!r} ({word!r})"
        select = next((n for n, k in form["controls"] if k == "select"), "")
        if len(select) < MIN_JUDGEABLE_SELECT_NAME:
            return f"POST selector named {select!r}: too short to tell it from a setting"
        if form.get("verdict") == VERDICT_SETTINGS:
            return "POST selector the crawler saw act as a settings form"
    reason = credential_change_reason(form)
    if reason:
        return reason
    if password_fields(form) and not login_shaped(form):
        return "password form that is not a login form (settings, CAPTCHA or other)"
    reason = destructive_reason(form["action_url"])
    if reason:
        return f"destructive action ({reason!r})"
    return entries_refusal(form["entries"])


def _import_forms(src, store: Store, run_id: int, counts: dict,
                  main: str | None = None) -> None:
    """Crawled forms -> endpoint, `form` row (its default entry list) and one parameter
    per fuzzable field (FR-FUZZ-42). GET forms drop the action's query (a browser
    replaces it); POST forms keep it on the endpoint URL (reviewer A4).

    Each form is its own request context (FR-AUD-31, BUG-0530): its fields are rows of
    that form, never attached to a link's parameter of the same name. Its replay recipe
    (FR-FUZZ-67, BUG-0544): the page it was found on, and the fields `form_record`
    blanked (a CSRF token, any sensitive name), which the binder fetches fresh before
    each send; a password control stays empty by policy (FR-FUZZ-44, D12)."""
    try:
        rows = src.execute("SELECT page_url, action_url, method, enctype, entries, "
                           "controls, selector, options FROM discovered_forms "
                           "ORDER BY rowid").fetchall()
    except sqlite3.Error:
        return                                   # an older spider DB: no forms
    try:
        verdicts = dict(src.execute("SELECT sig, verdict FROM selector_verdicts").fetchall())
    except sqlite3.Error:
        verdicts = {}                            # a spider DB from before FR-CRAWL-10
    from fuzzlab.core.redaction import (is_sensitive_name, redact_url_identifiers,
                                        stored_value)
    from fuzzlab.tools.formnav import signature_key
    counts.setdefault("form", 0)
    counts.setdefault("form_skipped", 0)
    counts.setdefault("form_duplicate_selector", 0)
    seen_selectors: set[tuple] = set()
    for row in rows:
        form = {"action_url": row["action_url"], "method": row["method"] or "GET",
                "enctype": (row["enctype"] or "").lower(),
                "entries": [tuple(e) for e in json.loads(row["entries"] or "[]")],
                "controls": [tuple(c) for c in json.loads(row["controls"] or "[]")],
                "selector": bool(row["selector"]),
                "options": json.loads(row["options"] or "[]")}
        if form["selector"]:
            form["verdict"] = verdicts.get(signature_key(form))
        if form_skip_reason(form):
            counts["form_skipped"] += 1
            continue
        if form["selector"] and form["method"] == "POST":
            # a picker repeated on many pages (a site-wide header form) is fuzzed once,
            # at the first action crawled (forms phase 2, FR-FUZZ-43)
            same = (signature_key(form), tuple(sorted(n for n, _k in form["controls"])))
            if same in seen_selectors:
                counts["form_skipped"] += 1
                counts["form_duplicate_selector"] += 1
                continue
            seen_selectors.add(same)
        kinds = dict(form["controls"])
        filled = _filled(form["entries"], kinds)
        # every stored value through the owner's rule (BUG-0556): one that holds a
        # secret anywhere (an identifier, a token in a nested URL) is blanked and named
        # in the replay recipe; a password control stays empty by policy (FR-FUZZ-44)
        stored = [(name, value if kinds.get(name) == "password"
                   else stored_value(name, value, value)) for name, value in filled]
        path = store_url(form["action_url"], main)
        # the action's query, as the strongest URL redactor stores it (BUG-0556); a value
        # it redacts is recorded as a placeholder, never a blank, so its points are
        # refused and never send it (PA-0544(1)/(3); review round 1, RU-4)
        query = urlparse(redact_url_identifiers(form["action_url"],
                                                placeholder=True)).query
        url = path + ("?" + query if query and form["method"] == "POST" else "")
        endpoint_id = _upsert_endpoint(store, run_id, url, form["method"], "form")
        fresh = [name for (name, value), (_n, kept) in zip(filled, stored)
                 if kinds.get(name) != "password"
                 and (is_sensitive_name(name) or kept != value)]
        form_id = _insert_sibling_set(
            store, run_id, endpoint_id, form["enctype"], json.dumps(stored),
            source_page=_source_page(row["page_url"], main),
            fresh=fresh, password_fields=json.dumps(password_fields(form)))
        counts["form"] += 1
        location = "body" if form["method"] == "POST" else "query"
        for name, value in stored:
            kind = kinds.get(name)
            if (kind in ("submit", "password") or is_sensitive_name(name)
                    or (kind == "hidden" and _object_selector(name))):
                # a password control is never fuzzed, whatever its name (FR-FUZZ-44)
                continue
            _insert_parameter(store, run_id, endpoint_id, name, location, value, form_id,
                              counts)


def _import_route_query(store: Store, run_id: int, raw: str, source, counts: dict,
                        main: str | None = None) -> None:
    """A crawled SPA hash route's query (``/#/search?q=x``) -> ``fragment`` parameters
    on the route's endpoint (``/#/search``, `core.urls.to_route_path`). The app reads it
    in the browser, so it is a DOM point (confirmed only with a browser, M6), never a
    ``query`` one: the server never sees it (forms phase 3, FR-AUD-22)."""
    from fuzzlab.core.urls import spa_route
    route = spa_route(raw)
    if route is None or not route[1]:
        return
    counts.setdefault("fragment_parameter", 0)
    endpoint_id = _upsert_endpoint(store, run_id, store_url(raw, main, route=True), "GET",
                                   source)
    counts["endpoint"] += 1
    for name, raw, value in query_pairs(route[1]):
        # the example is a stored value: through the owner's rule (BUG-0556)
        if _insert_parameter(store, run_id, endpoint_id, name, "fragment",
                             redact_sibling(name, raw, value), None, counts):
            counts["fragment_parameter"] += 1


# --- captured requests (forms phase 3, lane J; FR-AUD-22) ------------------------------
#: Methods a captured request may have to be imported; any other (DELETE included) is
#: never imported.
REQUEST_METHODS = ("GET", "POST", "PUT", "PATCH")
#: Methods imported only with ``--fuzz-json-writes`` (each probe updates the row the
#: request targets; FR-FUZZ-47).
WRITE_METHODS = frozenset({"PUT", "PATCH"})
#: The ``form.enctype`` of a captured form-encoded request.
FORM_URLENCODED = "application/x-www-form-urlencoded"


def _body_kind(content_type) -> str | None:
    """``"json"``, ``"form"`` or None for a captured request's content type."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media == "application/json" or (media.startswith("application/")
                                        and media.endswith("+json")):
        return "json"
    if media == FORM_URLENCODED:
        return "form"
    return None


def redact_leaf(segments, value):
    """A captured body leaf as it may be stored and sent: blanked (a string ``""``, any
    other type ``null``) when any key of its path is sensitive or its value looks like
    an identifier, else ``value``. The JSON counterpart of `redact_sibling` (PA-0100,
    FR-AUD-22)."""
    from fuzzlab.core.redaction import redact_leaf as _one_leaf_rule
    return _one_leaf_rule(segments, value)      # forms phase 3 merge: one rule (PA-0003)


def _captured_leaves(kind: str, body):
    """``[(name, key segments, path or None, value)]`` of a captured body, or a refusal.
    A JSON body's leaves keep their paths; a form body's names are flat."""
    from fuzzlab.core import jsonbody
    if kind == "json":
        found = jsonbody.leaves(body)
        if found is None:
            return ("not a JSON object, or over the leaf/depth limits "
                    f"({jsonbody.MAX_LEAVES} leaves, depth {jsonbody.MAX_DEPTH})")
        return [(jsonbody.display_name(p), [s for s in p if isinstance(s, str)], p, v)
                for p, v in found]
    # a form body: the spider's object of strings, or the wire's ordered pairs (a disco
    # capture, a repeated name kept in order; FR-AUD-31)
    if isinstance(body, list) and all(isinstance(p, list) and len(p) == 2
                                      and all(isinstance(x, str) for x in p) for p in body):
        pairs = [(n, v) for n, v in body]
    elif isinstance(body, dict) and all(isinstance(v, str) for v in body.values()):
        pairs = list(body.items())
    else:
        return "a form body that is not an object of strings"
    if len(pairs) > jsonbody.MAX_LEAVES:
        return f"over {jsonbody.MAX_LEAVES} fields"
    return [(n, [n], None, v) for n, v in pairs]


def request_refusal(method: str, url: str, *, fuzz_json_writes: bool = False,
                    page_url: str | None = None) -> str | None:
    """Why a captured request is never imported, judged on its method and URL alone, or
    None (FR-AUD-22): a method outside GET/POST/PUT/PATCH (DELETE included); PUT/PATCH
    without ``fuzz_json_writes``; a destructive or transaction URL (the shared
    `core.urls` rules); a URL on another origin than the page that sent it."""
    from fuzzlab.core.urls import canonical_origin, destructive_reason, transaction_reason
    method = (method or "").upper()
    if method not in REQUEST_METHODS:
        return f"method {method or '(none)'} is never imported"
    if method in WRITE_METHODS and not fuzz_json_writes:
        return f"{method} imported only with --fuzz-json-writes"
    reason = destructive_reason(url)
    if reason is not None:
        return f"destructive URL ({reason!r})"
    reason = transaction_reason(url)
    if reason is not None:
        return f"transaction URL ({reason!r})"
    if page_url and "://" in (url or "") and "://" in page_url \
            and canonical_origin(url) != canonical_origin(page_url):
        return "a request to another origin than its page"
    return None


def body_refusal(url: str, leaves) -> str | None:
    """Why a captured body is never imported, or None (FR-AUD-22): a credential-change
    or account-management body (`credential_change_rule`, the one rule forms use), a
    settings field (`formnav.settings_word` on any key), or a destructive or credential
    entry (`entries_refusal`, credential names checked on every non-password leaf)."""
    from fuzzlab.core.redaction import is_credential_name
    from fuzzlab.tools.formnav import settings_word
    passwords = [name for name, segs, _p, _v in leaves
                 if any(is_credential_name(s) for s in segs)]
    reason = credential_change_rule(passwords, url, what="body", field="password field")
    if reason:
        return reason
    for name, segs, _p, _v in leaves:
        word = next((w for w in map(settings_word, segs) if w), None)
        if word:
            return f"settings field {name!r} ({word!r})"
    others = [(name, value if isinstance(value, str) else json.dumps(value))
              for name, segs, _p, value in leaves if name not in passwords]
    return (entries_refusal(others, credential_names=True)
            or entries_refusal([(name, "") for name in passwords]))


def _import_requests(src, store: Store, run_id: int, counts: dict, *,
                     fuzz_json_writes: bool = False, main: str | None = None) -> None:
    """The app's own captured requests (spider table ``discovered_requests``, lane I's
    contract) -> endpoint, `form` row and parameters (forms phase 3, FR-AUD-22).

    A JSON object body becomes a `form` row with ``enctype`` `core.jsonbody.ENCTYPE`,
    its entries the leaves as ``[[path segments], typed value]`` (`jsonbody.
    encode_entries`), and each string/number/bool leaf a ``json`` parameter named by
    `jsonbody.display_name`. A form-encoded body becomes today's form points (``body``).
    Never points: a password leaf (a credential name on any key; sent ``""`` and listed
    in `form.password_fields`, so the path is isolated, FR-FUZZ-44), a sensitive or
    identifier-like leaf (blanked, `redact_leaf`), and an object selector
    (`_object_selector` on the last key; sent as captured). Refused requests are counted
    (``request_refused``), never stored. An older spider DB has no such table."""
    try:
        rows = src.execute("SELECT * FROM discovered_requests ORDER BY id").fetchall()
    except sqlite3.Error:
        return                                   # a spider DB from before FR-CRAWL-13
    for key in ("request", "request_json", "request_form", "request_refused"):
        counts.setdefault(key, 0)
    bodies: dict = {}                                # identical stored bodies are one
    for row in rows:
        counts["request"] += 1
        reason, kind, leaves = captured_request(dict(row), fuzz_json_writes=fuzz_json_writes)
        if reason is not None:
            counts["request_refused"] += 1
            continue
        _store_request(store, run_id, counts, kind, row["method"].upper(), row["url"],
                       leaves, main=main, page=row["page_url"], bodies=bodies)


def captured_request(row: dict, *, fuzz_json_writes: bool = False):
    """``(refusal or None, body kind, leaves)`` for one ``discovered_requests`` row: the
    whole import decision, pure (FR-AUD-22). ``leaves`` is ``[(name, key segments,
    path or None, value)]`` when the request is accepted. A body with a field name or
    string value holding a lone surrogate (a JSON ``\\udXXX`` escape with no partner,
    which the capture stores losslessly) is refused: no store row can hold it
    (BUG-0554)."""
    from fuzzlab.core import jsonbody
    url = row.get("url") or ""
    kind = _body_kind(row.get("content_type"))
    reason = request_refusal(row.get("method") or "", url,
                             fuzz_json_writes=fuzz_json_writes,
                             page_url=row.get("page_url"))
    if reason is None and kind is None:
        reason = f"unsupported content type {row.get('content_type')!r}"
    if reason is not None:
        return reason, kind, None
    try:
        leaves = _captured_leaves(kind, jsonbody.loads(row.get("body_json") or ""))
    except (ValueError, TypeError, RecursionError):
        leaves = "a malformed body"
    if isinstance(leaves, str):
        return leaves, kind, None
    if not leaves:
        return "an empty body", kind, None
    if not all(_storable_text(name) and _storable_text(value)
               for name, _segs, _path, value in leaves):
        return "a field holding a lone surrogate (not storable text)", kind, None
    return body_refusal(url, leaves), kind, leaves


def _storable_text(value) -> bool:
    """False for a string SQLite cannot bind: one holding a surrogate code point (BUG-0554;
    `json.loads` decodes a lone ``\\udXXX`` escape to one). True for anything else."""
    if not isinstance(value, str):
        return True
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _store_request(store, run_id, counts, kind, method, url, leaves, *,
                   visible: frozenset = frozenset(), main: str | None = None,
                   page: str | None = None, bodies: dict | None = None) -> None:
    """Write one accepted captured request (`_import_requests`): every value passes
    `redact_leaf` before it is stored (PA-0100). ``visible`` names the controls a user
    could see in the form that sent it (a disco form step): an object selector among
    them is a point, as a crawled form's visible field is (`_import_forms`); unseen, it
    is pinned.

    Each captured body is its own request context (FR-AUD-31, BUG-0530): its points are
    rows of its own `form` row -- never "the first captured request's leaf wins a name".
    Identical stored bodies (endpoint, encoding, entries) are one (``bodies``). The
    row's replay recipe (FR-FUZZ-67): the page that sent it, and the leaves redaction
    blanked (never a password, sent empty by policy)."""
    from fuzzlab.core import jsonbody
    from fuzzlab.core.redaction import is_credential_name, is_sensitive_name
    passwords, entries, points, fresh = [], [], [], []
    for name, segs, path, value in leaves:
        if any(is_credential_name(s) for s in segs):
            passwords.append(name)
            stored = ""                          # a password is sent empty, never fuzzed
        else:
            stored = redact_leaf(segs, value)
            if stored != value:
                fresh.append(name)               # a placeholder (FR-FUZZ-67)
        entries.append((path if kind == "json" else name, stored))
        last = segs[-1] if segs else name
        pinned = (stored != value or any(is_sensitive_name(s) for s in segs)
                  or (_object_selector(last) and last not in visible))
        if name not in passwords and not pinned and jsonbody.is_point_value(value):
            points.append((name, value))
    # the URL's query as the strongest URL redactor stores it (BUG-0556): a disco
    # capture redacted names only; the spider's capture already passed it. A value it
    # redacts is recorded as a placeholder, never a blank, so the request's points are
    # refused and never send it (PA-0544(1)/(3); review round 1, RU-4)
    from fuzzlab.core.redaction import redact_url_identifiers
    parts = urlparse(redact_url_identifiers(url, placeholder=True))
    endpoint_url = store_url(url, main) + ("?" + parts.query if parts.query else "")
    endpoint_id = _upsert_endpoint(store, run_id, endpoint_url, method, "request")
    enctype = jsonbody.ENCTYPE if kind == "json" else FORM_URLENCODED
    stored_entries = (jsonbody.encode_entries(entries) if kind == "json"
                      else json.dumps(entries))
    counts["request_json" if kind == "json" else "request_form"] += 1
    bodies = {} if bodies is None else bodies
    key = (endpoint_id, enctype, stored_entries)
    form_id = bodies.get(key)
    if form_id is None:
        form_id = bodies[key] = _insert_sibling_set(
            store, run_id, endpoint_id, enctype, stored_entries,
            source_page=_source_page(page, main), fresh=fresh,
            password_fields=json.dumps(passwords))
    location = jsonbody.LOCATION if kind == "json" else "body"
    for name, value in points:
        example = value if isinstance(value, str) else json.dumps(value)
        _insert_parameter(store, run_id, endpoint_id, name, location, example, form_id,
                          counts)


def import_audit(audit_db: str | Path, store: Store, run_id: int, *,
                 base_url: str | None = None) -> dict[str, int]:
    """Import auditor findings -> candidate rows (with rule evidence).

    Every stored text passes the redaction owner (BUG-0556 review round 1, PA-0100): a
    finding's endpoint is `core.urls.store_url` of its page -- a path parameter that
    holds a secret dropped, and another origin kept -- in the form this run's spider
    rows already hold it (`_audit_endpoint`: the run's main origin is the spider's, not
    the first finding page's; review round 2, N3), else by the run's main origin
    (``base_url``'s, else the first finding page's); its ``target_identifier`` and
    ``html_context`` (stored as ``sink_context``) pass `_audit_text`.

    A finding page no origin can be read from (BUG-0556 r6 review, D1 and R4): the main
    origin is the first page's that `_readable_origin` reads; a page whose authority
    ``urlsplit`` rejects once `canonical_origin` reads it as a URL (``x[y/app/p.php``,
    ``h]/…``, ``\\u3000http://[h/…``) is stored by its path, as 7393c90's ``to_path``
    stored every finding page (so it can keep a userinfo or a JWT segment, as on
    7393c90: ``\\u3000http://u:<pw>@[h/app/p.php`` is stored
    ``/\\u3000http://u:<pw>@[h/app/p.php``).

    A page ``urlsplit`` rejects as written, where ``to_path`` rejects it too and
    7393c90's import raised, gets no endpoint (the candidate's ``parameter_id`` is NULL)
    and every non-NULL text of its finding is `AUDIT_TEXT_WITHHELD` (`_audit_text`), with
    or without a ``?`` (BUG-0556 r6 review, R4; the `?`-less page since the merge's
    follow-up: it failed the whole import before). A page stored as a BLOB is read as
    7393c90 read it (`_audit_endpoint`): one with an empty path (``b"http://h"``,
    ``b"x://"``) is stored ``/``, its texts never judged against it (as on 7393c90); one
    with a path (``TypeError`` in ``to_path``) or one ``urlsplit`` rejects fails the
    import, as on 7393c90 (pinned)."""
    src = sqlite3.connect(str(audit_db))
    src.row_factory = sqlite3.Row
    counts = {"candidate": 0}
    try:
        rows = src.execute(
            "SELECT page_url, category, transaction_type, target_identifier, "
            "html_context, occurrences, reference FROM findings"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    main = _main_origin(base_url, (r["page_url"] for r in rows),
                        origin_of=_readable_origin)
    for row in rows:
        page = row["page_url"]
        endpoint = _audit_endpoint(store, run_id, page, main, spider_form=not base_url)
        endpoint_id = (None if endpoint is None
                       else _upsert_endpoint(store, run_id, endpoint, "GET", "audit"))
        target = _audit_text(row["target_identifier"], page, url=True)
        # the legacy auditor names a parameter only: its first row of that name
        found = None if endpoint_id is None else store.conn.execute(
            "SELECT id FROM parameter WHERE run_id=? AND endpoint_id=? AND name=? "
            "ORDER BY id", (run_id, endpoint_id, target)).fetchone()
        param_id = int(found["id"]) if found else None
        evidence = {
            "category": row["category"],
            "transaction_type": row["transaction_type"],
            "target_identifier": target,
            "occurrences": row["occurrences"] if "occurrences" in row.keys() else 1,
            "reference": row["reference"] if "reference" in row.keys() else None,
        }
        store.conn.execute(
            "INSERT INTO candidate (run_id, parameter_id, rule, evidence, sink_context) "
            "VALUES (?,?,?,?,?)",
            (run_id, param_id, row["transaction_type"], json.dumps(evidence),
             _audit_text(row["html_context"], page)),
        )
        counts["candidate"] += 1
    store.conn.commit()
    src.close()
    return counts


def _readable_origin(url) -> str | None:
    """`canonical_origin` of a finding page, or ``None`` where it raises ``ValueError``
    (an authority ``urlsplit`` rejects once read as a URL: ``x[y/app/p.php``, to which
    `canonical_origin` prefixes ``http://``; ``http://[h/…``): such a page names no
    origin (BUG-0556 r6 review, D1). Or ``TypeError``: a page stored as a BLOB
    (``b"http://h"``), which 7393c90's ``to_path`` imported where its path is empty and
    the batch's import refused (``TypeError`` in `canonical_origin`; BUG-0556, at the
    merge, D1(b))."""
    try:
        return canonical_origin(url)
    except (ValueError, TypeError):
        return None


def _audit_endpoint(store: Store, run_id: int, page: str, main: str | None, *,
                    spider_form: bool) -> str | None:
    """A legacy-auditor finding page's endpoint as this run's spider rows hold the same
    page (review round 2, N3): `import_spider` and `import_audit` each took the run's
    main origin from their own first row (the seed; the first page with a finding), so
    an off-origin first finding stored the main origin's pages absolute, beside the
    spider's paths. ``store_url`` gives a page on another origin absolute only, so the
    spider's absolute form names a page off the main origin and its path form one on it.
    With neither stored, or without ``spider_form`` (the caller was given the operator's
    base URL, whose origin is the main one), the run's ``main`` decides.

    A page no origin can be read from (`_readable_origin` is ``None`` because
    `canonical_origin` raised ``ValueError``: BUG-0556 r6 review, D1) is stored by its
    path, as ``store_url`` stores a URL whose origin is unknown and as 7393c90's
    ``to_path`` stored every finding page (a ``;`` path parameter holding a secret
    dropped, `core.redaction.strip_secret_path_params`; nothing else of the path is
    judged, so a userinfo or a JWT segment the page holds is kept, as on 7393c90): r6's
    import raised there, 7393c90's did not. ``None`` -- no endpoint -- where the page's
    path cannot be read either (``to_path`` raises ``ValueError``: ``http://[h/…``,
    ``//[h/…``; 7393c90's import raised there).

    A page stored as a BLOB (`canonical_origin` raises ``TypeError``; at the merge,
    D1(b)) is read by ``to_path`` exactly as 7393c90 read it, nothing it raises caught:
    one with an empty path (``b"http://h"``) is stored ``/``, and one with a path
    (``TypeError``) or one ``urlsplit`` rejects (``ValueError``) fails the import, as
    7393c90's did (pinned). The batch's import raised ``TypeError`` (in
    `canonical_origin`) on each of them but ``b""``."""
    from fuzzlab.core.redaction import strip_secret_path_params
    from fuzzlab.core.urls import to_path
    try:
        origin = canonical_origin(page)
    except TypeError:                   # a BLOB page: 7393c90's reading, whatever it raises
        return strip_secret_path_params(to_path(page))
    except ValueError:
        try:
            return strip_secret_path_params(to_path(page))
        except ValueError:
            return None
    try:
        if spider_form and origin is not None:
            path = store_url(page, origin)
            for stored in (origin + path, path):
                if store.conn.execute(
                        "SELECT 1 FROM page WHERE run_id=? AND url=? UNION ALL "
                        "SELECT 1 FROM endpoint WHERE run_id=? AND url=? AND source != "
                        "'audit' LIMIT 1", (run_id, stored, run_id, stored)).fetchone():
                    return stored
        return store_url(page, main)
    except ValueError:                  # its path is unreadable (``//[h/x``: no origin)
        return None


#: A run of a secret value this long or longer that a finding's text holds is the
#: value's: replaced, wherever and however long the rule cut it (`_secret_spans`).
_AUDIT_RUN = 8

#: What `_audit_text` stores for a text the redaction owner cannot judge: a text of a
#: str page ``urlsplit`` rejects (the floor raises on one that holds a ``?``, as the pushed
#: tree's redactor did, BUG-0556 r6, A1; ``urlparse`` on one without, the merge's
#: follow-up), or a target URL the floor rejects. Withheld whole, as `core.trace.safe_ref`
#: withholds such a URL, and the import goes on.
AUDIT_TEXT_WITHHELD = "(unparseable URL withheld)"


def _secret_spans(text: str, secrets: list[str]) -> list[tuple[int, int]]:
    """The spans of ``text`` that repeat a run of `_AUDIT_RUN` or more characters of any
    of ``secrets``: every window of that length found in a secret value is marked, and
    overlapping windows join (review round 2, N3: the legacy rules quote a value's
    substring -- ``rule_serialized_tokens``'s ``match.group(0)[:60]``, a JWT behind
    ``Bearer `` -- not only a prefix at a known cut). Linear in the text and the values
    (a set of fixed-length windows), never a search per cut."""
    k = _AUDIT_RUN
    grams = {s[i:i + k] for s in secrets for i in range(len(s) - k + 1)}
    spans: list[tuple[int, int]] = []
    if not grams:
        return spans
    for i in range(len(text) - k + 1):
        if text[i:i + k] in grams:
            if spans and spans[-1][1] >= i:
                spans[-1] = (spans[-1][0], i + k)
            else:
                spans.append((i, i + k))
    return spans


def _audit_text(text, page_url, *, url: bool = False):
    """A legacy-auditor finding's text as it may be stored (BUG-0556 review rounds 1-2,
    PA-0100, D12). Its rules quote the finding page's URL (``called from <url>``), its
    path (``<path>?<name>``, ``linked from <path>``) and its query values: whole, cut to
    a prefix, or a substring a pattern matched (``rule_serialized_tokens``). Each is
    replaced where it appears: the page URL by `core.redaction.redact_url_identifiers`'
    form of it, the path by `core.redaction.strip_secret_path_params`' form, and every
    query value the owner's rule would not store -- judged **whole**
    (`core.redaction.stored_value`: a sensitive name, or a value that holds a secret
    anywhere, nested included) -- by `PLACEHOLDER` wherever the text repeats it whole or
    any run of it `_AUDIT_RUN` characters or longer (`_secret_spans`; never by matching
    the rules' cut lengths, review round 2, N3). A ``url`` text (the target identifier,
    which may name another URL: a form action, a link) also passes
    `strip_secret_path_params` and `redact_url_identifiers` itself. The rest of a quoted
    HTML snippet is body redaction's (audit defect 26). A text of a str page ``urlsplit``
    rejects -- the floor, the pushed tree's redactor, raises on one that holds a ``?``,
    and ``urlparse`` on one without -- is `AUDIT_TEXT_WITHHELD`, never stored, whatever
    its type, a BLOB too, and a NULL stays NULL (BUG-0556 r6, A1; the merge's check, P2;
    the follow-up's check, which made the `?`-less page withheld too: it failed the whole
    import before, as 7393c90's ``to_path`` did). Otherwise a non-string is returned as
    it is, and a text of a page stored as a BLOB is judged against nothing of that page
    (as on 7393c90, which judged no text)."""
    import re

    from fuzzlab.core.redaction import (PLACEHOLDER, redact_url_identifiers, stored_value,
                                        strip_secret_path_params)
    clean = parts = None
    if isinstance(page_url, str):
        try:
            clean = redact_url_identifiers(page_url)
            # a page `urlsplit` rejects without a `?` passes the floor unread: it raises here
            parts = urlparse(page_url)
        except ValueError:                  # a page `urlsplit` rejects (A1, R4): withheld,
            # whatever the text's type -- a BLOB too (the merge's check, P2); NULL stays NULL
            return text if text is None else AUDIT_TEXT_WITHHELD
    if not isinstance(text, str):
        return text
    swaps: dict[str, str] = {}
    secrets: list[str] = []
    if isinstance(page_url, str):
        if clean != page_url:
            swaps[page_url] = clean
        path = parts.path.lstrip("/")                     # as the auditor's page sees it
        if strip_secret_path_params(path) != path:
            swaps[path] = strip_secret_path_params(path)
        for part in parts.query.split("&"):
            name, _eq, rawest = part.partition("=")
            name, raw, value = unquote_plus(name), unquote(rawest), unquote_plus(rawest)
            if not value or stored_value(name, raw, value) != "":
                continue
            # the whole value, in every spelling a rule may quote it in (as crawled,
            # percent-decoded, form-decoded as `parse_qsl` gives the rules)
            for whole in {rawest, raw, value}:
                if whole:
                    swaps.setdefault(whole, PLACEHOLDER)
                    secrets.append(whole)
    out = text
    if swaps:
        # longest first, each a whole run (never inside a longer word)
        alternation = "|".join(re.escape(k) for k in sorted(swaps, key=len, reverse=True))
        out = re.sub(f"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])",
                     lambda m: swaps[m.group(0)], out)
    if secrets:
        pieces, last = [], 0
        for start, end in _secret_spans(out, secrets):
            pieces += [out[last:start], PLACEHOLDER]
            last = end
        out = "".join(pieces + [out[last:]])
    if url:
        cut = min([i for i in (out.find("?"), out.find("#")) if i >= 0] or [len(out)])
        try:
            out = redact_url_identifiers(strip_secret_path_params(out[:cut]) + out[cut:])
        except ValueError:                  # the owner's floor rejects it (A1): withheld
            return AUDIT_TEXT_WITHHELD
    return out


def import_fuzz_csv(csv_path: str | Path, store: Store, run_id: int) -> dict[str, int]:
    """Import fuzzer observations -> `attempt` rows only.

    Findings are no longer written here: the deterministic oracle
    (`fuzzlab/oracle/`) is the sole writer of `finding` labels, replacing the
    earlier provisional timing-only findings. The attempt's `reward` still records
    the fuzzer's timing detection (screening signal) for later ML.
    """
    counts = {"attempt": 0}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            detected = str(row.get("time_delay_detected", "0")).strip() in ("1", "true", "True")
            features = {
                # this writer's own schema (BUG-0069 sweep, CC-FUZZ-0055): fuzz-CSV
                # telemetry, not the core extractor's vector — feature_version stays NULL
                "_schema": "fuzz-csv/1",
                "server_response_status": _to_int(row.get("server_response_status")),
                "server_response_length": _to_int(row.get("server_response_length")),
                "observed_latency_seconds": _to_float(row.get("observed_latency_seconds")),
                "latency_delta_seconds": _to_float(row.get("latency_delta_seconds")),
                "size_delta_bytes": _to_int(row.get("size_delta_bytes")),
                "repeats": _to_int(row.get("repeats")),
            }
            store.conn.execute(
                "INSERT INTO attempt (run_id, payload_family, features_json, reward) "
                "VALUES (?,?,?,?)",
                (run_id, row.get("payload_family"), json.dumps(features),
                 1.0 if detected else 0.0),
            )
            counts["attempt"] += 1
    store.conn.commit()
    return counts


def _to_int(value) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
