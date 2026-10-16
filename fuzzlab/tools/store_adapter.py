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
from fuzzlab.core.urls import to_path


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


def _get_parameter(store: Store, run_id: int, endpoint_id: int, name: str) -> int | None:
    row = store.conn.execute(
        "SELECT id FROM parameter WHERE run_id=? AND endpoint_id=? AND name=?",
        (run_id, endpoint_id, name),
    ).fetchone()
    return int(row["id"]) if row else None


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
    name is sensitive or its raw value looks like an identifier (a token, an id), else
    ``value`` (forms phase 2, FR-FUZZ-43; PA-0100)."""
    from fuzzlab.core.redaction import is_sensitive_name, looks_like_identifier
    if is_sensitive_name(name) or looks_like_identifier(raw_value):
        return ""
    return value


def entries_refusal(entries, *, credential_names: bool = False,
                    destructive: bool = True) -> str | None:
    """Why an entry list must never be sent as siblings, or None: any name or value
    tokenises destructive (with ``destructive``; D72: False for what is sent as a GET,
    a link set or a GET form); with ``credential_names``, any name carries a credential
    token. The one check for forms and link sets (PA-0003)."""
    from fuzzlab.core import sendpolicy
    from fuzzlab.core.redaction import is_credential_name
    from fuzzlab.core.urls import text_destructive_reason
    for name, value in entries:
        for text in (name, value) if destructive else ():
            reason = sendpolicy.destructive(text_destructive_reason(text))   # BUG-0131
            if reason:
                return f"destructive entry {name}={value!r} ({reason!r})"
        if credential_names and is_credential_name(name):
            return f"credential entry {name!r}"
    return None


def import_spider(spider_db: str | Path, store: Store, run_id: int, *,
                  fuzz_json_writes: bool = False) -> dict[str, int]:
    """Import discovered pages -> page/endpoint/parameter rows, crawled forms, each
    query-bearing URL's query as a link set (forms phase 2), each SPA hash route's query
    as ``fragment`` parameters, and the app's own captured requests (forms phase 3,
    FR-AUD-22; PUT/PATCH only with ``fuzz_json_writes``). A SPA query seed that blocked
    a write (``source = 'spa-query-writes'``, FR-CRAWL-17) is a page only: no endpoint,
    parameter or link set comes from it (counted ``write_seed_skipped``)."""
    src = sqlite3.connect(str(spider_db))
    src.row_factory = sqlite3.Row
    counts = {"page": 0, "endpoint": 0, "parameter": 0}
    seen_pages: set[tuple[str, str]] = set()
    link_sets: list[tuple[int, list[tuple[str, str, str]]]] = []
    try:
        # crawl order is the tie-break: the first crawled link wins (FR-FUZZ-43)
        rows = src.execute(
            "SELECT url, status_code, source FROM discovered_pages ORDER BY rowid"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    for row in rows:
        raw = row["url"]
        path = to_path(raw)
        source = row["source"] if "source" in row.keys() else "link"
        if (path, "GET") not in seen_pages:
            store.conn.execute(
                "INSERT OR IGNORE INTO page (run_id, url, method, status, source) "
                "VALUES (?,?,?,?,?)",
                (run_id, path, "GET", row["status_code"], source),
            )
            seen_pages.add((path, "GET"))
            counts["page"] += 1
        if source == _write_seed_source():
            # a SPA query seed whose load blocked a write (FR-CRAWL-17, review A-M1): a
            # page, never a point -- an M6 load of it would send that write unguarded
            counts["write_seed_skipped"] = counts.get("write_seed_skipped", 0) + 1
            continue
        # blank values are parameters too (`?title=`), forms phase 1
        query = parse_qsl(urlparse(raw).query, keep_blank_values=True)
        if query:
            endpoint_id = _upsert_endpoint(store, run_id, path, "GET", source)
            counts["endpoint"] += 1
            for name, value in query:
                if _get_parameter(store, run_id, endpoint_id, name) is None:
                    store.conn.execute(
                        "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
                        "VALUES (?,?,?,?,?)",
                        (run_id, endpoint_id, name, "query", value),
                    )
                    counts["parameter"] += 1
            link_sets.append((endpoint_id, query_pairs(urlparse(raw).query)))
        _import_route_query(store, run_id, raw, source, counts)
    _import_forms(src, store, run_id, counts)
    _import_requests(src, store, run_id, counts, fuzz_json_writes=fuzz_json_writes)
    _import_link_sets(store, run_id, link_sets, counts)   # after forms: forms win
    store.conn.commit()
    src.close()
    return counts


def _write_seed_source() -> str:
    from fuzzlab.tools.spa import WRITE_SEED_SOURCE        # the one definition (PA-0003)
    return WRITE_SEED_SOURCE


def _import_link_sets(store: Store, run_id: int, link_sets, counts: dict) -> None:
    """Each crawled link's query becomes a `form` row with ``enctype`` NULL
    (`core.forms.LINK_SET_ENCTYPE`): its values pass `redact_sibling`, and a set with a
    credential entry is refused (not stored; D72: a destructive word no longer refuses
    one, it is sent with GET probes). A set with two or more
    names is bound to its parameters that no form already binds, the first crawled
    link winning; a one-name set is kept only as the page's representative query for
    header points (FR-FUZZ-43)."""
    counts.setdefault("link_set", 0)
    counts.setdefault("link_set_refused", 0)
    counts.setdefault("link_set_bound", 0)
    stored_ids: dict[tuple[int, str], int] = {}
    for endpoint_id, pairs in link_sets:
        # D72: a link set is sent with GET probes (a visit): no destructive-word rule,
        # the credential-name rule kept
        if entries_refusal([(n, v) for n, _r, v in pairs], credential_names=True,
                           destructive=False):
            counts["link_set_refused"] += 1
            continue
        entries = [(name, redact_sibling(name, raw, value)) for name, raw, value in pairs]
        key = (endpoint_id, json.dumps(entries))
        form_id = stored_ids.get(key)
        if form_id is None:
            cur = store.conn.execute(
                "INSERT INTO form (run_id, endpoint_id, enctype, entries) VALUES (?,?,?,?)",
                (run_id, endpoint_id, LINK_SET_ENCTYPE, key[1]))
            form_id = stored_ids[key] = int(cur.lastrowid)
            counts["link_set"] += 1
        names = list(dict.fromkeys(name for name, _v in entries))
        if len(names) < 2:
            continue
        for name in names:
            cur = store.conn.execute(
                "UPDATE parameter SET form_id=? WHERE run_id=? AND endpoint_id=? AND "
                "name=? AND form_id IS NULL", (form_id, run_id, endpoint_id, name))
            counts["link_set_bound"] += cur.rowcount


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
    skipped when submitting it could change a credential, an account, or -- a POST form
    only since D72 -- something destructive (forms phase 1, reviewers A/B). A form with a password control is
    imported only when it is an in-app login form; its points are then probed on an
    isolated session, never the run's (FR-FUZZ-44).

    A **POST selector** form (one ``<select>`` and buttons) is fuzzed since forms phase
    2 (FR-FUZZ-43) unless a control name carries a settings word
    (`formnav.settings_word`), its select name is too short to judge, or the crawler
    saw it act as a settings form (``form["verdict"]``, FR-CRAWL-10). GET selector
    forms are not subject to that rule (GET is safe)."""
    from fuzzlab.core import sendpolicy
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
    credentials = sendpolicy.enforced(sendpolicy.CREDENTIAL_CHANGES)    # D71
    reason = credential_change_reason(form) if credentials else None
    if reason:
        return reason
    if credentials and password_fields(form) and not login_shaped(form):
        return "password form that is not a login form (settings, registration or other)"
    # D72: a GET form is sent as a GET (a visit): no destructive-word rule on its
    # action or entries; a POST form keeps both (a write)
    write = (form.get("method") or "GET").upper() != "GET"
    reason = sendpolicy.destructive(destructive_reason(form["action_url"])) if write \
        else None
    if reason:
        return f"destructive action ({reason!r})"
    return entries_refusal(form["entries"], destructive=write)


def _import_forms(src, store: Store, run_id: int, counts: dict) -> None:
    """Crawled forms -> endpoint, `form` row (its default entry list) and one parameter
    per fuzzable field (FR-FUZZ-42). GET forms drop the action's query (a browser
    replaces it); POST forms keep it on the endpoint URL (reviewer A4)."""
    try:
        rows = src.execute("SELECT action_url, method, enctype, entries, controls, "
                           "selector, options FROM discovered_forms ORDER BY rowid").fetchall()
    except sqlite3.Error:
        return                                   # an older spider DB: no forms
    try:
        verdicts = dict(src.execute("SELECT sig, verdict FROM selector_verdicts").fetchall())
    except sqlite3.Error:
        verdicts = {}                            # a spider DB from before FR-CRAWL-10
    from fuzzlab.core.redaction import is_sensitive_name
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
        form["entries"] = _filled(form["entries"], kinds)
        path = to_path(form["action_url"])
        query = urlparse(form["action_url"]).query
        url = path + ("?" + query if query and form["method"] == "POST" else "")
        endpoint_id = _upsert_endpoint(store, run_id, url, form["method"], "form")
        cur = store.conn.execute(
            "INSERT INTO form (run_id, endpoint_id, enctype, entries, password_fields) "
            "VALUES (?,?,?,?,?)",
            (run_id, endpoint_id, form["enctype"], json.dumps(form["entries"]),
             json.dumps(password_fields(form))))
        form_id = int(cur.lastrowid)
        counts["form"] += 1
        location = "body" if form["method"] == "POST" else "query"
        for name, value in form["entries"]:
            kind = kinds.get(name)
            if (kind in ("submit", "password") or is_sensitive_name(name)
                    or (kind == "hidden" and _object_selector(name))):
                # a password control is never fuzzed, whatever its name (FR-FUZZ-44)
                continue
            existing = _get_parameter(store, run_id, endpoint_id, name)
            if existing is not None:
                # a link already gave this parameter: attach the form's siblings to it
                store.conn.execute("UPDATE parameter SET form_id=? WHERE id=? AND "
                                   "form_id IS NULL", (form_id, existing))
                continue
            store.conn.execute(
                "INSERT INTO parameter (run_id, endpoint_id, name, location, example, "
                "form_id) VALUES (?,?,?,?,?,?)",
                (run_id, endpoint_id, name, location, value, form_id))
            counts["parameter"] += 1


def _import_route_query(store: Store, run_id: int, raw: str, source, counts: dict) -> None:
    """A crawled SPA hash route's query (``/#/search?q=x``) -> ``fragment`` parameters
    on the route's endpoint (``/#/search``, `core.urls.to_route_path`). The app reads it
    in the browser, so it is a DOM point (confirmed only with a browser, M6), never a
    ``query`` one: the server never sees it (forms phase 3, FR-AUD-22)."""
    from fuzzlab.core.urls import spa_route, to_route_path
    route = spa_route(raw)
    if route is None or not route[1]:
        return
    counts.setdefault("fragment_parameter", 0)
    endpoint_id = _upsert_endpoint(store, run_id, to_route_path(raw), "GET", source)
    counts["endpoint"] += 1
    for name, value in parse_qsl(route[1], keep_blank_values=True):
        if _get_parameter(store, run_id, endpoint_id, name) is None:
            store.conn.execute(
                "INSERT INTO parameter (run_id, endpoint_id, name, location, example) "
                "VALUES (?,?,?,?,?)", (run_id, endpoint_id, name, "fragment", value))
            counts["parameter"] += 1
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
    if not isinstance(body, dict) or not all(isinstance(v, str) for v in body.values()):
        return "a form body that is not an object of strings"
    if len(body) > jsonbody.MAX_LEAVES:
        return f"over {jsonbody.MAX_LEAVES} fields"
    return [(n, [n], None, v) for n, v in body.items()]


def request_refusal(method: str, url: str, *, fuzz_json_writes: bool = False,
                    page_url: str | None = None) -> str | None:
    """Why a captured request is never imported, judged on its method and URL alone, or
    None (FR-AUD-22): a method outside GET/POST/PUT/PATCH (DELETE included); PUT/PATCH
    without ``fuzz_json_writes``; a destructive or transaction URL (the shared
    `core.urls` rules); a URL on another origin than the page that sent it."""
    from fuzzlab.core import sendpolicy
    from fuzzlab.core.urls import canonical_origin, destructive_reason, transaction_reason
    method = (method or "").upper()
    if method not in REQUEST_METHODS:
        return f"method {method or '(none)'} is never imported"
    if method in WRITE_METHODS and not fuzz_json_writes:
        return f"{method} imported only with --fuzz-json-writes"
    reason = sendpolicy.destructive(destructive_reason(url))
    if reason is not None:
        return f"destructive URL ({reason!r})"
    reason = sendpolicy.transaction(transaction_reason(url))
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
    from fuzzlab.core import sendpolicy
    from fuzzlab.core.redaction import is_credential_name
    from fuzzlab.tools.formnav import settings_word
    passwords = [name for name, segs, _p, _v in leaves
                 if any(is_credential_name(s) for s in segs)]
    reason = sendpolicy.credential_change(
        credential_change_rule(passwords, url, what="body", field="password field"))
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
                     fuzz_json_writes: bool = False) -> None:
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
    (``request_refused``), never stored. A row with source ``blocked`` (a write the
    crawl's window refused and recorded unsent, CC-CRAWL-0036) passes the same rules and
    is also counted ``request_blocked``. An older spider DB has no such table."""
    try:
        rows = src.execute("SELECT * FROM discovered_requests ORDER BY id").fetchall()
    except sqlite3.Error:
        return                                   # a spider DB from before FR-CRAWL-13
    for key in ("request", "request_json", "request_form", "request_refused",
                "request_blocked"):
        counts.setdefault(key, 0)
    for row in rows:
        counts["request"] += 1
        reason, kind, leaves = captured_request(dict(row), fuzz_json_writes=fuzz_json_writes)
        if reason is not None:
            counts["request_refused"] += 1
            continue
        if "source" in row.keys() and row["source"] == "blocked":
            # CC-CRAWL-0036: a write the crawl's window refused, recorded unsent; the
            # same rules decide (above), counted on its own
            counts["request_blocked"] += 1
        _store_request(store, run_id, counts, kind, row["method"].upper(), row["url"],
                       leaves)


def captured_request(row: dict, *, fuzz_json_writes: bool = False):
    """``(refusal or None, body kind, leaves)`` for one ``discovered_requests`` row: the
    whole import decision, pure (FR-AUD-22). ``leaves`` is ``[(name, key segments,
    path or None, value)]`` when the request is accepted."""
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
    return body_refusal(url, leaves), kind, leaves


def _store_request(store, run_id, counts, kind, method, url, leaves) -> None:
    """Write one accepted captured request (`_import_requests`): every value passes
    `redact_leaf` before it is stored (PA-0100)."""
    from fuzzlab.core import jsonbody
    from fuzzlab.core.redaction import is_credential_name, is_sensitive_name
    passwords, entries, points = [], [], []
    for name, segs, path, value in leaves:
        if any(is_credential_name(s) for s in segs):
            passwords.append(name)
            stored = ""                          # a password is sent empty, never fuzzed
        else:
            stored = redact_leaf(segs, value)
        entries.append((path if kind == "json" else name, stored))
        pinned = (stored != value or any(is_sensitive_name(s) for s in segs)
                  or _object_selector(segs[-1] if segs else name))
        if name not in passwords and not pinned and jsonbody.is_point_value(value):
            points.append((name, value))
    parts = urlparse(url)
    endpoint_url = to_path(url) + ("?" + parts.query if parts.query else "")
    endpoint_id = _upsert_endpoint(store, run_id, endpoint_url, method, "request")
    enctype = jsonbody.ENCTYPE if kind == "json" else FORM_URLENCODED
    cur = store.conn.execute(
        "INSERT INTO form (run_id, endpoint_id, enctype, entries, password_fields) "
        "VALUES (?,?,?,?,?)",
        (run_id, endpoint_id, enctype,
         jsonbody.encode_entries(entries) if kind == "json" else json.dumps(entries),
         json.dumps(passwords)))
    form_id = int(cur.lastrowid)
    counts["request_json" if kind == "json" else "request_form"] += 1
    location = jsonbody.LOCATION if kind == "json" else "body"
    for name, value in points:
        if _get_parameter(store, run_id, endpoint_id, name) is not None:
            continue                             # the first captured request wins
        example = value if isinstance(value, str) else json.dumps(value)
        store.conn.execute(
            "INSERT INTO parameter (run_id, endpoint_id, name, location, example, "
            "form_id) VALUES (?,?,?,?,?,?)",
            (run_id, endpoint_id, name, location, example, form_id))
        counts["parameter"] += 1


def import_audit(audit_db: str | Path, store: Store, run_id: int) -> dict[str, int]:
    """Import auditor findings -> candidate rows (with rule evidence)."""
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
    for row in rows:
        path = to_path(row["page_url"])
        endpoint_id = _upsert_endpoint(store, run_id, path, "GET", "audit")
        param_id = _get_parameter(store, run_id, endpoint_id, row["target_identifier"])
        evidence = {
            "category": row["category"],
            "transaction_type": row["transaction_type"],
            "target_identifier": row["target_identifier"],
            "occurrences": row["occurrences"] if "occurrences" in row.keys() else 1,
            "reference": row["reference"] if "reference" in row.keys() else None,
        }
        store.conn.execute(
            "INSERT INTO candidate (run_id, parameter_id, rule, evidence, sink_context) "
            "VALUES (?,?,?,?,?)",
            (run_id, param_id, row["transaction_type"], json.dumps(evidence),
             row["html_context"]),
        )
        counts["candidate"] += 1
    store.conn.commit()
    src.close()
    return counts


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
