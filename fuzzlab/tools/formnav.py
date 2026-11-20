"""Selector-form navigation for the crawler (FR-CRAWL-8, forms phase 1).

Some apps reach their pages only through a menu-like form: one ``<select>`` and a
button (bWAPP's "choose your bug" pickers POST a select and answer with a redirect).
A link-only crawler never sees those pages. This module decides which such forms may
be submitted, and with which options, and turns their redirects into links to crawl.

Submitting a form can change state, so the gate comes **before** any submission
(reviewers A/B):

* off unless the operator asks (``--follow-selector-forms``);
* a GET selector form may be enumerated (GET is safe); a POST one only when the
  operator **names its select** (``--follow-selector-forms bug``);
* a form whose select, control or submitter **name** is a settings word, or whose
  action is out of scope or destructive, is never submitted; an **option** whose value
  or label is a settings word or destructive is skipped;
* every response must be a cookie-less 3xx to an in-scope, non-destructive URL, or
  enumeration of that form stops; a redirect back to the form's own page or action is
  skipped, and five of those in a row mark a settings form (stop);
* submissions go through an isolated client (the caller's ``submit``), so a response
  cookie never reaches the crawler.

The HTTP itself is the caller's ``submit(method, action_url, entries) -> (status,
headers)``; this module is pure and testable.
"""

from __future__ import annotations

import logging
from typing import Callable
from urllib.parse import urljoin, urlsplit

from fuzzlab.core.forms import FormEntries
from fuzzlab.core.redaction import name_tokens
from fuzzlab.core.urls import destructive_reason, text_destructive_reason, url_key

#: A select or control named with one of these words configures something. Shared by
#: navigation (`refusal`, `option_refusal`), the importer's POST-selector rule (forms
#: phase 2, FR-CRAWL-10 / FR-FUZZ-43), the captured-body rule (FR-AUD-22) and the SPA
#: form and label gates. The gate is safety-direction (a word removed means more
#: submissions of forms that may change server state), so a word stays only with a
#: public specification, vendor documentation or two independent apps naming it as a
#: persistent setting (PA-0660(2); FR-CRAWL-680, CC-CRAWL-0680 holds the full record).
#: No word is kept or added because one lab's recall needed it. ``t`` is deliberately
#: absent: a lone ``t`` token comes from contractions ("Don't").
SETTINGS_WORDS = frozenset({
    # Security / logging level. Spring Boot Actuator ``loggers`` endpoint (a POST of
    # ``configuredLevel`` changes the level); GitLab Members API ``access_level``; the
    # security-level pickers of independent deliberately vulnerable training apps.
    "level",
    # Security-level pickers of independent training apps (a select named
    # ``security``, and ones whose name holds ``security`` and ``level``);
    # OWASP WSTG 4.2 WSTG-CONF (security configuration).
    "security",
    # Authorisation. OWASP Mass Assignment Cheat Sheet (``isAdmin``-style fields);
    # OWASP API Security Top 10 2023 API5 (BFLA, admin functions); GitHub REST
    # "Add a repository collaborator" (``permission``: pull/push/admin).
    "role", "permission", "permissions", "admin",
    # Publication / account state. WordPress REST API posts ``status``; Drupal core
    # node base field ``status``; Django ``User.is_active``; GitHub REST webhooks
    # ``active``.
    "status", "active",
    # Toggles. GitHub REST Actions "Enable/Disable a workflow" endpoints; Jenkins
    # remote access API ``/job/<name>/enable`` and ``/disable``.
    "enable", "disable",
    # Locale. WHATWG HTML autofill field name ``language`` and the ``lang`` global
    # attribute (BCP 47); RFC 9110 §12.5.4 Accept-Language; Django ``set_language``
    # view (a POST of ``language``); Shopify localization form (``language_code``);
    # Spring ``LocaleChangeInterceptor`` (default parameter ``locale``); Rails I18n
    # guide, "Setting the Locale from URL Params" (``params[:locale]``).
    "lang", "language", "locale",
    # Appearance. Spring ``ThemeChangeInterceptor`` (default parameter ``theme``);
    # Bootstrap 5.3 colour modes (``data-bs-theme``, a stored preference).
    "theme",
    # Time zone. RFC 6557 (the IANA "tz" database); Django time-zone docs, "Selecting
    # the current time zone" (a POST of ``timezone``); Rails ``time_zone_select``
    # (``time_zone``, in `SETTINGS_PAIRS`).
    "tz", "timezone",
    # Region and money. WHATWG HTML autofill ``country`` and ``transaction-currency``
    # (ISO 3166 / ISO 4217); Shopify localization form (``country_code``) and cart
    # ``currency``.
    "currency", "country",
    # A stored default. Shopify Admin API "set a default address"
    # (``.../addresses/<id>/default``); Stripe ``default_payment_method``.
    "default",
    # Notification preferences. WordPress options ``comments_notify`` /
    # ``moderation_notify``; Jira REST "Edit issue" ``notifyUsers``.
    "notify",
    # Privacy. YouTube Data API ``status.privacyStatus``; Vimeo API ``privacy.view``;
    # GitHub REST and GitLab Projects API ``visibility`` (public/private/internal).
    "privacy", "visibility",
})
# Removed by FR-CRAWL-680 (no independent source names them a stored setting; the
# record is CC-CRAWL-0680): ``sort`` and the pair ``per page`` (read-only list
# modifiers: JSON:API 1.1 "Sorting", GitHub REST "Using pagination", WordPress REST
# ``orderby`` / ``per_page``; ORDER BY is an injection point, OWASP WSTG-INPV-05),
# ``view`` (a navigation parameter, as in Joomla's ``view=article``), ``display``,
# ``layout``, ``skin``, ``region``, ``mode``. A picker that acts as a setting is
# still caught by its behaviour (`enumerate_form`'s cookie / self-redirect verdict).
#: Adjacent tokens that together are a settings word. Rails ``time_zone_select``
#: (``time_zone`` tokenises to ``time``, ``zone``; neither alone counts).
SETTINGS_PAIRS = frozenset({("time", "zone")})
#: IANA tz database areas (tzdata ``Theory``: names are ``Area/Location``, the area a
#: continent or ocean, or ``Etc``): a select whose every option is one picks a time
#: zone, whatever its name.
TZ_AREAS = frozenset({"africa", "america", "antarctica", "arctic", "asia", "atlantic",
                      "australia", "europe", "indian", "pacific", "etc"})
#: This many self-redirects in a row, before any real navigation: a settings form.
MAX_SELF_REDIRECTS = 5
#: At most this many options of one form are submitted.
MAX_OPTIONS = 500


def settings_word(text: str) -> str | None:
    """The settings word (or pair, as ``per_page``) in a control name, option value
    or label, matched by whole token; None when there is none."""
    toks = [t.lower() for t in name_tokens(text or "")]
    for tok in toks:
        if tok in SETTINGS_WORDS:
            return tok
    for pair in zip(toks, toks[1:]):
        if pair in SETTINGS_PAIRS:
            return "_".join(pair)
    return None


def _language_tag(value: str) -> bool:
    """True when ``value`` is a locale name the platform knows (``en``, ``pt-BR``,
    ``zh_TW``, ``english``): CPython's `locale.locale_alias`, X.Org's ``locale.alias``
    table keyed by ISO 639 language and ISO 3166 region codes."""
    import locale
    key = (value or "").strip().lower().replace("-", "_")
    return (len(key) >= 2 and key[:2].isalpha() and key not in ("posix", "cextend")
            and key in locale.locale_alias)


def option_set_setting(values) -> str | None:
    """What setting a select's own option values pick (FR-CRAWL-680), or None: the
    target's data, read against public code lists, where its names say nothing. At
    least two values, every one an IANA time zone (``Area/Location``, `TZ_AREAS`) or a
    known locale name (`_language_tag`)."""
    values = [v for v in values if (v or "").strip()]
    if len(values) < 2:
        return None
    if all("/" in v and v.split("/", 1)[0].lower() in TZ_AREAS for v in values):
        return "time zone options"
    if all(_language_tag(v) for v in values):
        return "language options"
    return None


def signature(record: dict) -> tuple:
    """One enumeration per (method, select name, option values), whatever the action:
    the same header picker appears on every page."""
    opts = record.get("options") or []
    name = opts[0][0] if opts else ""
    return (record["method"], name, tuple(sorted(v for _n, v, _l in opts)))


def signature_key(record: dict) -> str:
    """`signature` as text: how the spider files a picker's verdict and the importer
    finds it again (one derivation, PA-0003)."""
    import json
    return json.dumps(signature(record))


def refusal(record: dict, named: frozenset[str], allow_get: bool,
            in_scope: Callable[[str], bool]) -> str | None:
    """Why this selector form must never be submitted, or None when it may be."""
    if not record.get("selector") or not record.get("options"):
        return "not a selector form"
    select = record["options"][0][0]
    if record["method"] == "POST" and select not in named:
        return f"POST select {select!r} not named by the operator"
    if record["method"] == "GET" and not allow_get and select not in named:
        return "GET selector forms not enabled"
    for name, _kind in record.get("controls") or []:
        word = settings_word(name)
        if word:
            return f"control {name!r} is a settings control ({word!r})"
    picked = option_set_setting(v for _n, v, _l in record["options"])
    if picked:
        return f"select {select!r} is a settings control ({picked})"
    action = record["action_url"]
    if not in_scope(action):
        return "action out of scope"
    reason = destructive_reason(action)
    if reason:
        return f"action is destructive ({reason!r})"
    return None


def option_refusal(value: str, label: str) -> str | None:
    """Why one option must not be submitted (it is skipped, the form continues)."""
    for text in (value, label):
        word = settings_word(text)
        if word:
            return f"settings word {word!r}"
        reason = text_destructive_reason(text)              # never via a URL (BUG-0131)
        if reason:
            return f"destructive ({reason!r})"
    return None


#: What a submitted picker did (FR-CRAWL-10): recorded so the importer never fuzzes a
#: picker the crawler saw act as a settings form.
VERDICT_NAVIGATION = "navigation"
VERDICT_SETTINGS = "settings"


def enumerate_form(record: dict, submit, in_scope: Callable[[str], bool],
                   log: Callable[[str], None] = logging.info,
                   on_verdict: Callable[[str], None] | None = None) -> list[str]:
    """Submit each allowed option of a gated selector form; return the in-scope,
    non-destructive URLs it redirects to (to crawl as ordinary GET links).

    ``on_verdict`` (forms phase 2) is told ``"settings"`` when enumeration stops on a
    cookie or on the self-redirect run, else ``"navigation"`` when a redirect was found.
    It only reports; what is submitted is unchanged."""
    base = FormEntries(tuple(e) for e in record["entries"])
    select = record["options"][0][0]
    own = {url_key(record["page_url"]), url_key(record["action_url"])}
    found: list[str] = []
    self_run = 0
    settings = False
    for _name, value, label in (record["options"] or [])[:MAX_OPTIONS]:
        why = option_refusal(value, label)
        if why:
            log(f"selector {select!r}: skipped option {label!r} ({why})")
            continue
        status, headers = submit(record["method"], record["action_url"],
                                 base.replace(select, value))
        low = {k.lower(): v for k, v in (headers or {}).items()}
        location = low.get("location")
        if "set-cookie" in low:
            log(f"selector {select!r}: response set a cookie; stopped (settings form)")
            settings = True
            break
        if not (300 <= status < 400) or not location:
            log(f"selector {select!r}: non-redirect response {status}; stopped")
            break
        target = urljoin(record["action_url"], location).split("#")[0]
        if not in_scope(target) or destructive_reason(target):
            log(f"selector {select!r}: redirect to {urlsplit(target).path} refused; stopped")
            break
        if url_key(target) in own:
            self_run += 1
            if self_run >= MAX_SELF_REDIRECTS and not found:
                log(f"selector {select!r}: redirects back to itself; stopped (settings form)")
                settings = True
                break
            continue
        self_run = 0
        if target not in found:
            found.append(target)
    if on_verdict is not None and (settings or found):
        on_verdict(VERDICT_SETTINGS if settings else VERDICT_NAVIGATION)
    return found
