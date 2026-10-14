"""HTML form serialisation the way a browser does it (BUG-0110).

A form is submitted as its *entry list* (HTML Living Standard §4.10.21.4, "Constructing
the entry list"). Anything that submits a scraped form on our behalf, or that reports a
control's default value, uses these helpers instead of reading a control's ``value``
attribute directly. That attribute is wrong for a ``<select>`` (its value is the selected
option's), a ``<textarea>`` (its text), and an unchecked checkbox or radio (not sent at
all).

Every rule implemented here is listed in :data:`RULES` with the spec step it follows.
``tests/test_form_entries.py`` fails if a rule has no fixture (PA-0111).

Not covered: ``dirname``, ``_charset_`` (sent as its own value, not the encoding),
duplicate form ids (a ``form=`` control is given to every form with that id, not only
the first), script-set state, and the submitter's ``formaction`` / ``formmethod`` / ``formenctype``. Those are reported by
:func:`submitter_overrides` so a caller can refuse rather than guess.
"""

from __future__ import annotations

#: Rule id -> where it comes from. One fixture per id in tests/test_form_entries.py.
RULES: dict[str, str] = {
    "skip-unnamed": "§4.10.21.4 step 5.3: a field with no (or empty) name is skipped "
                    "(the image submitter excepted)",
    "skip-disabled": "§4.10.21.4 step 5.1: a disabled control is skipped (§4.10.18.5)",
    "skip-disabled-fieldset": "§4.10.18.5: a disabled <fieldset> disables its "
                              "descendants except those in its first <legend>",
    "readonly-sent": "§4.10.5.3.3: readonly does not bar submission",
    "form-owner": "§4.10.17.3 form owner: a control with a form= attribute belongs "
                  "to the form with that id (anywhere in the document), not to the "
                  "form it sits in",
    "submitter-first-in-tree-order": "§4.10.21.2: the form's default button is its "
                                     "first submit button in tree order. fuzzlab takes "
                                     "the first *enabled* one (the button a user would "
                                     "click); the spec instead blocks implicit "
                                     "submission when the default button is disabled",
    "button-default-type-submit": "§4.10.6: a <button> with a missing or invalid type "
                                  "is a submit button; type is ASCII case-insensitive",
    "non-submitter-buttons-skipped": "§4.10.21.4 step 5.1: a button that is not the "
                                     "submitter is skipped (reset/button never submit)",
    "image-submitter-coordinates": "§4.10.21.4 step 5.4: an image submitter adds "
                                   "name.x/name.y, or x/y when unnamed",
    "checkable-only-when-checked": "§4.10.21.4 step 5.1: an unchecked checkbox/radio "
                                   "is skipped",
    "checkable-default-on": "§4.10.5.1.15/16: a checked checkbox/radio with no value "
                            "attribute submits 'on' (an empty value attribute stays '')",
    "select-each-selected-option": "§4.10.21.4 step 5.5: each selected, enabled option "
                                   "of a <select> is an entry",
    "select-selected-disabled-not-sent": "§4.10.21.4 step 5.1 with §4.10.7: a "
                                         "disabled option that is selected stays "
                                         "selected and is not sent",
    "select-display-default": "§4.10.7 selectedness setting: a drop-down select (no "
                              "multiple, display size 1) with nothing selected "
                              "selects its first enabled option; a listbox (size>1) "
                              "selects nothing",
    "option-disabled-by-optgroup": "§4.10.10: an option in a disabled <optgroup> is "
                                   "disabled",
    "option-value-or-text": "§4.10.10: an option's value is its value attribute if "
                            "present (even empty), else its collapsed text",
    "textarea-text": "§4.10.11: a textarea's value is its text, minus one leading "
                     "newline (§13.2.6.4.7)",
    "file-not-sent-as-text": "fuzzlab rule: a file input is never sent as a text field "
                             "(no file to upload)",
    "duplicates-kept-in-order": "§4.10.21.4: the entry list is ordered and keeps every "
                                "entry, duplicate names included",
}

#: ``<input>`` types that submit the form. Only the submitter is sent, never the rest.
_SUBMIT_INPUT_TYPES = frozenset({"submit", "image"})
#: Button-like ``<input>`` types that are never part of the entry list unless submitter.
_BUTTON_INPUT_TYPES = frozenset({"submit", "image", "reset", "button"})
#: Submitter attributes that override the form's destination/method/encoding.
_OVERRIDE_ATTRS = ("formaction", "formmethod", "formenctype")


class FormEntries(list):
    """An ordered entry list of ``(name, value)`` pairs.

    ``requests`` sends a list of pairs as-is, duplicates included. ``get`` returns the
    *last* value for a name (what ``dict(entries)`` and PHP's ``$_POST`` see).
    """

    def get(self, name: str, default=None):
        for key, value in reversed(self):
            if key == name:
                return value
        return default

    def names(self) -> set[str]:
        return {key for key, _ in self}

    def replace(self, name: str, value: str) -> "FormEntries":
        """A copy with every entry called ``name`` set to ``value``, in place (appended
        if there was none)."""
        out = FormEntries((k, value if k == name else v) for k, v in self)
        if name not in out.names():
            out.append((name, value))
        return out


#: The store's ``form`` table holds a request's default sibling entry list: a crawled
#: form's (``enctype`` set, possibly ``""``) or a crawled link's query (``enctype``
#: NULL). The link-set writer uses this value; every reader asks `is_link_set`
#: (forms phase 2, FR-CORE-32, PA-0003).
LINK_SET_ENCTYPE = None


def is_link_set(row) -> bool:
    """True when a store ``form`` row (a mapping or ``sqlite3.Row`` with ``enctype``)
    is a crawled link's query rather than a crawled form."""
    return row["enctype"] is LINK_SET_ENCTYPE


def first_link_set(conn, run_id: int, path: str) -> list[tuple[str, str]] | None:
    """The first crawled link query recorded for ``GET path`` in a run (already
    redacted by the importer), or None. The one store reader of ``form.enctype``
    (a guard test keeps it that way)."""
    import json
    for row in conn.execute(
            "SELECT f.enctype AS enctype, f.entries AS entries FROM form f "
            "JOIN endpoint e ON e.id = f.endpoint_id "
            "WHERE f.run_id = ? AND e.url = ? AND e.method = 'GET' ORDER BY f.id",
            (run_id, path)).fetchall():
        if is_link_set(row):
            return [(str(n), str(v)) for n, v in json.loads(row["entries"])]
    return None


def _input_type(el) -> str:
    return (el.get("type") or "text").strip().lower()


def _button_type(el) -> str:
    btype = (el.get("type") or "submit").strip().lower()
    return btype if btype in ("submit", "reset", "button") else "submit"


def is_disabled(el) -> bool:
    """True if a control is disabled, directly, by a disabled ``<fieldset>``, or (an
    option) by a disabled ``<optgroup>``."""
    if el.has_attr("disabled"):
        return True
    if el.name == "option":
        group = el.find_parent("optgroup")
        return group is not None and group.has_attr("disabled")
    child = el
    for parent in el.parents:
        if getattr(parent, "name", None) == "fieldset" and parent.has_attr("disabled"):
            legend = parent.find("legend", recursive=False)
            if legend is None or child is not legend:
                return True
        child = parent
    return False


def is_submit_control(el) -> bool:
    if el.name == "button":
        return _button_type(el) == "submit"
    return el.name == "input" and _input_type(el) in _SUBMIT_INPUT_TYPES


_CONTROL_TAGS = ["input", "button", "select", "textarea"]


def owned_controls(form):
    """The controls ``form`` owns, in tree order (§4.10.17.3).

    A control with a ``form=`` attribute belongs to the form whose id it names, wherever
    it sits in the document; one without belongs to the form it is inside.
    """
    root = form
    while root.parent is not None:
        root = root.parent
    form_id = form.get("id") or ""
    owned = []
    for el in root.find_all(_CONTROL_TAGS):
        if el.has_attr("form"):
            if form_id and el.get("form") == form_id:
                owned.append(el)
        elif el.find_parent("form") is form:
            owned.append(el)
    return owned


def submitter(form):
    """The form's default button: its first enabled submit control, or None."""
    return next((c for c in owned_controls(form) if is_submit_control(c)
                 and not is_disabled(c)), None)


def submitter_overrides(form) -> tuple[str, ...]:
    """The ``formaction``/``formmethod``/``formenctype`` the submitter carries.

    A browser would take the destination, method or encoding from these instead of the
    form's own. This module does not apply them, so a caller must refuse a non-empty
    result rather than send the form somewhere else than a browser would.
    """
    sub = submitter(form)
    if sub is None:
        return ()
    return tuple(a for a in _OVERRIDE_ATTRS if sub.has_attr(a))


def option_value(option) -> str:
    """An ``<option>``'s value: its ``value`` attribute if present, else its text."""
    if option.has_attr("value"):
        return option.get("value") or ""
    return " ".join(option.get_text().split())


def select_values(select) -> list[str]:
    """The values a ``<select>`` submits (one per selected, enabled option)."""
    # Selectedness is decided over *all* options; only then are disabled ones dropped.
    # A disabled, pre-selected "Choose..." placeholder stays selected and sends nothing.
    options = select.find_all("option")
    selected = [o for o in options if o.has_attr("selected")]
    if not select.has_attr("multiple"):
        if selected:
            selected = selected[-1:]  # a single-choice select keeps the last `selected`
        else:
            try:
                size = int((select.get("size") or "1").strip())
            except ValueError:
                size = 1
            enabled = [o for o in options if not is_disabled(o)]
            # A listbox (size > 1) selects nothing by default; a drop-down its first
            # enabled option.
            selected = enabled[:1] if size <= 1 else []
    return [option_value(o) for o in selected if not is_disabled(o)]


def textarea_value(el) -> str:
    """A ``<textarea>``'s value: its text, minus the one leading newline HTML drops."""
    text = el.get_text()
    if text.startswith("\r\n"):
        return text[2:]
    return text[1:] if text.startswith("\n") else text


def default_value(el) -> str:
    """The value a control holds before the user touches it (for display/reporting)."""
    if el.name == "select":
        values = select_values(el)
        return values[0] if values else ""
    if el.name == "textarea":
        return textarea_value(el)
    if el.name == "input" and _input_type(el) in ("checkbox", "radio"):
        return (el.get("value") or "") if el.has_attr("value") else "on"
    return el.get("value") or ""


def form_entries(form) -> FormEntries:
    """A form's entry list as a browser builds it on an unmodified submit."""
    entries = FormEntries()
    sub = submitter(form)
    for el in owned_controls(form):
        if is_disabled(el):
            continue
        name = el.get("name") or ""
        if el.name == "button":
            if el is sub and name:
                entries.append((name, el.get("value") or ""))
            continue
        if el.name == "input":
            itype = _input_type(el)
            if itype in _BUTTON_INPUT_TYPES:
                if el is sub:
                    if itype == "image":
                        prefix = f"{name}." if name else ""
                        entries.append((f"{prefix}x", "0"))
                        entries.append((f"{prefix}y", "0"))
                    elif name:
                        entries.append((name, el.get("value") or ""))
                continue
            if not name or itype == "file":
                continue
            if itype in ("checkbox", "radio"):
                if el.has_attr("checked"):
                    entries.append((name, default_value(el)))
                continue
            entries.append((name, el.get("value") or ""))
            continue
        if not name:
            continue
        if el.name == "select":
            entries.extend((name, v) for v in select_values(el))
        else:                                            # textarea
            entries.append((name, textarea_value(el)))
    return entries


# --- form classification and records (forms phase 1, CC-CORE-0039) ------------------
#: Control kinds a user types free text into.
_FREE_TEXT = frozenset({"text", "search", "email", "url", "tel", "number", "password",
                        "textarea", "date", "datetime-local", "month", "week", "time",
                        "color", "range"})


def control_kind(el) -> str:
    """``select``, ``textarea``, ``submit`` (any submit-capable button), or the
    ``<input>`` type, lower-cased."""
    if el.name in ("select", "textarea"):
        return el.name
    if el.name == "button":
        return "submit" if _button_type(el) == "submit" else _button_type(el)
    kind = _input_type(el)
    return "submit" if kind in _SUBMIT_INPUT_TYPES else kind


def controls(form) -> list[tuple[str, str]]:
    """The form's enabled, named controls as ``(name, kind)``, in tree order."""
    return [(el.get("name"), control_kind(el)) for el in owned_controls(form)
            if el.get("name") and not is_disabled(el)]


def is_selector_form(form) -> bool:
    """A menu-like form: apart from hidden fields and buttons, exactly one ``<select>``
    and nothing a user types or ticks."""
    kinds = [k for _n, k in controls(form)
             if k not in ("hidden", "submit", "reset", "button", "image")]
    return kinds == ["select"]


def form_method(form) -> str:
    method = (form.get("method") or "GET").strip().upper()
    return method if method in ("GET", "POST") else "GET"


def form_record(form, page_url: str) -> dict:
    """A storable description of ``form``: action, method, enctype, its entry list
    with sensitive values blanked, and its controls. Values of password controls and of
    names `core.redaction` deems sensitive (tokens, CSRF nonces) are never kept: they
    are stored, and later sent, as ``""`` (reviewers A/B, forms phase 1)."""
    from urllib.parse import urljoin

    from fuzzlab.core.redaction import is_sensitive_name
    kinds = dict(controls(form))
    action = (form.get("action") or "").strip()
    entries = [(name, "" if kinds.get(name) == "password" or is_sensitive_name(name)
                else value) for name, value in form_entries(form)]
    return {
        "page_url": page_url,
        "action_url": urljoin(page_url, action) if action else page_url,
        "method": form_method(form),
        "enctype": (form.get("enctype") or "application/x-www-form-urlencoded").lower(),
        "entries": entries,
        "controls": [[n, k] for n, k in controls(form)],
        "selector": is_selector_form(form),
        "options": _selector_options(form) if is_selector_form(form) else [],
    }


def _selector_options(form) -> list[list[str]]:
    """``[[select name, value, label], ...]`` for a selector form's one select."""
    select = next(el for el in owned_controls(form) if el.name == "select")
    out = []
    for opt in select.find_all("option"):
        if not is_disabled(opt):
            out.append([select.get("name") or "", option_value(opt),
                        " ".join(opt.get_text().split())])
    return out
