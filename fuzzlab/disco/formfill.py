"""Valid-first form values (pure; no browser).

Client-side validation blocks a submission, so the explorer first fills each control
with values a real user would enter and **lets the browser judge them**: `candidates`
orders plausible values best first, and the explorer keeps the first one the element's
own ``checkValidity()`` accepts. That is what makes hidden POST/PUT endpoints fire. One
perturbation per control follows (`perturbations`: empty, the boundary length or value,
another option) -- coverage, not attack; payloads are Phase 2's job.

Inference uses only what the page states: ``type``, ``pattern``, ``min`` / ``max`` /
``step``, ``minlength`` / ``maxlength``, ``autocomplete``, ``required``, the control's
name, its ``<label>`` and placeholder, and ``<select>`` options -- never a lab's route or
field list.

Never overwritten: a sensitively named control other than a password
(`is_sensitive_name`: a CSRF token, a code, a card security code) that the page already
filled, or that is optional -- left as the page set it. One that is required and empty
gets a candidate like any other control, or the browser would refuse the whole form. A
password gets `PASSWORD_FILLER`, never a real credential.
"""

from __future__ import annotations

import re

from fuzzlab.core.redaction import is_credential_name, is_sensitive_name, name_tokens

#: The value every password control gets (never a real credential).
PASSWORD_FILLER = "Disco-Filler-9!"
#: Text types the explorer types into.
TEXT_TYPES = frozenset({"text", "search", "email", "url", "tel", "password", "number",
                        "date", "datetime-local", "month", "week", "time", "color",
                        "range", ""})

_SEMANTIC: tuple[tuple[frozenset[str], tuple[str, ...]], ...] = (
    (frozenset({"email", "mail"}), ("disco.user@example.com",)),
    (frozenset({"phone", "tel", "mobile"}), ("+15555550123", "5555550123", "555-555-0123")),
    (frozenset({"zip", "postal", "postcode"}), ("12345", "SW1A 1AA")),
    (frozenset({"url", "website", "homepage", "link"}), ("https://example.com/",)),
    (frozenset({"city", "town"}), ("Springfield",)),
    (frozenset({"country"}), ("US", "United States")),
    (frozenset({"address", "street"}), ("1 Main Street",)),
    (frozenset({"first", "given", "fname"}), ("Alex",)),
    (frozenset({"last", "family", "surname", "lname"}), ("Doe",)),
    (frozenset({"user", "username", "login", "handle"}), ("disco_user1",)),
    (frozenset({"name", "fullname"}), ("Alex Doe",)),
    (frozenset({"qty", "quantity", "count", "amount", "age", "number", "num"}), ("1", "2")),
    (frozenset({"price", "cost", "total"}), ("10", "10.00")),
    (frozenset({"date", "dob", "birthday"}), ("2000-01-01",)),
    (frozenset({"search", "query", "q", "term", "keyword"}), ("test",)),
    (frozenset({"comment", "message", "text", "body", "description", "review",
                "feedback", "note", "content", "title", "subject"}),
     ("Hello from disco", "Hello")),
)

_TYPE_DEFAULTS = {
    "email": ("disco.user@example.com",),
    "url": ("https://example.com/",),
    "tel": ("+15555550123", "5555550123"),
    "number": ("1",),
    "range": ("1",),
    "date": ("2000-01-01",),
    "datetime-local": ("2000-01-01T12:00",),
    "month": ("2000-01",),
    "week": ("2000-W01",),
    "time": ("12:00",),
    "color": ("#336699",),
}

_AUTOCOMPLETE = {
    "email": "email", "tel": "phone", "postal-code": "zip", "url": "url",
    "given-name": "first", "family-name": "last", "name": "name", "username": "user",
    "street-address": "address", "address-line1": "address", "country": "country",
    "bday": "date", "address-level2": "city",
}


def field_tokens(field: dict) -> set[str]:
    """Name tokens of the control's name, id, autocomplete, label and placeholder."""
    out: set[str] = set()
    for key in ("name", "id", "label", "placeholder", "aria_label"):
        out.update(name_tokens(str(field.get(key) or "")))
    ac = str(field.get("autocomplete") or "").split()[-1:] or [""]
    if ac[0] in _AUTOCOMPLETE:
        out.add(_AUTOCOMPLETE[ac[0]])
    return out


def skip_reason(field: dict) -> str | None:
    """Why a control is left as the page set it, or None."""
    ftype = str(field.get("type") or "").lower()
    if field.get("disabled") or field.get("readonly"):
        return "disabled"
    if ftype in ("hidden", "submit", "button", "reset", "image"):
        return ftype
    if ftype == "file":
        return "file"
    name = str(field.get("name") or field.get("id") or "")
    if ftype != "password" and name and is_sensitive_name(name) \
            and not is_credential_name(name) \
            and (str(field.get("value") or "") or not field.get("required")):
        return "sensitive"
    return None


def _numeric(field: dict) -> list[str]:
    def num(key):
        try:
            return float(field.get(key))
        except (TypeError, ValueError):
            return None
    lo, hi, step = num("min"), num("max"), num("step")
    base = lo if lo is not None else (1.0 if hi is None or hi >= 1 else hi)
    if step and step > 0 and lo is not None:
        base = lo + step if hi is None or lo + step <= hi else lo
    vals = [base]
    if hi is not None:
        vals.append(hi)
    else:
        # no stated maximum: wider magnitudes for a range only a script enforces (one
        # judged by `aria-invalid`; measured: a phone-number field that wanted 7-10
        # digits rejected "1")
        vals += [10.0 ** k for k in range(1, 10) if lo is None or 10.0 ** k > lo]
    return [str(int(v)) if float(v).is_integer() else str(v) for v in vals]


def _from_pattern(pattern: str) -> str | None:
    """A string for simple patterns (classes, literals, ``\\d`` / ``\\w``, quantifiers
    ``{n}`` / ``{n,m}`` / ``+`` / ``*`` / ``?``); None for anything else."""
    out = []
    tokens = re.findall(r"\\[dws]|\[[^\]]+\]|\\.|[^\\\[\]{}+*?()|^$]|\{\d+(?:,\d*)?\}|[+*?]",
                        pattern)
    if "".join(tokens) != pattern.strip("^$"):
        return None
    last = None
    for tok in tokens:
        if tok.startswith("{") or tok in "+*?":
            if last is None:
                return None
            # `*` repeats once: an empty value fails `required` (measured: Juice Shop's
            # `-?[\d]*` CAPTCHA control got "" and blocked its form)
            n = 0 if tok == "?" else 1
            if tok.startswith("{"):
                n = int(tok[1:-1].split(",")[0])
            out[-1] = last * n
            continue
        if tok == r"\d":
            last = "1"
        elif tok == r"\w":
            last = "a"
        elif tok == r"\s":
            last = " "
        elif tok.startswith("["):
            body = tok[1:-1]
            if body.startswith("^"):
                return None
            m = re.match(r"(.)-(.)", body)
            esc = {r"\d": "1", r"\w": "a", r"\s": " "}.get(body[:2])
            last = esc or (m.group(1) if m else body[0])
        elif tok.startswith("\\"):
            last = tok[1]
        else:
            last = tok
        out.append(last)
    return "".join(out)


def _fits(value: str, field: dict) -> bool:
    try:
        lo = int(field.get("minlength")) if field.get("minlength") not in (None, "") else None
        hi = int(field.get("maxlength")) if field.get("maxlength") not in (None, "") else None
    except (TypeError, ValueError):
        lo = hi = None
    if hi is not None and hi >= 0 and len(value) > hi:
        return False
    if lo is not None and len(value) < lo:
        return False
    pattern = field.get("pattern")
    if pattern:
        try:
            return re.fullmatch(pattern, value) is not None
        except re.error:
            return True                 # the browser judges a pattern Python cannot read
    return True


def candidates(field: dict) -> list[str]:
    """Plausible values for a text-like control, best first (the explorer keeps the
    first one the browser accepts). Empty for a control `skip_reason` refuses."""
    if skip_reason(field):
        return []
    ftype = str(field.get("type") or "").lower()
    if ftype == "password":
        return [PASSWORD_FILLER]
    if ftype in ("number", "range"):
        pool = _numeric(field)
    else:
        tokens = field_tokens(field)
        pool = []
        for words, values in _SEMANTIC:
            if tokens & words:
                pool.extend(values)
        pool.extend(_TYPE_DEFAULTS.get(ftype, ()))
        pool.extend(("disco", "Disco value 1"))
    pattern = field.get("pattern")
    if pattern:
        made = _from_pattern(str(pattern))
        if made is not None:
            pool.insert(0, made)
    try:
        lo = int(field.get("minlength") or 0)
    except (TypeError, ValueError):
        lo = 0
    if lo > 0:
        pool.append("d" * lo)
    seen, out = set(), []
    for v in pool:
        if v not in seen and _fits(v, field):
            seen.add(v)
            out.append(v)
    for v in pool:                       # unfitting values last: the browser decides
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def choose_option(field: dict) -> str | None:
    """A ``<select>``'s value: its first option with a non-empty value."""
    for opt in field.get("options") or []:
        if str(opt or "").strip():
            return str(opt)
    return None


def perturbations(field: dict, valid: str | None) -> list[tuple[str, str]]:
    """``(kind, value)`` coverage perturbations for one control: empty, the boundary
    length (``maxlength``) or value (``max`` / ``min``), another option."""
    if skip_reason(field):
        return []
    ftype = str(field.get("type") or "").lower()
    out: list[tuple[str, str]] = []
    if field.get("tag") == "select":
        opts = [str(o) for o in field.get("options") or [] if str(o or "").strip()]
        alt = next((o for o in opts if o != valid), None)
        return [("alternate-option", alt)] if alt is not None else []
    if ftype in ("checkbox", "radio"):
        return []
    out.append(("empty", ""))
    if ftype in ("number", "range"):
        for key in ("max", "min"):
            if field.get(key) not in (None, ""):
                out.append((f"boundary-{key}", str(field.get(key))))
                break
    else:
        try:
            hi = int(field.get("maxlength"))
        except (TypeError, ValueError):
            hi = None
        if hi is not None and 0 < hi <= 4096:
            out.append(("boundary-length", "x" * hi))
    return out
