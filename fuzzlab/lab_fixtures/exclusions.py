"""The bundled labs' crawl exclusions (FR-LAB-410, CC-LAB-0412) and the CLI merge of
``--exclude`` / ``--exclude-lab`` (FR-CRAWL-675).

Pure data and one function, no I/O: both crawlers' argument parsing reads it, and the
web process imports those (PA-0535 keeps raw file opens out of its import closure;
`lab_fixtures.external` holds the lab lifecycle and its file reads). Fixture knowledge,
never detection logic (PA-0660): a lab's own state-switching GET routes no generic rule
can tell apart."""

from __future__ import annotations

#: lab name -> URL path/query patterns a crawl of it must never load
#: (`core.urls.compile_exclusions`).
CRAWL_EXCLUDE: dict[str, tuple[str, ...]] = {
    # `/difficulty/<level>` switches every resolver's checks; `/start_over` wipes the data
    # (lane CRAWLSAFE measured a crawl following both)
    "dvga": (r"^/difficulty/", r"^/start_over"),
}


class UnknownLab(ValueError):
    """``--exclude-lab`` names no bundled lab."""


def crawl_exclusions(name: str) -> tuple[str, ...]:
    """A bundled lab's crawl exclusions; `UnknownLab` for a lab that has none (an
    ``--exclude-lab`` that would exclude nothing is a usage error, never silent)."""
    if name not in CRAWL_EXCLUDE:
        raise UnknownLab(f"no bundled lab {name!r} with crawl exclusions "
                         f"(labs with a list: {', '.join(sorted(CRAWL_EXCLUDE))})")
    return CRAWL_EXCLUDE[name]


def exclusions_for(args) -> tuple[str, ...]:
    """A crawl's URL exclusions from its CLI arguments (`fuzzlab crawl`, `fuzzlab disco
    capture`): every ``--exclude`` pattern, then the named lab's list."""
    out = list(getattr(args, "exclude", None) or [])
    lab = getattr(args, "exclude_lab", None)
    if lab:
        out.extend(crawl_exclusions(lab))
    return tuple(out)
