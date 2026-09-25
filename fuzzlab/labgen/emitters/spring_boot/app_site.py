"""CC-LAB-0244 (FR-LAB-164/165, Browsable Labs Lane 4): the three
`spring_boot` app identities' own static site data -- name, tagline, brand
colour and nav -- kept in one place so a route's page and its app's
homepage/catalog always agree (plan §2a). Fictional brand names throughout
(TrackerNest / ReelQueue / WanderFare), not the real companies the ground
truth is modelled on.

Nothing here is request-derived or per-cell: every value is a plain string
constant, byte-identical across a build's vulnerable and secure twins.
"""

from __future__ import annotations

from typing import NamedTuple


class AppSite(NamedTuple):
    #: Registry key, also the ground-truth-directory-derived app name used
    #: in log/doc prose (never in a URL).
    key: str
    #: Display name, shown in the layout header and page titles.
    name: str
    #: One-line tagline, shown on the homepage only.
    tagline: str
    #: CSS colour for the layout header (plan §2c: "byte-identical per
    #: app, inline CSS, no external assets").
    brand: str
    #: Ordered (href, label) pairs, sorted deterministically by href
    #: (contract point 2) -- the same nav rendered on every page of this
    #: app, including the homepage and the catalog.
    nav: tuple[tuple[str, str], ...]


#: CC-LAB-0244 (FR-LAB-164): one entry per app identity (plan §1.3/§2a).
APP_REGISTRY: dict[str, AppSite] = {
    "trackernest": AppSite(
        key="trackernest",
        name="TrackerNest",
        tagline="Wiki pages, issue tracking and integrations for your team.",
        brand="#0052cc",
        nav=(
            ("/", "Home"),
            ("/catalog", "Site map"),
            ("/integrations/webhook-payload", "Webhooks"),
            ("/issues/import", "Import issues"),
            ("/wiki/pages/render", "Wiki"),
        ),
    ),
    "reelqueue": AppSite(
        key="reelqueue",
        name="ReelQueue",
        tagline="Stream your shows and movies, manage your account.",
        brand="#b3121f",
        nav=(
            ("/", "Home"),
            ("/account/billing", "Billing"),
            ("/account/preferences", "Preferences"),
            ("/account/settings", "Account settings"),
            ("/catalog", "Site map"),
            ("/content/import", "Partner content import"),
            ("/content/thumbnail-import", "Thumbnail import"),
            ("/playback/resume", "Resume playback"),
            ("/profiles/avatar", "Profile avatar"),
            ("/profiles/switch", "Switch profile"),
            ("/session/refresh", "Session refresh"),
            ("/subscription/change-plan", "Change plan"),
            ("/support/template-preview", "Support console"),
        ),
    ),
    "wanderfare": AppSite(
        key="wanderfare",
        name="WanderFare",
        tagline="Search and book hotels for your next trip.",
        brand="#f2a900",
        nav=(
            ("/", "Home"),
            ("/catalog", "Site map"),
            ("/hotels/search-sort", "Search hotels"),
            ("/trips/restore", "Restore a trip"),
        ),
    ),
}

#: CC-LAB-0244: which app owns each real route -- the one shared mapping
#: `_PAGE_PARAMS`'s per-route `app` key and `render_site` both read, so a
#: route's app membership is declared once (plan §1.3: "app membership
#: cannot be derived from the manifest file... it is derivable from the
#: route, and from the cell-ID prefix").
ROUTE_APP: dict[str, str] = {
    "/wiki/pages/render": "trackernest",
    "/issues/import": "trackernest",
    "/integrations/webhook-payload": "trackernest",
    "/api/playback/resume": "reelqueue",
    "/api/content/import": "reelqueue",
    "/api/profiles/switch": "reelqueue",
    "/api/account/billing": "reelqueue",
    "/api/subscription/change-plan": "reelqueue",
    "/api/profiles/avatar": "reelqueue",
    "/api/account/settings": "reelqueue",
    "/api/account/preferences": "reelqueue",
    "/api/content/thumbnail-import": "reelqueue",
    "/api/session/refresh": "reelqueue",
    "/api/support/template-preview": "reelqueue",
    "/api/hotels/search-sort": "wanderfare",
    "/api/trips/restore": "wanderfare",
}


def nav_html_for(app_key: str) -> str:
    """The app's nav bar, as one HTML string -- shared by every page and
    by `SiteLayout` (Java-side callers pass this pre-rendered string in,
    the same "render-only, not verdict-relevant" split every other
    per-route static value in this emitter uses)."""
    from html import escape

    site = APP_REGISTRY[app_key]
    return "".join(f'<a href="{href}">{escape(label)}</a>' for href, label in site.nav)
