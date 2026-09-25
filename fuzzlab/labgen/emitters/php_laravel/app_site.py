"""Per-app presentational site layer for the ``php_laravel`` emitter's
split-out apps (CircleFeed, Huddle Hub, Booking clone -- Lane 1 step 2,
``docs/LAB_BROWSABLE_APPS_PLAN.md``).

The default assembled app (no ``--app``, or ``--app pff``) keeps using the
static, hand-authored site layer already checked into the skeleton
(``resources/views/layouts/site.blade.php`` and friends, added in step 1)
unchanged -- this module is never consulted for that build, so its existing
behavior and every test that already exercises it are untouched.

When :func:`fuzzlab.labgen.assemble.assemble_lab` is given ``app`` equal to
one of :data:`APP_REGISTRY`'s keys, it overwrites just the three files this
module returns (:func:`site_layer_files`) with branded content for that one
app, after the skeleton copy and the app's own cells have been rendered.
Everything else in the skeleton -- ``SiteController.php``'s (unused, unrouted)
extra form methods included -- is left as-is; a split app's ``routes/site.php``
only ever registers ``home``/``catalog``, so those other methods are simply
never reachable, not a functional difference.

Cell-ID-prefix filtering (:data:`APP_REGISTRY`'s ``prefix``) is the same
mechanism :func:`fuzzlab.labgen.assemble.collect_cells` already dedupes
cells by ``cell_id`` with -- ``LABGEN-CF-*``/``LABGEN-HHB-*``/``LABGEN-BC-*``
are exactly CircleFeed's/Huddle Hub's/Booking's own cells (confirmed against
every `lab/manifests/*circlefeed*.yaml`/`*huddlehub*.yaml`/`booking_*.yaml`
file, all ``stack_profile: php_laravel``).

**Scope note, deliberately not done here:** this step makes each app a
separate, standalone, browsable Laravel build. It does **not** rename these
apps' cells off their current generic ``/cell/labgen-<slug>-NNNN`` URLs onto
realistic per-page paths, and it does not remove them from the default
(no ``--app``) merged PFF build -- either change would move a
ground-truth-covered URL, which `docs/LAB_BROWSABLE_APPS_PLAN.md` and
`regression_gate.py` both require an explicit, reviewed baseline update for,
not a silent one bundled into a browsability pass. Left for a follow-up step
(tracked in the plan doc), so this step stays purely additive: a new,
independently bootable app, with zero change to the existing merged build's
routes, ground truth, or gate baselines.
"""

from __future__ import annotations

__all__ = ["APP_REGISTRY", "site_layer_files"]

#: One entry per split-out app. ``prefix`` is the exact ``cell_id`` prefix
#: (case-sensitive, matching the manifests) that identifies a cell as this
#: app's own.
APP_REGISTRY: dict[str, dict[str, str]] = {
    "circlefeed": {
        "name": "CircleFeed",
        "prefix": "LABGEN-CF-",
        "tagline": "Share posts and photos with your circle.",
        "brand": "#2f5d8a",
    },
    "huddlehub": {
        "name": "Huddle Hub",
        "prefix": "LABGEN-HHB-",
        "tagline": "Team chat, huddles, and webhooks.",
        "brand": "#3a6b4f",
    },
    "booking": {
        "name": "Booking clone",
        "prefix": "LABGEN-BC-",
        "tagline": "Search stays and manage bookings.",
        "brand": "#7a3b69",
    },
}

#: CC-LAB-0239 (docs/LAB_BROWSABLE_APPS_STEP3_PLAN.md step 3): one extra
#: GET-reachable client page per app, for the `POST`-only `api` cell that
#: `/catalog` (a `GET`-only listing) can otherwise never surface. Mirrors
#: PFF's own step-1 pattern (`GET /login.php` shows a form, `POST
#: /login.php` is the cell) -- registered at the *same* URL as the cell's
#: own `POST` route, in this separate, hand-authored `routes/site.php`
#: (never passed through `RouteAccumulator`, so its own url-only dedup
#: check, R9, never sees these two coexisting `Route::get`/`Route::post`
#: registrations as a collision -- Laravel's router is method-aware).
_WEBHOOK_CLIENT_PAGE_BY_APP: dict[str, dict[str, str]] = {
    "circlefeed": {
        "url": "/groups/webhook",
        "view": "site.groups-webhook",
        "title": "Groups webhook",
    },
    "huddlehub": {
        "url": "/webhooks/events",
        "view": "site.webhooks-events",
        "title": "Webhooks",
    },
}

#: CC-LAB-0239: `LABGEN-BC-0005`/`0006` (checkout, a `page` not an `api` --
#: unlike the webhook cells above) is `POST`-only too, so it needs the same
#: GET-reachable-page treatment, but as a real `<form method="POST">`, the
#: way a real customer would check out, not a `fetch()` client page.
_FORM_PAGE_BY_APP: dict[str, dict[str, str]] = {
    "booking": {
        "url": "/booking/checkout",
        "view": "site.booking-checkout-form",
        "title": "Checkout",
    },
}


def _layout_blade(app_name: str, brand_color: str) -> bytes:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '    <meta charset="utf-8">\n'
        f"    <title>@yield('title', '{app_name}')</title>\n"
        "    <style>\n"
        "        body { font-family: Arial, Helvetica, sans-serif; margin: 0; background: #f5f5f0; color: #222; }\n"
        f"        header {{ background: {brand_color}; color: #fff; padding: 16px 24px; }}\n"
        "        header h1 { margin: 0 0 8px 0; font-size: 20px; }\n"
        "        header nav a { color: #fff; margin-right: 14px; text-decoration: none; font-size: 13px; }\n"
        "        header nav a:hover { text-decoration: underline; }\n"
        "        main { max-width: 860px; margin: 24px auto; background: #fff; padding: 24px; border: 1px solid #ddd; }\n"
        "        footer { text-align: center; color: #888; font-size: 12px; padding: 16px; }\n"
        "        table { border-collapse: collapse; width: 100%; }\n"
        "        table th, table td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }\n"
        "        .site-list a { display: block; margin: 4px 0; }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "<header>\n"
        f"    <h1>{app_name}</h1>\n"
        "    <nav>\n"
        '        <a href="/">Home</a>\n'
        '        <a href="/catalog">Catalog</a>\n'
        "    </nav>\n"
        "</header>\n"
        "<main>\n"
        "@yield('content')\n"
        "</main>\n"
        f"<footer>{app_name} &mdash; lab-only, authorized-testing target.</footer>\n"
        "</body>\n"
        "</html>\n"
    ).encode("utf-8")


def _home_blade(app_name: str, tagline: str) -> bytes:
    return (
        "@extends('layouts.site')\n"
        f"@section('title', '{app_name}')\n"
        "@section('content')\n"
        f"    <h2>Welcome to {app_name}</h2>\n"
        f"    <p>{tagline}</p>\n"
        '    <p><a href="/catalog">Browse every page on this site</a>.</p>\n'
        "@endsection\n"
    ).encode("utf-8")


def _site_routes_php(app_key: str) -> bytes:
    lines = [
        "<?php\n",
        "// Hand-authored, part of the stack skeleton -- overwritten per split app\n",
        "// by fuzzlab.labgen.emitters.php_laravel.app_site.site_layer_files() for\n",
        "// --app builds. Only the homepage, catalog, and (CC-LAB-0239) this app's\n",
        "// own POST-only api cell's GET client page: a split app carries none of\n",
        "// Puppy Fort Factory's own login/register/contact/newsletter/edit_profile\n",
        "// real-page cells, so those routes would be dead ends here.\n",
        "\n",
        "use App\\Http\\Controllers\\Site\\SiteController;\n",
        "use Illuminate\\Support\\Facades\\Route;\n",
        "\n",
        "Route::get('/', [SiteController::class, 'home']);\n",
        "Route::get('/catalog', [SiteController::class, 'catalog']);\n",
    ]
    client_page = _WEBHOOK_CLIENT_PAGE_BY_APP.get(app_key)
    if client_page is not None:
        lines.append(f"Route::get('{client_page['url']}', fn () => view('{client_page['view']}'));\n")
    form_page = _FORM_PAGE_BY_APP.get(app_key)
    if form_page is not None:
        lines.append(f"Route::get('{form_page['url']}', fn () => view('{form_page['view']}'));\n")
    return "".join(lines).encode("utf-8")


def _webhook_client_view(title: str, url: str) -> bytes:
    return (
        "@extends('layouts.site')\n"
        f"@section('title', '{title}')\n"
        "@section('content')\n"
        f"    <h2>{title}</h2>\n"
        "    <p>This app receives webhook callbacks at this same URL"
        " (a real frontend never calls this itself -- shown here only so"
        " the endpoint is reachable by clicking through the site).</p>\n"
        "    <pre id=\"webhook-result\">(not sent yet)</pre>\n"
        "    <script>\n"
        "    // Minimal inline fetch(), the way a real frontend would call\n"
        "    // this endpoint -- never posted automatically on page load.\n"
        "    function sendTestWebhook() {\n"
        f"        fetch('{url}', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: '{{}}'}})\n"
        "            .then(r => r.text())\n"
        "            .then(t => { document.getElementById('webhook-result').textContent = t; });\n"
        "    }\n"
        "    </script>\n"
        "    <button onclick=\"sendTestWebhook()\">Send a test webhook</button>\n"
        "@endsection\n"
    ).encode("utf-8")


def _booking_checkout_form_view() -> bytes:
    return (
        "@extends('layouts.site')\n"
        "@section('title', 'Checkout')\n"
        "@section('content')\n"
        "    <h2>Checkout</h2>\n"
        '    <form method="POST" action="/booking/checkout">\n'
        '        <label>Room type\n'
        '            <select name="room_type">\n'
        '                <option value="standard">Standard</option>\n'
        '                <option value="deluxe">Deluxe</option>\n'
        '                <option value="suite">Suite</option>\n'
        "            </select>\n"
        "        </label><br>\n"
        '        <label>Amount <input name="amount" value="89.00"></label><br>\n'
        '        <button type="submit">Confirm booking</button>\n'
        "    </form>\n"
        "@endsection\n"
    ).encode("utf-8")


def site_layer_files(app_key: str) -> dict[str, bytes]:
    """The files (relative path -> content) that give ``app_key`` (a key of
    :data:`APP_REGISTRY`) its own branded homepage/layout/catalog (and, for
    CircleFeed/Huddle Hub, their own webhook client page, CC-LAB-0239),
    overwriting what the skeleton copy placed there for the default PFF app.
    """
    app = APP_REGISTRY[app_key]
    files = {
        "resources/views/layouts/site.blade.php": _layout_blade(app["name"], app["brand"]),
        "resources/views/site/home.blade.php": _home_blade(app["name"], app["tagline"]),
        "routes/site.php": _site_routes_php(app_key),
    }
    client_page = _WEBHOOK_CLIENT_PAGE_BY_APP.get(app_key)
    if client_page is not None:
        view_path = "resources/views/" + client_page["view"].replace(".", "/") + ".blade.php"
        files[view_path] = _webhook_client_view(client_page["title"], client_page["url"])
    form_page = _FORM_PAGE_BY_APP.get(app_key)
    if form_page is not None:
        view_path = "resources/views/" + form_page["view"].replace(".", "/") + ".blade.php"
        files[view_path] = _booking_checkout_form_view()
    return files
