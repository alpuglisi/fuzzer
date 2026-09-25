'use strict';

// MeadowMart site layer (CC-LAB-0246 / FR-LAB-168, Browsable Labs Lane 6).
//
// Per-stack scaffold file: rendered once, never touched per generated cell.
// app.js calls register(app, catalog) once, after every cell route, with a
// catalog built from the same sorted cell list as its route lines.
//
// Every MeadowMart endpoint is a backend-for-frontend (BFF) JSON API, so
// this file adds the storefront a browser actually sees: a homepage, one
// shared layout, client pages that call the BFF the way the real frontend
// does (a small inline fetch()), and an endpoint catalog. No cell response
// passes through layout() -- the API responses are unchanged.
//
// Rules this file keeps (plan R2/R6, checked by
// tests/test_labgen_node_express_browsable.py):
// - arrays and literal markup only: no for...in loops, no merging of
//   request data into objects, no reads of optional properties off plain
//   objects -- so a polluted Object.prototype cannot change what it renders;
// - the only innerHTML write is the search page's rendering of the
//   /api/search response (fixed product copy plus <mark> tags); everything
//   else is written with textContent/createElement;
// - nothing here reads request input.

const APP_NAME = 'MeadowMart';

// Nav: sorted by path (deterministic, design contract point 2).
const NAV = [
    ['/', 'Home'],
    ['/account/preferences', 'Preferences'],
    ['/cart', 'Cart'],
    ['/catalog', 'API endpoints'],
    ['/orders', 'Track an order'],
    ['/products', 'Products'],
    ['/search', 'Search'],
];

const STYLE = [
    'body{margin:0;font-family:system-ui,sans-serif;background:#f6f8f4;color:#1d2a1d}',
    'header{background:#2f6b3a;color:#fff;padding:12px 20px}',
    'header a{color:#fff;margin-right:14px;text-decoration:none}',
    'header .brand{font-weight:700;font-size:1.2em;margin-right:24px}',
    'main{max-width:820px;margin:24px auto;padding:0 16px}',
    'footer{color:#5b6b5b;font-size:.85em;text-align:center;padding:24px}',
    'table{border-collapse:collapse}td,th{border:1px solid #c9d6c9;padding:4px 8px;text-align:left}',
    'mark{background:#ffe27a}',
].join('\n');

function escapeText(value) {
    return String(value).replace(/[&<>"']/g, (c) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
}

function layout(title, bodyHtml) {
    const nav = NAV.map((item) => '<a href="' + item[0] + '">' + escapeText(item[1]) + '</a>').join('');
    return '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        + '<title>' + escapeText(title) + ' - ' + APP_NAME + '</title>\n'
        + '<style>\n' + STYLE + '\n</style>\n</head>\n<body>\n'
        + '<header><span class="brand">' + APP_NAME + '</span>' + nav + '</header>\n'
        + '<main>\n' + bodyHtml + '\n</main>\n'
        + '<footer>' + APP_NAME + ' storefront - lab build, loopback only</footer>\n'
        + '</body>\n</html>\n';
}

function homePage() {
    const links = NAV.slice(1).map((item) => '<li><a href="' + item[0] + '">' + escapeText(item[1]) + '</a></li>').join('');
    return layout('Home', '<h1>Welcome to ' + APP_NAME + '</h1>\n'
        + '<p>Everyday essentials at big-box prices. Browse products, search the catalog, '
        + 'track an order or update your account preferences.</p>\n'
        + '<ul>' + links + '</ul>');
}

function catalogPage(catalog) {
    const rows = catalog.map((row) => {
        const target = row.href
            ? '<a href="' + row.href + '">' + escapeText(row.path) + '</a>'
            : escapeText(row.path);
        return '<tr><td>' + escapeText(row.method) + '</td><td>' + target + '</td></tr>';
    }).join('\n');
    return layout('API endpoints', '<h1>API endpoints</h1>\n'
        + '<p>The storefront backend-for-frontend endpoints this build serves.</p>\n'
        + '<table><tr><th>Method</th><th>Endpoint</th></tr>\n' + rows + '\n</table>');
}

function clientPage(title, bodyHtml, script) {
    return layout(title, bodyHtml + '\n<script>\n' + script + '\n</script>');
}

const PRODUCTS_SCRIPT = [
    "fetch('/api/products').then((r) => r.json()).then((data) => {",
    "    const list = document.getElementById('products');",
    "    data.products.forEach((p) => {",
    "        const li = document.createElement('li');",
    "        li.textContent = p.name + ' - $' + p.price;",
    "        list.appendChild(li);",
    "    });",
    "});",
].join('\n');

const CART_SCRIPT = [
    "fetch('/api/cart').then((r) => r.json()).then((data) => {",
    "    const list = document.getElementById('cart');",
    "    data.items.forEach((item) => {",
    "        const li = document.createElement('li');",
    "        li.textContent = 'Product ' + item.productId + ' x ' + item.quantity;",
    "        list.appendChild(li);",
    "    });",
    "    document.getElementById('total').textContent = 'Total: $' + data.total;",
    "});",
].join('\n');

const ORDERS_SCRIPT = [
    "document.getElementById('track').addEventListener('submit', (e) => {",
    "    e.preventDefault();",
    "    const id = document.getElementById('orderId').value;",
    "    fetch('/api/orders/' + encodeURIComponent(id)).then((r) => r.json()).then((data) => {",
    "        document.getElementById('status').textContent = 'Status: ' + data.status;",
    "        const list = document.getElementById('history');",
    "        list.textContent = '';",
    "        data.history.forEach((h) => {",
    "            const li = document.createElement('li');",
    "            li.textContent = h.stage + ' at ' + h.at;",
    "            list.appendChild(li);",
    "        });",
    "    });",
    "});",
].join('\n');

const SEARCH_SCRIPT = [
    "function runSearch(term) {",
    "    document.getElementById('q').value = term;",
    "    document.getElementById('term').textContent = term;",
    "    fetch('/api/search?q=' + encodeURIComponent(term)).then((r) => r.text()).then((text) => {",
    "        // The response is fixed product copy with <mark> highlights only.",
    "        document.getElementById('results').innerHTML = text;",
    "    });",
    "}",
    "document.getElementById('search').addEventListener('submit', (e) => {",
    "    e.preventDefault();",
    "    runSearch(document.getElementById('q').value);",
    "});",
    "document.querySelectorAll('.popular').forEach((a) => {",
    "    a.addEventListener('click', (e) => { e.preventDefault(); runSearch(a.dataset.term); });",
    "});",
].join('\n');

const PREFERENCES_SCRIPT = [
    "function show(data) {",
    "    document.getElementById('current').textContent = JSON.stringify(data.preferences);",
    "}",
    "fetch('/api/preferences').then((r) => r.json()).then(show);",
    "document.getElementById('prefs').addEventListener('submit', (e) => {",
    "    e.preventDefault();",
    "    const body = {",
    "        theme: document.getElementById('theme').value,",
    "        notifications: document.getElementById('notifications').checked,",
    "    };",
    "    fetch('/api/preferences', {",
    "        method: 'POST',",
    "        headers: { 'Content-Type': 'application/json' },",
    "        body: JSON.stringify(body),",
    "    }).then((r) => r.json()).then(show);",
    "});",
].join('\n');

function register(app, catalog) {
    app.get('/', (req, res) => {
        res.send(homePage());
    });

    app.get('/catalog', (req, res) => {
        res.send(catalogPage(catalog));
    });

    app.get('/products', (req, res) => {
        res.send(clientPage('Products', '<h1>Products</h1>\n<ul id="products"></ul>', PRODUCTS_SCRIPT));
    });

    app.get('/cart', (req, res) => {
        res.send(clientPage('Cart', '<h1>Your cart</h1>\n<ul id="cart"></ul>\n<p id="total"></p>', CART_SCRIPT));
    });

    app.get('/orders', (req, res) => {
        res.send(clientPage('Track an order', '<h1>Track an order</h1>\n'
            + '<form id="track"><label>Order number <input id="orderId" value="ORD-12345"></label> '
            + '<button type="submit">Track</button></form>\n'
            + '<p id="status"></p>\n<ul id="history"></ul>', ORDERS_SCRIPT));
    });

    app.get('/search', (req, res) => {
        res.send(clientPage('Search', '<h1>Search</h1>\n'
            + '<form id="search"><input id="q" name="q"> <button type="submit">Search</button></form>\n'
            + '<p>Popular searches: '
            + '<a class="popular" data-term="shoes" href="/search">shoes</a>, '
            + '<a class="popular" data-term="mesh" href="/search">mesh</a></p>\n'
            + '<p>Results for: <span id="term"></span></p>\n<div id="results"></div>', SEARCH_SCRIPT));
    });

    app.get('/account/preferences', (req, res) => {
        res.send(clientPage('Preferences', '<h1>Account preferences</h1>\n'
            + '<p>Current: <code id="current"></code></p>\n'
            + '<form id="prefs">'
            + '<label>Theme <select id="theme"><option value="light">Light</option>'
            + '<option value="dark">Dark</option></select></label> '
            + '<label><input type="checkbox" id="notifications" checked> Email notifications</label> '
            + '<button type="submit">Save</button></form>', PREFERENCES_SCRIPT));
    });
}

module.exports = { register, layout };
