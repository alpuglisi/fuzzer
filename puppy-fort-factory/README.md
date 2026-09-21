# Ryder's Puppy Fort Factory

A small e-commerce web app for a fictional puppy-fort company, built as a
**deliberately vulnerable test target** for local security testing. It pairs
with the blind SQL injection fuzzer in the parent repo.

> ⚠️ **Do not deploy this on a public or shared network.** It contains
> intentional SQL injection and XSS flaws and stores passwords as unsalted MD5.
> Run it only on a machine you control, ideally isolated from the internet.

See [`VULNERABILITIES.md`](VULNERABILITIES.md) for the full page-by-page map of
which pages are vulnerable and which are secure.

## Stack

- PHP 7.4+ or 8.x with the `mysqli` extension
- MySQL 5.7+ / MariaDB 10+
- Apache (or PHP's built-in server for quick tests)

## Setup

### 1. Get the code under a web root

Copy `puppy-fort-factory/` under your Apache `DocumentRoot`, e.g.
`/var/www/html/puppy-fort-factory`, or use the built-in PHP server (below).

### 2. Create the database and the application user

Import the schema as an administrative account (this creates the `puppy_fort`
database with `users`, `products`, `posts`, and `cart_items` tables and seed
data):

```bash
sudo mysql < sql/schema.sql          # or: mysql -u admin -p < sql/schema.sql
```

Then create the dedicated **application user** the app connects as. Do **not**
use the database `root` account: on modern MariaDB/MySQL `root` authenticates
over the unix socket, so a TCP login as `root` is refused (you would get
`Access denied for user 'root'`). Least privilege is also good practice.

```sql
CREATE USER IF NOT EXISTS 'pff'@'127.0.0.1' IDENTIFIED BY 'pff_lab_pw';
CREATE USER IF NOT EXISTS 'pff'@'localhost' IDENTIFIED BY 'pff_lab_pw';
GRANT ALL PRIVILEGES ON puppy_fort.* TO 'pff'@'127.0.0.1';
GRANT ALL PRIVILEGES ON puppy_fort.* TO 'pff'@'localhost';
FLUSH PRIVILEGES;
```

(The **containerized** lab in `lab/` provisions this `pff` user automatically —
see `lab/README.md` — so these manual steps are only for a bare LAMP setup.)

### 3. Configure the DB connection

`config/config.php` already defaults to the `pff` user above, so no change is
needed if you used those lab credentials. To override, edit `config/config.php`
or set environment variables (never point the app at `root`):

```bash
export PFF_DB_HOST=127.0.0.1
export PFF_DB_USER=pff
export PFF_DB_PASS=pff_lab_pw
export PFF_DB_NAME=puppy_fort
```

### 4. Run it

With Apache, browse to `http://localhost/puppy-fort-factory/`.

Or with PHP's built-in server (from inside `puppy-fort-factory/`):

```bash
php -S localhost:8080
```

Then open `http://localhost:8080/`.

## Test accounts

| Username | Password |
| --- | --- |
| `admin` | `admin123` |
| `alice` | `password1` |
| `bob`   | `letmein` |

## Pointing the fuzzer at it

The main SQLi target is `product.php?id=`:

```bash
python ../blind_sqli_fuzzer.py \
  --url http://localhost:8080/product.php \
  --param id \
  --authorized
```

Expect the time-based payloads to be flagged against `product.php` and
`search.php` (`q`), and the secure pages to stay clean.

## Feature overview

The site has **30 pages, 10 of them rendered with JavaScript**.

- User registration and login, session-based auth, logout
- Product listing with a category filter, product detail pages, search
- Add to cart, view/remove cart items, checkout
- View and edit user profile
- Contact form, about, FAQ, careers, newsletter, order tracking
- A blog (index + posts) backed by a `posts` table
- **10 JavaScript-rendered pages** (deals, new arrivals, bestsellers,
  recommendations, reviews, gallery, store locations, support, wishlist,
  feedback). Their content and the "Discover" nav links that reach them are
  built client-side, so a basic HTML-only spider cannot see them; a headless
  browser is required.

The 20 server-rendered pages are linked from the header and footer and are fully
crawlable. Which pages are vulnerable and which are secure is documented in
[`VULNERABILITIES.md`](VULNERABILITIES.md).

## Blog table

The blog needs a `posts` table. A fresh `sql/schema.sql` import creates it. On an
existing database, add it without losing data:

```bash
sudo mysql puppy_fort < sql/002_blog.sql
```
