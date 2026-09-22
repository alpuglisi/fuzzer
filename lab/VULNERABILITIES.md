# Target lab -- vulnerability map (generated)

**Generated file -- do not hand-edit.** Rendered by
`fuzzlab.labgen.vuln_map` from `lab/ground-truth/labels.json` and
`lab/ground-truth/migration-exemptions.yaml` (`L-P3.3c-CUT`). Regenerate
with:

```
python3 -m fuzzlab.labgen.vuln_map --out lab/VULNERABILITIES.md
```

This is the deliberately vulnerable target lab for the toolkit's own
security testing (lab-only, authorized-only -- see the repo's top-level
`README.md` and `CLAUDE.md`). "Vulnerable" / "secure" below refer
specifically to **SQL injection (SQLi)** and **cross-site scripting (XSS)**,
the two classes `lab/ground-truth/labels.json` labels; a page marked
*secure* is free of SQLi/XSS, not a claim it is hardened against every
possible attack.

## Labeled cases (`lab/ground-truth/labels.json`)

| Case | URL | Method | Param | Class | Verdict | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| PFF-0001 | `/product.php` | GET | `id` | sqli | VULNERABLE | id concatenated raw into WHERE; verbose DB errors surfaced |
| PFF-0002 | `/search.php` | GET | `q` | sqli | VULNERABLE | q in a raw LIKE clause |
| PFF-0003 | `/search.php` | GET | `q` | xss-reflected | VULNERABLE | q echoed unescaped into the HTML body |
| PFF-0004 | `/login.php` | POST | `username` | sqli | VULNERABLE | username concatenated raw; classic auth bypass |
| PFF-0005 | `/profile.php` | GET | `bio` | xss-stored | VULNERABLE | bio stored via prepared stmt (not SQLi) then rendered unescaped on profile.php |
| PFF-0006 | `/blog_post.php` | GET | `id` | sqli | VULNERABLE | id concatenated raw; DB errors suppressed -> blind only |
| PFF-0007 | `/reviews.php` | GET | `author` | xss-dom | VULNERABLE | location.hash author written via innerHTML; never reaches the server |
| PFF-0008 | `/feedback.php` | GET | `ref` | xss-dom | VULNERABLE | ref query param used client-side only, written via innerHTML |
| PFF-1001 | `/products.php` | GET | `category` | none | secure | prepared statement + escaped output |
| PFF-1002 | `/track.php` | GET | `order_id` | none | secure | integer cast; canned status |
| PFF-1003 | `/api/products.php` | GET | `category` | none | secure | prepared statement; JSON output |
| PFF-1004 | `/register.php` | POST | `username` | none | secure | prepared statements + escaped output |
| PFF-1005 | `/contact.php` | POST | `message` | none | secure | reflected through htmlspecialchars |
| PFF-1006 | `/newsletter.php` | POST | `email` | none | secure | escaped echo; no DB write |
| PFF-1007 | `/edit_profile.php` | POST | `full_name` | none | secure | prepared update; escaped where rendered |
| PFF-1008 | `/login.php` | POST | `password` | none | secure | md5-hashed before use; not an injection point |

## Not yet reproduced by the generator (`lab/ground-truth/migration-exemptions.yaml`)

These labeled cases have no `php_laravel` cell reproducing them yet. Each
entry below is a reviewed, machine-readable exemption -- see
`fuzzlab.labgen.cutover_gate` (the module that enforces this list is
exhaustive: every `PFF-` case in `labels.json` must be either covered or
named here, or the cutover gate fails the build).

| Case | Reason |
| --- | --- |
| PFF-0003 | search.php's reflected XSS (the HTML-body echo and the quoted value="..." attribute echo, both real and both folded by labels.json into this one case) cannot currently be reproduced at its real /search.php URL simultaneously with PFF-0002 (the LIKE-clause SQLi at the same URL, also real and also currently true): the Cell IR renders one route from exactly one cell, with no multi-sink page composition, so /search.php's single php_laravel page profile must pick ONE canonical cell (CC-LAB-0058/FR-LAB-55, docs/LAB_IMPLEMENTATION_PLAN.md §4.3.6.6 point 3 / L-P3.3c-CUT). PFF-0002 was chosen canonical (higher severity, and the shape every other real-page group with the same choice already canonicalizes); this is a genuine, reviewed downgrade from "covered" to "exempted" for PFF-0003, not a silent drop -- the six LABGEN-PL-RP-000x cells (including the two that render this exact XSS shape) remain authored and individually tested at their illustrative twin URLs; only the real-URL/live-boot claim is affected. Building real multi-sink page composition is tracked as future work, not something L-P3.3c-CUT waits on. |
| PFF-1002 | track.php performs no database query at all (order_id is int-cast, status is canned demo data) -- its security comes from having no sink, not from a modeled safe op, and lab/safety_matrix.yaml has no intval_cast op to express "safe because there is nothing to inject into." No php_laravel cell is emitted for this page (plan §4.3.6.6, "Two findings that change the naive reading of this table"). |
