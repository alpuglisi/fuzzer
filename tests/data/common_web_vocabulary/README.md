# Common web vocabulary (the black-box guard's allow-list)

`tests/test_blackbox_detection.py` (PA-0660) builds the set of lab-unique
identifiers -- parameter names, path segments and app names from every
`lab/ground-truth*/` answer key and `lab/manifests/*.yaml` labgen manifest -- and
subtracts these two public word lists, so a name a real crawler would meet on any
web application (`id`, `q`, `url`, `search`, `redirect`, ...) is never called
lab-specific. What is left is vocabulary only a lab supplied; the guard fails if
any of it appears in detection rules data or in a detection module's string
literals.

| File | Source | Lines |
| --- | --- | --- |
| `burp-parameter-names.txt` | SecLists `Discovery/Web-Content/burp-parameter-names.txt` | 6453 |
| `common.txt` | SecLists `Discovery/Web-Content/common.txt` | 4751 |

Both copied verbatim from https://github.com/danielmiessler/SecLists at commit
`1368fb8f4ba9ef6cd1b4408b47d904f9329a9063` (fetched 2026-11-20). SecLists is MIT
licensed (Copyright (c) 2018 Daniel Miessler).

sha256:
- `burp-parameter-names.txt` `91f7e457415ffd0e4278d13887804036b62240a135a022a6fd6e831a7151899f`
- `common.txt` `47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a`

Do not add a lab's own words here. A word these lists miss that detection code
legitimately needs goes in the guard's `CITED` table with an independent source
(an RFC, a published schema, OWASP / PortSwigger / vendor documentation), never a
lab.
