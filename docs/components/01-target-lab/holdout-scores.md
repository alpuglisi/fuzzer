# Held-out benchmark (crawl runs only)

fuzzlab commit `2ab5955395021d45719777ce50a695fac166fd47`; detection code identical to `e14c925`: True; generated 2026-11-20T13:36:22Z.

| lab | status | tp | fp | fn | tn | precision | recall | requests | wall_seconds | crawl_auth | auto_auth |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| vampi | ok | 0 | 0 | 4 | 5 | 0.0 | 0.0 | 8 | 13.4 | anonymous (the logged-in crawl failed) | identity |
| dvws-node | ok | 0 | 0 | 21 | 11 | 0.0 | 0.0 | 139 | 59.1 | anonymous (the logged-in crawl failed) | anonymous (the logged-in run failed) |
| railsgoat | ok | 1 | 3 | 12 | 13 | 0.25 | 0.0769 | 792 | 539.2 | identity | identity |

## vampi

| fn | point | class | reach | progress |
| --- | --- | --- | --- | --- |
| VAMPI-0001 | GET /users/v1/{username} [username] (path) | sqli | crawl,gt | no candidate |
| VAMPI-0002 | GET /books/v1/{book_title} [book_title] (path) | access_control | crawl,gt | no candidate |
| VAMPI-0003 | PUT /users/v1/{username}/password [username] (path) | access_control | crawl | no candidate |
| VAMPI-0004 | POST /users/v1/register [admin] (body) | mass_assignment | gt | no candidate |

## dvws-node

| fn | point | class | reach | progress |
| --- | --- | --- | --- | --- |
| DVWS-0001 | GET /api/v2/passphrase/{username} [username] (path) | sqli | crawl,gt | no candidate |
| DVWS-0002 | POST /api/v2/passphrase [passphrase] (body) | sqli | crawl,gt | no candidate |
| DVWS-0003 | POST /api/v2/passphrase [reminder] (body) | sqli | crawl,gt | no candidate |
| DVWS-0004 | POST /api/v2/notesearch [search] (body) | ssjs | crawl,gt | no candidate |
| DVWS-0005 | POST /api/v2/login [username] (body) | nosqli | crawl,gt | no candidate for the class |
| DVWS-0006 | GET /api/v2/sysinfo/{command} [command] (path) | command-injection | crawl,gt | no candidate |
| DVWS-0007 | POST /dvwsuserservice [username] (body) | xxe | gt | no candidate |
| DVWS-0008 | POST /api/v2/notes/import/xml [xml] (body) | xxe | crawl,gt | no candidate |
| DVWS-0009 | POST /xmlrpc [body] (body) | ssrf | gt | no candidate |
| DVWS-0010 | GET /api/v2/release/{release} [release] (path) | xpath_injection | crawl,gt | no candidate |
| DVWS-0011 | GET /api/v2/users/ldap-search [user] (query) | ldap_injection | crawl,gt | no candidate |
| DVWS-0012 | POST /api/v2/users/ldap-search [user] (body) | ldap_injection | crawl,gt | no candidate |
| DVWS-0013 | POST /api/download [filename] (body) | path_traversal | crawl,gt | no candidate |
| DVWS-0014 | GET /api/v2/reports/monthly [period] (query) | path_traversal | crawl,gt | no candidate |
| DVWS-0015 | GET /api/v2/greeter [name] (query) | ssti | crawl,gt | no candidate |
| DVWS-0016 | POST /api/v2/export [data] (body) | insecure_deserialization | gt | no candidate |
| DVWS-0017 | GET /api/v2/users/logout/{redirect} [redirect] (path) | open_redirect | none - the path names logout: fuzzlab's send gate refuses it as destructive and a contract point may not name it (B9); it is in the OpenAPI document | no candidate |
| DVWS-0018 | GET /api/v2/notes/{noteId} [noteId] (path) | access_control | gt | no candidate |
| DVWS-0019 | PUT /api/v2/users/notification-preferences [admin] (body) | mass_assignment | crawl,gt | no candidate |
| DVWS-0020 | POST /api/v2/resource-store/orders [quantity] (body) | price_integrity_bypass | none - the path names an order: fuzzlab's send gate refuses it as a transaction and a contract point may not name it (B9); the Resource Store page posts it | no candidate |
| DVWS-0021 | GET /search [body] (body) | xss-stored | gt | no candidate |

## railsgoat

| fn | point | class | reach | progress |
| --- | --- | --- | --- | --- |
| RGOAT-0001 | POST /users/6 [user[id]] (body) | sqli | crawl | no candidate |
| RGOAT-0004 | POST /users/6 [user[first_name]] (body) | xss-stored | crawl | no candidate |
| RGOAT-0006 | POST /users/6 [user[admin]] (body) | mass_assignment | crawl | no candidate |
| RGOAT-0007 | POST /users [user[admin]] (body) | mass_assignment | crawl | no candidate |
| RGOAT-0009 | POST /upload [benefits[upload]] (body) | command-injection | crawl,gt | no candidate |
| RGOAT-0011 | GET /download [name] (query) | path_traversal | crawl,gt | no candidate for the class |
| RGOAT-0014 | POST /forgot_password [email] (body) | xss-stored | crawl,gt | no candidate |
| RGOAT-0015 | GET /login [lang] (fragment) | xss-dom | gt | no candidate |
| RGOAT-0018 | POST /sessions [url] (body) | open_redirect | crawl | candidate not checked (inconclusive) |
| RGOAT-0022 | GET /users/{user_id}/work_info [user_id] (path) | access_control | crawl,gt | no candidate |
| RGOAT-0024 | GET /admin/{admin_id}/get_user [admin_id] (path) | access_control | gt | no candidate |
| RGOAT-0025 | GET /admin/1/analytics [field] (query) | sqli | none - the injectable text is the NAME of a field-hash parameter (its column key, joined into select(...)), never a value | no candidate |

false alarms: /users/{id}/messages/4:id:access_control; /users/{id}/messages:id:access_control; /users/{id}/pay:id:access_control
