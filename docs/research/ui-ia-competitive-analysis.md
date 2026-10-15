# UI and information architecture: competitive analysis and recommendations for fuzzlab

**Date:** 2026-10-15. **Status:** research only; no code changed.
**Read by:** the two sessions redesigning the UI, one around (a) saved project files and one
around (b) a URL directory tree. Also read by the session separating **working runs** from
**training/benchmark runs**.
**Base:** `origin/ccr-27885270-9ahcdd` @ `cdde39f`.

This document answers one question: how should fuzzlab's UI be organized so that pointing
it at a URL and reading the results is simple? The rest of the toolkit (benchmarks, ML, the
lab, the proxy) should stay reachable without getting in the way. Sections 2 to 8 survey
seven products. Section 9 compares them. Sections 10 and 11 map fuzzlab today and its gaps.
Sections 12 to 15 give the recommendations, wireframes and a ranked list.

**Conventions.**
- Every factual claim about a product carries a `[src](url)` link to a public source.
- **(inference)** marks a conclusion drawn without a direct source.
- **(snippet)** marks a claim read from a search-engine summary because the page itself
  refused the fetch (G2, Capterra, Gartner and some vendor help sites returned HTTP 403).
- Proprietary text and screenshots are described, not copied.
- §17 lists how each claim was gathered and which ones could not be verified.

---

## 1. Executive summary

The ten findings that should shape the redesign:

1. **The project file is the unit of work, and it auto-saves.**
   - Burp keeps all data and configuration for one engagement in one project file, saved
     incrementally with no Save button
     [src](https://portswigger.net/burp/documentation/desktop/projects).
   - ZAP asks once whether to persist a session, then saves every change automatically
     [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/persistsession/)
     [src](https://www.zaproxy.org/docs/desktop/ui/tlmenu/file).
   - fuzzlab's SQLite store already holds most of what a project file needs, including a
     key/value `meta` table (§10.1). What is missing is project metadata and the lifecycle:
     new, open, recent, temporary, snapshot.
   - Decision D21 already settled the layout: per-project SQLite files plus a small global
     config database (`docs/DECISIONS_AND_ROADMAP.md`). No global config DB exists in code
     yet.
2. **The site tree is host → path → leaf, and a leaf is identified by method plus parameter
   *names*.**
   - ZAP names leaves `METHOD:segment(urlParams)(postParams)`
     [src](https://www.zaproxy.org/docs/desktop/start/features/sitestree/).
   - Burp separates GET and PUT to the same path, greys out discovered-but-unrequested
     items, and puts a dot on each branch showing the worst issue beneath it
     [src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map).
   - Greenbone has no URL tree at all
     [src](https://forum.greenbone.net/t/can-greenbone-scan-a-specific-url/14494), and no
     Nessus documentation we found describes one **(inference)**. A good URL tree is
     therefore a likely differentiator for fuzzlab **(inference)**.
3. **Hash routes are first-class in at least one tool.**
   - ZAP's ordinary Sites tree cannot show `#fragments`, so ZAP added a separate
     **Client Map** to show them
     [src](https://zaproxy.org/docs/desktop/addons/client-side-integration).
   - Burp accepts `#` start URLs only with its browser-based crawler
     [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
   - fuzzlab already stores SPA routes as `/#/search` (`fuzzlab/core/urls.py:24`), so it can
     show them inline in one tree.
4. **Configuration lives apart from operation, and is reused by name.**
   - Nessus splits *Policies* (tuned and reusable) from *Scans* (policy plus targets plus
     history). Settings tuned in a policy are locked in scans built from it
     [src](https://docs.tenable.com/nessus/Content/TemplateSettings.htm).
   - Burp has a *Configuration library* of named presets named for their outcome
     ("Lightweight", "Deep", "passive")
     [src](https://portswigger.net/burp/documentation/desktop/scanning/built-in-configurations).
   - Greenbone has a separate *Configuration* menu
     [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html).
   - NinjaOne creates and manages policies under Administration (device overrides are made
     on the device), with **Inherited / Overridden / Revert** badges
     [src](https://www.ninjaone.com/docs/policies-and-conditions/policies/policy-inheritance/).
   - fuzzlab instead renders every argparse flag as a form field (§10.2, P2 and P3).
5. **"URL → results" takes a handful of actions in every scanner, and one field in the
   best.**
   - Greenbone's Task Wizard: one field and Start
     [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#using-the-task-wizard).
   - ZAP's Quick Start: URL and Attack
     [src](https://www.zaproxy.org/docs/desktop/addons/quick-start/).
   - Burp: New scan, Crawl and audit, URL, preset, Scan
     [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/launching-scans/full-crawl-and-audit).
   - fuzzlab: run `crawl`, then fill the 33-field `auto` form. `auto` imports that crawl and,
     without ground truth, needs `--categories`. The panel's "Run full pipeline" button is
     an unwired stub in the shipped `fuzzlab web` (P1).
6. **Test or benchmark runs are kept out of the real results.**
   - Burp's **"Run isolated scan"** keeps a scan out of the site map and All issues, so you
     can test configurations without polluting live results
     [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
   - Huntress's **Incident Simulation** produces reports with the same structure as real
     ones, stamped **Simulated** and listed on their own page
     [src](https://support.huntress.io/hc/en-us/articles/30950483531539-EDR-ITDR-Incident-Simulation)
     (snippet).
   - Together these are the model for fuzzlab's working vs training/benchmark split.
7. **Findings have two axes plus a status, and the status survives later runs.**
   - Burp rates severity × confidence
     [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/results/issues).
     So does ZAP, where only a user can set "False Positive" or "Confirmed"
     [src](https://www.zaproxy.org/docs/desktop/start/features/alerts/).
   - Greenbone's QoD confidence scale hides results below 70 by default
     [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
   - Burp DAST separates scanner states (New, Present, Regressed, Fixed) from user states
     (False positive, Accepted risk…), and keeps the user state across rescans
     [src](https://portswigger.net/burp/documentation/dast/user-guide/reference/issue-statuses).
   - fuzzlab has no triage state and no cross-run de-duplication (P8, P11).
8. **Comparing two runs is first-class.**
   - Greenbone's delta report labels each result New, Gone, Same or Changed
     [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
   - Nessus's Diff shows only what is new against a baseline, so Tenable advises running it
     in both directions
     [src](https://docs.tenable.com/nessus/Content/CompareScanReportResults.htm). fuzzlab
     should diff both ways.
9. **Automatic suppression stays visible and explains itself.**
   - Aikido's default *Focus* view hides auto-triaged items, but the *All* view and an
     "N auto ignored" tile show each one with its reason
     [src](https://help.aikido.dev/getting-started/core-functionalities/main-feed.md)
     [src](https://help.aikido.dev/workflows-and-guides/resolve-dependency-vulnerabilities-with-autotriage-and-ai-autofix.md).
   - Huntress's home page shows a funnel: events reviewed, then signals investigated, then
     the incidents you must act on
     [src](https://support.huntress.io/hc/en-us/articles/24001293720083-Huntress-Command-Center-Your-New-Homepage)
     (snippet).
   - fuzzlab's store has most stages of that funnel: endpoint → parameter → candidate
     (with `oracle_status`) → finding. `auto` runs write no `attempt` rows (P10).
10. **What users complain about across products:**
    - project files grow huge or open slowly (Burp, ZAP)
      [src](https://forum.portswigger.net/thread/huge-project-files-when-scanning-9d968752)
      [src](https://github.com/zaproxy/zaproxy/issues/1364);
    - large tables freeze
      [src](https://portswigger.net/blog/performance-improvements-to-table-sorting-and-repeater);
    - the UI is cluttered or has a steep learning curve (ZAP, Burp, Nessus);
    - overrides are confusing to scope (Greenbone)
      [src](https://forum.greenbone.net/t/none-of-my-overrides-appear-to-work/3639);
    - reporting is thin (Huntress, NinjaOne).

    The redesign should avoid each of these on purpose.

---

## 2. Burp Suite (Community and Professional; DAST where it clarifies)

### 2.1 Project/session model
- **One project file per engagement.** It holds all data and configuration, saves
  incrementally and can grow to several GB
  [src](https://portswigger.net/burp/documentation/desktop/projects). Because data is
  written as it arrives, a crash loses nothing
  [src](https://portswigger.net/blog/introducing-burp-projects).
- **Startup wizard.**
  - Screen 1: **Temporary project** (in memory, discarded on exit), **New project on disk**,
    or **Open existing project**, which shows a recent-projects list.
  - Screen 2: which configuration to load: Burp defaults, the settings stored in the
    project, or a config file.
  - Source: [src](https://portswigger.net/blog/introducing-burp-projects).
- **Opening a project.** You can choose "Pause Automated Tasks" and "Trust this project
  file". An untrusted file has potentially harmful settings stripped
  [src](https://portswigger.net/burp/documentation/desktop/projects).
- **Conversion.** The 2016 launch post said a temporary project could not become a disk
  project [src](https://portswigger.net/blog/introducing-burp-projects). Current docs say
  Project → **Save copy** converts it
  [src](https://portswigger.net/burp/documentation/desktop/troubleshooting/performance).
- **Edition split.** "Project files (save your work)" is listed as a Professional feature,
  so Community works in temporary projects
  [src](https://portswigger.net/burp/communitydownload).
- **Scans live inside the project.** Each scan is a Dashboard *task*, and tasks are paused
  by default when the project is reopened
  [src](https://portswigger.net/burp/documentation/desktop/dashboard).
- **Two levels of settings.** User settings cover the UI and extensions. Project settings
  cover target work such as session rules and scanner settings. Where both exist, the
  project value wins [src](https://portswigger.net/blog/introducing-burp-projects).

### 2.2 Target and site organization
- **Site map tree.** It runs domain → directories → files → parameterized requests, sorted
  by root domain and then subdomain. GET and PUT to the same endpoint are separate nodes
  [src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map).
- **Visited vs unvisited.** Black items were requested. Grey items were discovered but
  never requested, and turning off passive crawling hides them (same src).
- **Worst-severity roll-up.** A coloured circle on a tree icon shows the most severe issue
  in that branch (same src).
- **Contents table.** It lists the items under the selected node, with a request/response
  pane and Inspector below it and a right-click "send to tool" menu (same src).
- **Display filters.** Filters only hide items; nothing is deleted
  [src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/site-map-filter).
  You can show only in-scope, requested or parameterized items, and filter by MIME type,
  status and extension. Search accepts regex and negation (Pro), and filters can also be
  written as scripts.
- **Scope.**
  - *Simple scope* uses URL prefixes plus an "include subdomains" option.
  - *Advanced scope* uses rules on protocol, host, port and path regex.
  - Scope decides what Proxy logs and intercepts, and what live auditing covers
    [src](https://portswigger.net/burp/documentation/desktop/tools/target/scope).
- **SPA routes.**
  - `#` fragments are accepted in start URLs only with the browser-based crawler; the
    legacy crawler rejects them
    [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
  - The crawler identifies locations by their content rather than their URL
    [src](https://forum.portswigger.net/thread/single-page-scanning-74f3baafdc67820).
  - **Target > Crawl paths** is a separate view beside the site map
    [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).

### 2.3 Findings organization
- **Two rating axes.** Severity is High, Medium, Low or Information. Confidence is Certain,
  Firm or Tentative. Burp calls both "indicative"
  [src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map).
- **Three views of the same issues:**
  - Dashboard → All issues, for the whole project;
  - each task's Issues tab, for one scan;
  - the site-map Issues pane, for the selected branch.

  Source: [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/results/issues).
- **Issue table.** Columns are time, source, type, host, path, insertion point, severity,
  confidence and comment. You can filter by severity, confidence and check type (same src).
- **Evidence tabs:**
  - Advisory: description and remediation;
  - Request, with the payload highlighted;
  - Response, with the reflection highlighted;
  - **Path to issue**: the scanner actions that led to the request.

  Same src.
- **Triage in Pro has no status field.** You set severity (including "False positive") and
  confidence, add comments and highlights, and can restore the original value. Issues can
  also be deleted from the table (same src).
- **De-duplication.** An issue is recorded only the first time it is found (same src). How
  Pro matches issues across separate scans is not documented.
- **DAST/Enterprise has a full lifecycle.**
  - Scanner states: New, Present, Regressed, Fixed, Inconclusive.
  - User states: False positive, Accepted risk, Verified risk, Fixed (unconfirmed).
  - A user state persists across later scans of the site
    [src](https://portswigger.net/burp/documentation/dast/user-guide/reference/issue-statuses).
  - False positives sink to the bottom of the list and are left out of charts
    [src](https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/managing-issues).

### 2.4 Run / scan launch flow
- **Minimal path.** Dashboard **New scan** → "Crawl and audit" → URL(s) → preset → **Scan**.
  Login, resource pool and detailed scope are optional
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/launching-scans/full-crawl-and-audit).
- **Default scope.** The crawl stays inside the start URL's final directory
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
- **Isolated scan.** "Run isolated scan" keeps a scan's results out of the site map, crawl
  paths and All issues. The docs present it as a way to test scan configurations (same
  src; spot-checked §17).
- **Presets are named for their outcome:**
  - combined: Lightweight (15 min), Fast, Balanced, Deep;
  - crawl: by time limit or by strategy;
  - audit: passive, light active, "critical issues only", "minimize false positives".

  Source: [src](https://portswigger.net/burp/documentation/desktop/scanning/built-in-configurations).
- **Resource pools.** A pool throttles concurrent requests and rate per task, and several
  tasks can share one
  [src](https://portswigger.net/blog/burp-2-0-how-do-i-throttle-requests).

### 2.5 Operation vs configuration
- **Configuration library.** Settings → Configuration library holds named, single-purpose
  configurations (crawl, audit, scope). You can filter built-in vs custom, and import or
  export each as JSON.
- **Partial overlays.** A configuration may set only some options; stacked configurations
  override in order, and anything unset falls back to the defaults
  [src](https://portswigger.net/burp/documentation/desktop/settings/library).
- **Custom checks.** BChecks are custom checks that each configuration can switch on or off
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/bchecks).
- **One settings dialog.** In 2022.11 a single Settings dialog replaced the separate User
  and Project options tabs. It has search and All/User/Project filter buttons
  [src](https://portswigger.net/burp/releases/professional-community-2022-11)
  [src](https://portswigger.net/burp/documentation/desktop/settings).

### 2.6 Navigation and layout
- **Top-level tools.** Dashboard, Target, Proxy, Intruder, Repeater, Sequencer, Decoder,
  Comparer, Logger, Organizer, Collaborator and Extensions, plus a cross-cutting search and
  command palette. Right-click "send to tool" is the core workflow
  [src](https://portswigger.net/burp/documentation/desktop/tools).
- **Dashboard.**
  - A tasks list with pause/resume; each task has tabs for Summary, Issues, Audit items,
    Event log and Live crawl view.
  - A bottom dock with All issues, the event log, memory use and project size.
  - Source: [src](https://portswigger.net/burp/documentation/desktop/dashboard).
- **Hotkeys.** Ctrl+R sends to Repeater, and all hotkeys are editable
  [src](https://forum.portswigger.net/thread/keyboard-shortcut-in-repeater-tab-06d13b0d).

### 2.7 Reporting and export
- **Formats.** The report wizard produces HTML; XML is available for your own tooling
  [src](https://portswigger.net/burp/documentation/desktop/running-scans/reporting).
- **Report settings.** Organize by type, severity or URL, and choose which severities go in
  the summary
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/reporting/report-settings).
- **Selection.** Right-click → "Report selected issues"
  [src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map).
- **DAST.** Adds OWASP Top 10 and PCI DSS reports
  [src](https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/generate-reports).

### 2.8 Praise and complaints
- **Praise:** easy to navigate once learned
  [src](https://beaglesecurity.com/blog/article/burp-suite-review.html).
- **Complaint, learning curve:** steep for new users, especially proxy setup and how the
  modules fit together (same src)
  [src](https://www.g2.com/survey_responses/burpsuite-review-5248891).
- **Complaint, file size:** one project file grew from 30 MB to 12 GB during a scan
  [src](https://forum.portswigger.net/thread/huge-project-files-when-scanning-9d968752).
- **Complaint, slow tables:** sorting the issue table froze on large projects
  [src](https://forum.portswigger.net/thread/slow-loading-applications-with-a-large-project-file-801bf9ea).
  PortSwigger acknowledged UI freezing as a major complaint and reworked disk retrieval
  [src](https://portswigger.net/blog/performance-improvements-to-table-sorting-and-repeater).
- **Complaint, manual checking:** findings still need checking by hand before reporting
  [src](https://www.g2.com/survey_responses/burp-suite-review-12818180).

---

## 3. OWASP ZAP ("ZAP by Checkmarx")

### 3.1 Project/session model
- **Always on disk.** A session is always written to an HSQLDB database. If you never
  persist it, the files are deleted on exit
  [src](https://www.zaproxy.org/pdf/ZAPGettingStartedGuide-2.15.pdf).
- **Persist prompt.** Every new session asks: persist with a timestamped name, persist to a
  location you choose, or don't persist for now. A "remember my choice" box suppresses the
  prompt (spot-checked §17)
  [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/persistsession/).
- **Auto-save after persisting.** Every later change saves automatically
  [src](https://www.zaproxy.org/docs/desktop/ui/tlmenu/file). ZAP's own tip is to save at
  the start of a test, not the end
  [src](https://zaproxy.org/docs/desktop/addons/tips-and-tricks).
- **File menu.** New, Open, **Open Recent**, Persist, **Snapshot Session As** (a timestamped
  copy; there is no Save As), Session Properties, Import/Export Context
  [src](https://www.zaproxy.org/docs/desktop/ui/tlmenu/file).
- **Contexts.** A context is a named URL group, usually one per application, defined by
  include/exclude regexes. Each context has its own technology, structure, authentication,
  session-management and users settings, and can be exported and imported
  [src](https://www.zaproxy.org/docs/desktop/start/features/contexts/)
  [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/session/contexts/).
- **Known weaknesses.**
  - Reopening a session replays the whole message history to rebuild the trees, so large
    sessions open very slowly or never finish
    [src](https://github.com/zaproxy/zaproxy/issues/1364).
  - Scan progress is not saved [src](https://github.com/zaproxy/zaproxy/issues/4270).
  - Only one session can be open at a time. This is implied by a still-open feature
    request for multiple sessions [src](https://github.com/zaproxy/zaproxy/issues/3772).

### 3.2 Target and site organization
- **Node naming.** Top-level nodes are protocol + host + port. Middle nodes are path
  segments. Leaves are `METHOD:lastSegment(urlParamNames)(postParamNames)`, for example
  `GET:bbb(cc,ee)` and `POST:/(cc)(cc,ee,gg)`. Requests that differ only in parameter
  *values* share a node (spot-checked §17)
  [src](https://www.zaproxy.org/docs/desktop/start/features/sitestree/).
- **Structural modifiers.** Both are defined by hand (same src):
  - *Structural parameters* split a node by value (`action=add` vs `action=delete`).
  - *Data-driven nodes* collapse data-like path segments into one node, shown as
    `«ddn-name»`.
- **Sites tab.** A Contexts tree sits above the Sites tree. The right-click menu offers
  attack, include/exclude from context, and exclude from proxy, scanner or spider
  [src](https://www.zaproxy.org/docs/desktop/ui/tabs/sites/).
- **Scope.** Nothing is in scope by default
  [src](https://www.zaproxy.org/docs/desktop/start/features/scope/).
- **Discovered vs visited.** Pages found by spidering carry an icon until you visit them
  yourself [src](https://zaproxy.org/docs/desktop/addons/tips-and-tricks).
- **SPAs.**
  - The Sites tree never shows `#fragments`. The **Client Map** (Client-side Integration
    add-on) does, with distinct icons for fragment-only, seen-in-DOM-not-yet-accessed,
    redirect and loaded-as-content URLs, and a link back to the Sites tree (spot-checked
    §17) [src](https://zaproxy.org/docs/desktop/addons/client-side-integration).
  - The AJAX Spider is no longer recommended; the Client Spider replaces it
    [src](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/).

### 3.3 Findings organization
- **Two axes.** Risk is High, Medium, Low or Informational. Confidence is False Positive,
  Low, Medium, High or Confirmed. Scanners never assign False Positive or Confirmed; only a
  user or a filter does [src](https://www.zaproxy.org/docs/desktop/start/features/alerts/).
- **Alerts tab.** A tree sorted by risk, with counts. Its filters are "only in scope" and
  "link with Sites selection"
  [src](https://www.zaproxy.org/docs/desktop/ui/tabs/alerts/).
- **Evidence.** Selecting an alert loads its request and response, with the evidence
  highlighted [src](https://www.zaproxy.org/pdf/ZAPGettingStartedGuide-2.15.pdf).
- **Tuning alerts.**
  - **Alert Filters**, global or per context, match on rule, URL, parameter and evidence and
    set a new risk. They have *Test* and *Apply* buttons
    [src](https://www.zaproxy.org/docs/desktop/addons/alert-filters/alertfilterdialog/)
    [src](https://www.zaproxy.org/docs/desktop/addons/alert-filters/).
  - Context alert filters travel with a context export
    [src](https://www.zaproxy.org/docs/desktop/addons/alert-filters/contextalertfilter/).
- **De-duplication (2.17).**
  - 2.17 de-duplicates alerts by Sites-tree node and flags site-wide issues as Systemic.
  - The accompanying blog recommends a `nodeName` field for comparing alerts across
    scans.
  - A new **Insights** tab holds information that is not a vulnerability.
  - Sources: [src](https://www.zaproxy.org/blog/2025-09-30-alert-de-duplication/)
    [src](https://www.zaproxy.org/docs/desktop/releases/2.17.0/).

### 3.4 Run / scan launch flow
- **Quick Start → Automated Scan.** Enter a URL, choose a policy and spider options, press
  Attack [src](https://www.zaproxy.org/docs/desktop/addons/quick-start/).
- **Active Scan dialog.** Shows a basic set of fields; ticking **"Show Advanced Options"**
  reveals input vectors, custom vectors, technology, policy overrides and filters
  [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/advascan/).
- **Policy Manager.** Named, importable and exportable policies. Each rule has a threshold
  (Off/Low/Medium/High) and a strength (Low to Insane)
  [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/scanpolicymgr/)
  [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/scanpolicy/).

### 3.5 Operation vs configuration
- **Three layers.**
  - **Contexts** describe what to attack.
  - **Policies** describe how hard to attack.
  - **Options** hold global settings across 19 screens
    [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/options/).
- **Modes.**
  - Safe, Protected (attacks only in scope), Standard, and ATTACK (actively scans each new
    in-scope node as soon as it is found).
  - Spidering, scanning, fuzzing and resending are blocked in the modes that forbid them.
  - Source: [src](https://www.zaproxy.org/docs/desktop/start/features/modes/).
- **Automation Framework.**
  - One YAML plan: an `env` section (contexts, users, variables) plus an ordered `jobs` list
    that mixes configuration jobs with action jobs.
  - Plans run headless and set exit codes
    [src](https://www.zaproxy.org/docs/automate/automation-framework/).
  - The desktop Automation tab loads, saves and runs plans
    [src](https://www.zaproxy.org/docs/desktop/addons/automation-framework/gui/).

### 3.6 Navigation and layout
- **Fixed regions.**
  - A Tree window holding Sites and Scripts.
  - A Workspace holding Request, Response and Quick Start.
  - An Information window holding History, Search, Alerts, Output, Active Scan and other
    tabs.
  - A footer with alert counts.
  - Source: [src](https://www.zaproxy.org/docs/desktop/ui/).
- **Progressive disclosure.** Only essential tabs show at first; others appear through a
  "+" tab (same src).
- **Search tab.** Regex search across URL, request and response
  [src](https://www.zaproxy.org/docs/desktop/ui/tabs/search/).
- **Shortcuts and help.** Shortcuts can be rebound, and the keyboard options screen prints a
  cheatsheet [src](https://www.zaproxy.org/docs/desktop/ui/dialogs/options/keyboard/). F1
  opens help for the current tab
  [src](https://zaproxy.org/docs/desktop/addons/tips-and-tricks).
- **HUD.** An in-browser overlay with page flags on one side and site flags on the other
  [src](https://secureideas.com/blog/day-6-passive-flaw-detection-and-using-the-hud).

### 3.7 Reporting and export
- **Report dialog.** It has three tabs:
  - Scope: which contexts and sites;
  - Template, with themes and sections;
  - Filter, by risk × confidence.

  Source: [src](https://www.zaproxy.org/docs/desktop/addons/report-generation/).
- **Templates.** These include traditional HTML/JSON/XML/MD/PDF, modern, risk-confidence
  HTML, SARIF and high-level
  [src](https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/).
- **Export and import.**
  - Export messages, responses, the sites tree and URL lists.
  - Import HAR and URL lists.
  - Source: [src](https://www.zaproxy.org/docs/desktop/addons/import-export/).

### 3.8 Praise and complaints
- **Praise:** free, easy to start, has an API and CI support
  [src](https://www.peerspot.com/products/owasp-zap-pros-and-cons).
- **Complaint, clutter:** a cluttered UI and navigation problems
  [src](https://www.g2.com/products/zap-by-checkmarx/reviews) (snippet).
- **Complaint, compared with Burp:** a weaker UI and weaker reports than Burp, plus
  false-positive noise
  [src](https://www.peerspot.com/products/owasp-zap-pros-and-cons).
- **Complaint, slow large sessions:**
  [src](https://origin.peerspot.com/products/owasp-zap-reviews/page-3)
  [src](https://github.com/zaproxy/zaproxy/issues/1364).
- **Complaint, freezes:** while spidering
  [src](https://github.com/zaproxy/zaproxy/issues/9277).
- **Complaint, slow alerts tree:** slow updates with many alerts
  [src](https://github.com/zaproxy/zaproxy/issues/3881).
- **Complaint, duplicate alerts:** acknowledged, and addressed in 2.17
  [src](https://www.zaproxy.org/blog/2025-09-30-alert-de-duplication/).

---

## 4. Tenable Nessus

### 4.1 Project/session model
- **There is no project file.** The **saved scan** is the unit of work. Scans sit in folders
  (My Scans, All Scans, Trash, plus custom folders), and Trash keeps them for 30 days
  [src](https://docs.tenable.com/nessus/Content/ManageScanFolders.htm).
- **Run history.** Each scan has a **History** tab listing every run
  [src](https://docs.tenable.com/nessus/Content/ScanResults.htm). In Web App Scanning,
  clicking an older run makes it the run on display
  [src](https://docs.tenable.com/web-app-scanning/Content/WAS/Scans/ViewScanDetails.htm).
- **Two portable formats.** **.nessus** is XML with passwords stripped. **Nessus DB** is
  encrypted and complete, and needs a password
  [src](https://docs.tenable.com/nessus/Content/ScanReportFormats.htm). Both can be
  imported [src](https://docs.tenable.com/nessus/Content/ImportAScan.htm).
- **Live Results.** Existing scan data can be re-evaluated against newly released plugins
  without rescanning. These results are visibly marked (striped severity and a "Live"
  icon) [src](https://docs.tenable.com/nessus/Content/LiveResults.htm).

### 4.2 Target and site organization
- **Targets** are hosts, ranges, CIDR blocks or a target file
  [src](https://docs.tenable.com/nessus/Content/ScanTargets.htm).
- **Hosts tab.** Drill down host → vulnerabilities → plugin output
  [src](https://docs.tenable.com/nessus/10_11/Content/Vulnerabilities.htm). Selected hosts
  can be turned into a **new scan** in one step
  [src](https://docs.tenable.com/nessus/Content/CreateANewScanFromScanResults.htm).
- **Web apps (Expert).**
  - A single Target URL, with include/exclude URL scope and crawl modes
    [src](https://docs.tenable.com/nessus/Content/CreateWebApplicationScan.htm)
    [src](https://docs.tenable.com/nessus/10_12/Content/ScopeSettings.htm).
  - No site-tree view is documented; the sitemap seems to come out as a CSV
    [src](https://static.tenable.com/training/ProServ/specs/PS_SB_QS_WAS.pdf)
    **(inference)**.

### 4.3 Findings organization
- **Grouping.** On the Vulnerabilities tab, an optional toggle groups related plugins into
  one "(Multiple Issues)" row; its severity reads "Mixed" when the members differ
  [src](https://docs.tenable.com/nessus/10_12/Content/manage-vulnerabilities.htm).
- **Severity.** Info to Critical, from CVSS bands, with the CVSS version settable per scan
  [src](https://docs.tenable.com/nessus/Content/ConfigureIndividualScanSeverity.htm).
  Sorting by VPR needs grouping turned off
  [src](https://docs.tenable.com/nessus/Content/ScanResults.htm).
- **Filters.** About 60 attributes, combined with All/Any, and saveable
  [src](https://docs.tenable.com/nessus/Content/SearchAndFilterResults.htm).
- **Triage at three levels:**
  - **Modify** changes severity or hides the result, optionally for future scans too;
  - **Snooze** hides it for a set time, with a "Show snoozed" toggle and a Wake action
    [src](https://docs.tenable.com/nessus/10_12/Content/manage-vulnerabilities.htm);
  - **Plugin Rules** do the same globally and only change how results are reported
    [src](https://docs.tenable.com/nessus/10_12/Content/PluginRules.htm).
- **Diff.** Tick two runs on the History tab and pick a baseline. The output shows only
  what is new versus that baseline, so Tenable advises running the diff both ways
  [src](https://docs.tenable.com/nessus/Content/CompareScanReportResults.htm).
- **Remediations tab.** Ranks fixes by how many vulnerabilities each one resolves
  [src](https://docs.tenable.com/nessus/Content/ScanResults.htm).

### 4.4 Run / scan launch flow
- **Three steps.** New Scan → **template gallery** (Discovery, Vulnerabilities, Compliance,
  Web App, plus a User Defined tab) → Basic settings (name, folder, targets) → Launch.
- **Defaults.** The Discovery, Assessment, Report, Advanced and Credentials tabs can be left
  on their defaults
  [src](https://www.tenable.com/blog/how-to-run-your-first-vulnerability-scan-with-nessus)
  [src](https://docs.tenable.com/nessus/Content/ScanAndPolicyTemplates.htm).
- **Complexity is hidden by template choice, not by a toggle.** Each template exposes only
  its own subset of settings (same src).

### 4.5 Operation vs configuration (Nessus's core IA pattern)
- **Policy vs scan.** A **policy** is a reusable, tuned configuration saved as a "User
  Defined" template. A **scan** is a policy (or template) plus targets plus run history
  [src](https://docs.tenable.com/nessus/Content/CreateAPolicy.htm).
- **Locked tuning.**
  - In a scan built from a policy, Discovery, Assessment, Report, Advanced, Compliance, SCAP
    and Plugins **cannot be changed**.
  - Credentials can still be overridden per scan.
  - Spot-checked §17. Source:
    [src](https://docs.tenable.com/nessus/Content/TemplateSettings.htm).
- **Tuning lives in its own place.** Policies, Plugin Rules and Customized Reports each have
  their own left-nav page, apart from the scan folders
  [src](https://docs.tenable.com/nessus/Content/manage-policies.htm). Policies can be
  exported and imported (same src).
- **Settings is a separate top-level page**
  [src](https://docs.tenable.com/nessus/Content/NavigatingNessus.htm).

### 4.6 Navigation and layout
- **Top bar.** Two pages only, **Scans | Settings**
  [src](https://docs.tenable.com/nessus/Content/NavigatingNessus.htm).
- **Scan result tabs.** Summary, Hosts, Vulnerabilities, Compliance and Remediations (each
  shown only when it has data), Notes, History
  [src](https://docs.tenable.com/nessus/Content/ScanResults.htm).

### 4.7 Reporting and export
- **Exports vs reports.** Exports are .nessus, DB and policy files. Reports are PDF, HTML
  and CSV [src](https://docs.tenable.com/nessus/Content/ScanReportFormats.htm).
- **A report contains what the current filters show**
  [src](https://docs.tenable.com/nessus/Content/CreateAScanReport.htm).
- **Custom templates** are built from chapters you add and reorder
  [src](https://docs.tenable.com/nessus/Content/CreateReportTemplate.htm).

### 4.8 Praise and complaints
- **Praise:** easy to learn; analysts start scans with little training
  [src](https://www.gartner.com/reviews/market/vulnerability-assessment/vendor/tenable/product/tenable-nessus)
  (snippet).
- **Complaints:**
  - a dated, "clunky" UI
    [src](https://origin.peerspot.com/products/tenable-nessus-pros-and-cons)
    [src](https://www.capterra.com/p/130577/Nessus/reviews/) (snippet);
  - cumbersome reporting (PeerSpot, same src);
  - requests for more custom views
    [src](https://g2.com/products/nessus/reviews) (snippet).

---

## 5. OpenVAS / Greenbone (GSA web UI)

### 5.1 Project/session model
- **No project file.** All state lives as server-side objects: **Target → Task → Report**.
  Each task run produces a report
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#configuring-a-simple-scan-manually).
- **What a task references.**
  - Reusable objects: a target, scan config, scanner, schedule and alerts.
  - Its own settings: "Add results to Assets", "Apply Overrides", "Min QoD" and others.
  - Source:
    [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#creating-a-task).
- **History lives on the task.**
  - The task list shows the report count, the highest severity and a **Trend** icon
    comparing the last two runs.
  - "Alterable Task" must be switched on to change a task's config once reports exist.
  - Sources: [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html)
    [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
- **Container tasks** hold imported reports
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#using-container-tasks).
- **Trashcan.** Restore is blocked when dependencies are missing
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/web-interface.html).

### 5.2 Target and site organization
- **Targets are network-centric:** hosts, exclusions, port lists, alive test
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#creating-a-target).
- **Assets** are hosts, operating systems and TLS certificates
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/managing-assets.html).
- **No URL or path tree.** Forum staff say the product scans hosts, not URLs, and that a
  web app needs a web application scanner
  [src](https://forum.greenbone.net/t/can-greenbone-scan-a-specific-url/14494). The closest
  thing to a tree is the report's Hosts → Ports → Applications tabs.

### 5.3 Findings organization
- **Report tabs:** Results, Hosts, Ports, Applications, Operating Systems, CVEs, Closed
  CVEs, TLS certificates, Error Messages, User Tags.
- **Severity.** CVSS bands: High, Medium, Low and Log. Low and Log are hidden by default.
- **QoD (Quality of Detection), 0–100%, is a confidence measure keyed to detection
  method.**
  - 100 = exploit, 97 = package check, 80 = remote banner, 50 = remote probe, 30 =
    unreliable.
  - **Only results at 70 or above show by default**, and a user who lowers the filter takes
    on judging false positives.
  - Spot-checked §17. Sources for the three bullets above:
    [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
- **Notes and Overrides.**
  - An override can change a result to False Positive or to another severity.
  - It can be scoped by host, port, task and result. The most specific match wins, and
    among equals the newest wins.
  - Overrides are **not applied by default** (same src).
- **Delta reports.** Comparing two reports of the same task labels each result **New /
  Gone / Same / Changed** (same src). A result's detail view shows a line diff
  [src](https://raw.githubusercontent.com/greenbone/gsa/main/src/web/pages/results/ResultDiff.tsx).
- **Evidence on a result.**
  - Fields: Summary, the **Detection Result** (raw scanner output), Product Detection,
    Insight, and the **Detection Method** with its check ID and version.
  - Active overrides and notes are shown inline.
  - Sources:
    [src](https://raw.githubusercontent.com/greenbone/gsa/main/src/web/pages/results/ResultDetails.tsx)
    [src](https://raw.githubusercontent.com/greenbone/gsa/main/src/web/pages/results/DetailsPage.jsx).

### 5.4 Run / scan launch flow
- **Task Wizard.** Enter an IP or hostname and press **Start Scan**. It creates the target
  and task and starts the scan
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#using-the-task-wizard).
- **Advanced wizard and manual path.** The Advanced wizard adds options. The manual path is
  three object-creation steps
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#using-the-advanced-task-wizard).

### 5.5 Operation vs configuration
- **Two menus.**
  - **Scans** (operational): Tasks, Reports, Results, Vulnerabilities, Notes, Overrides.
  - **Configuration**: Targets, Credentials, Port Lists, Scan Configs, Alerts, Schedules,
    Report Formats, Scanners, Filters, Tags.
  - Sources: [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html)
    [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/web-interface.html).
- **Scan configs.** "Full and fast" is the recommended default (same scanning src).
- **Compliance has its own top-level area**, Resilience
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/compliance-and-special-scans.html).

### 5.6 Navigation and layout
- **Top menu.** Scans, Assets, Resilience, SecInfo, Configuration, Administration, Help.
- **Dashboards.** Up to 10, built from presets.
- **Powerfilter.** One filter language (`keyword=value`, operators, `and`/`or`) on every
  list, with saved filters per resource type.
- **List/detail pattern.** Row actions plus bulk actions on lists.
- Source for all four:
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/web-interface.html).

### 5.7 Reporting and export
- **Formats.** HTML/PDF, CSV, re-importable XML and anonymised XML, among others.
- **Export uses the active filter.**
- **Alerts** can push results.
- Source for all three:
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).

### 5.8 Praise and complaints
- **Praise:** a "well designed and easy to use" console
  [src](https://www.capterra.com/p/171380/OpenVAS/reviews) (snippet).
- **Complaints:**
  - an outdated interface (same, snippet);
  - **confusing overrides**: they apply only to one result unless widened, and are off by
    default [src](https://forum.greenbone.net/t/none-of-my-overrides-appear-to-work/3639);
  - slow paging on large reports
    [src](https://forum.greenbone.net/t/report-slow-to-load-after-scan-complete/4699).

---

## 6. Huntress (managed EDR/ITDR/SIEM: analogies only)

Huntress is a managed security service, not a scanner. Every mapping to fuzzlab here is by
analogy.

### 6.1 Project/session model (analogue)
- **Hierarchy.** An **Account** holds **Organizations**, which hold agents. Users are
  scoped to organizations
  [src](https://support.huntress.io/hc/en-us/articles/4404004902803-Organize-Client-and-Agents-in-the-Huntress-Portal)
  (snippet).
- **No saved workspace.** The organization is the durable container **(inference)**.
- **Pitfall.** A mistyped organization key at agent install silently creates a duplicate
  organization (same src). A project's identity should be validated explicitly.

### 6.2 Target organization (analogue)
- **A shallow tree.** Account → Organization → Agent, with tags for grouping
  [src](https://support.huntress.io/hc/en-us/articles/4404012694291-Agent-Tags) (snippet).
- **Re-parenting.** "Move To" moves agents between organizations
  [src](https://support.huntress.io/hc/en-us/articles/4404004902803-Organize-Client-and-Agents-in-the-Huntress-Portal)
  (snippet).
- **Switcher.** A searchable organization selector in the nav bar
  [src](https://feedback.huntress.com/changelog/new-organization-selector-in-the-huntress-portal)
  (snippet).

### 6.3 Findings organization
- **A three-tier funnel.**
  - **Signals** start investigations.
  - An AI layer **bundles related signals** on the same entity into one investigation
    [src](https://www.huntress.com/blog/ai-signal-triage).
  - **Confirmed malicious activity becomes an Incident Report.** That *only* confirmed
    activity does is our reading **(inference)**. Benign investigations are still visible,
    with a timeline
    [src](https://www.huntress.com/blog/security-incident-investigations-partner-view).
- **Plain-language severity definitions.** Low, High and Critical are each defined by the
  action they require
  [src](https://support.huntress.io/hc/en-us/articles/4404005119251-Incident-Report-Overview)
  (snippet).
- **Report sections.**
  - Summary, Key Details, Timeline, Actions taken, Recommended actions.
  - ITDR reports add an executive summary for non-experts
    [src](https://support.huntress.io/hc/en-us/articles/54383533080979-In-Depth-Understanding-of-Huntress-EDR-and-ITDR-Incident-Reports)
    (snippet).
  - The timeline tells the incident's story in order
    [src](https://www.huntress.com/blog/huntress-managed-itdr-incident-report-timeline-response).
- **Remediation workflow.**
  - Steps are typed Active, Assisted (needs approval) or Manual, and each is tracked as
    Success, In Progress or Failure (Incident Report Overview, snippet).
  - Report statuses are Active and Resolved
    [src](https://www.huntress.com/blog/assisted-remediation-in-action).
  - **Resolve is blocked** while unreviewed Assisted or Manual steps remain
    [src](https://support.huntress.io/hc/en-us/articles/21925225772563-Bulk-Resolve-Incident-Reports)
    (snippet).

### 6.4 Launch flow (analogue)
- **Setup.** Deploy one agent with two keys; vendor-claimed setup time is under 20 minutes
  [src](https://www.huntress.com/start-trial).
- **Incident Simulation.**
  - "Simulate an Incident" produces a report with the same structure as a real one,
    **stamped Simulated** in the severity field and the body.
  - Simulations are listed on their own **Simulated Incidents** page.
  - Source:
    [src](https://support.huntress.io/hc/en-us/articles/30950483531539-EDR-ITDR-Incident-Simulation)
    (snippet).
  - This is the closest analogue to fuzzlab's benchmark runs.

### 6.5 Operation vs configuration
- **Settings.** Managed Response (automatic remediation) is switched on in Settings and
  can be scoped by account or organization
  [src](https://www.huntress.com/soc-guide/automated-threat-remediation).
- **Tuning is done for the user.** Huntress's SOC assigns severity, so users do not
  [src](https://www.huntress.com/use-cases/alert-fatigue).

### 6.6 Navigation and layout
- **Command Center home page.**
  - A **Triage Feed**, one to-do list merging incidents and escalations.
  - A **"SOC Actions" funnel**: events reviewed → signals investigated → incidents to act
    on.
  - Health and coverage widgets.
  - Source:
    [src](https://support.huntress.io/hc/en-us/articles/24001293720083-Huntress-Command-Center-Your-New-Homepage)
    (snippet).

### 6.7 Reporting and export
- **Scheduled reports.** Monthly and quarterly
  [src](https://support.huntress.io/hc/en-us/articles/4404012804115-Monthly-and-Quarterly-Threat-Reports-recently-updated)
  (snippet).
- **Executive summary.** A one-page plain-language summary
  [src](https://feedback.huntress.com/changelog/monthly-executive-summary-reports-are-now-available-ga)
  (snippet).
- **Timeline export.** The timeline exports as PDF
  [src](https://support.huntress.io/hc/en-us/articles/47094685052179-The-Incident-Report-Timeline)
  (snippet).

### 6.8 Praise and complaints
- **Praise:** noise reduction; alerts arrive already triaged
  [src](https://www.capterra.com/p/229839/Huntress/reviews/) (snippet).
- **Complaints:**
  - EDR reporting is "very limited";
  - reports can be hard for non-technical people to read;
  - some fields are buried in the UI.
  - Source:
    [src](https://www.g2.com/products/huntress-managed-edr/reviews?qs=pros-and-cons)
    (snippet).

---

## 7. NinjaOne (RMM/endpoint management: analogies only)

NinjaOne manages endpoints; it is not a web scanner. Every mapping to fuzzlab here is by
analogy.

### 7.1 Project/session model (analogue)
- **The Organization is the unit of work.** NinjaOne calls it the "shell" for policies and
  settings. Organizations can be copied, or imported from CSV
  [src](https://ninjaone.com/docs/groups-organizations-and-locations).
- **No saved workspace.** Per-user state is **Favorites** and **Recents** (the last 10
  items)
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/viewing-recent-saved-content/).

### 7.2 Target organization (analogue)
- **Hierarchy.** Organization → Location → Device. Every org starts with a "Main Office"
  location [src](https://www.ninjaone.com/docs/endpoint-management/hardware-inventory/organizations-and-locations/).
- **Drill-down dashboards, not a persistent tree.**
  - Health is colour-coded at each level.
  - **Clicking a count opens a grid already filtered** to those items.
  - Source:
    [src](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/system-organization-dashboard-navigation/).
- **Groups are saved, dynamic searches**, and about 30 ship built in
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/search-tools/devices-search-page/)
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/search-tools/default-device-groups/).

### 7.3 Findings organization
- **Vulnerabilities at three levels.** A Vulnerabilities tab exists at system, organization
  and device level, with one row per CVE and links from CVE detail to patch status
  [src](https://www.ninjaone.com/docs/integrations/vulnerability-management/find-cve-data/).
- **CVE detail.** Shows risk information, the CVSS score, the impacted devices and patch
  status (same src).
- **Activity and tickets.** A device's Activities feed records events and actions taken on
  the device (installs, scans, automated tasks, patch alerts)
  [src](https://www.ninjaone.com/docs/endpoint-management/manage-devices-and-run-actions/).
  Tickets have six system statuses (New, Open, Waiting, Paused, Resolved, Closed)
  [src](https://www.ninjaone.com/docs/ticketing/ninjaone-ticketing-getting-started/configure-custom-statuses-and-relationships/).
- **Re-imports.** Re-importing scan data treats a CVE missing from the new scan as
  remediated
  [src](https://www.ninjaone.com/docs/integrations/vulnerability-management/importing-vulnerability-scan-data/).

### 7.4 Launch flow (analogue)
- **Run Automation.** Reached from a device's "play" button in about three clicks
  **(inference)**
  [src](https://www.ninjaone.com/docs/endpoint-management/manage-devices-and-run-actions/).
- **Apply now.** Patches immediately, bypassing policy
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/patch-management-dashboard/).

### 7.5 Operation vs configuration (NinjaOne's strongest pattern)
- **Policies are created and managed under Administration → Policies**
  [src](https://www.ninjaone.com/docs/policies-and-conditions/ninjaone-policies/).
  Per-device overrides are made from the device's own policy settings and counted back on
  the policy list (below).
- **Inheritance with visible state.**
  - A child policy inherits from a parent.
  - Inherited settings carry an **Inherited** tag, and edited ones an **Overridden** tag.
  - Hovering an overridden setting offers **Revert** (spot-checked §17).
  - Source:
    [src](https://www.ninjaone.com/docs/policies-and-conditions/policies/policy-inheritance/).
- **The most specific assignment wins:** org default < location < device
  [src](https://www.ninjaone.com/docs/policies-and-conditions/ninjaone-policies/).
- **Override counts.** Each policy shows an **Overrides count** that links to the affected
  devices
  [src](https://www.ninjaone.com/docs/policies-and-conditions/policies/change-override-device-policy/).
- **NinjaOne's own warning.** Per-device overrides make it hard to see which policy applies
  [src](https://www.ninjaone.com/docs/mdm/distributing-apps-to-groups/).

### 7.6 Navigation and layout
- **Left nav.** Dashboard, Devices, Reporting, Administration, Favorites, Recents
  [src](https://www.ninjaone.com/docs/reporting/getting-started-with-reports/).
- **Global search with `/`.**
  - Shows recent searches.
  - Takes a `category:` prefix.
  - Keeps its state in the URL, so results can be bookmarked.
  - Offers actions inline on results.
  - Source:
    [src](https://www.ninjaone.com/docs/new-to-ninjaone/search-tools/global-search-platform/).

### 7.7 Reporting and export
- **Report types.** Summary reports export as PDF and data tables as CSV. Saved reports
  keep their filters and can be scheduled
  [src](https://www.ninjaone.com/docs/reporting/getting-started-with-reports/).

### 7.8 Praise and complaints
- **Praise:** "very easy to navigate", features "where they'd expect"
  [src](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-prxn3vnp37m7k?page=54).
- **Complaints:**
  - basic reporting (same src);
  - **no folders for policies or reports**
    [src](https://capterra.com/p/184229/NinjaOne/reviews?page=1) (snippet);
  - ambiguous patch-status colours [src](https://www.flamingo.run/blog/ninjaone-review).

---

## 8. Aikido Security (DAST and triage focus)

### 8.1 Project/session model
- **Units are connected resources.** The public API is organized around repositories,
  containers, **domains** and clouds [src](https://kestra.io/plugins/plugin-aikido).
- **Adding a domain.** Add Domain → choose a scan type → verify ownership
  [src](https://help.aikido.dev/dast-surface-monitoring/front-end-scanning/scan-front-end-app-domains-with-aikido.md)
  [src](https://help.aikido.dev/miscellaneous-info/domain-verification.md).
- **No portable session file.** Monitoring is continuous, with daily rescans
  [src](https://www.aikido.dev/attack/surface-monitoring-dast) **(inference: no project
  file)**.

### 8.2 Target organization
- **Per-domain flat lists.**
  - **Subdomains**, each excludable from its row
    [src](https://help.aikido.dev/dast-surface-monitoring/attack-surface-scanning/add-or-ignore-subdomains-in-attack-surface.md).
  - **Resources**, the detected libraries.
  - **Routes**, with "exclude from scan" in each row's menu
    [src](https://help.aikido.dev/dast-surface-monitoring/api-scanning/ignoring-routes-in-api-scanning.md).
- **The API surface comes from an OpenAPI spec, not crawling**
  [src](https://help.aikido.dev/dast-surface-monitoring/api-scanning/rest-api-scanning.md).
  No URL tree was found **(inference)**.

### 8.3 Findings organization
- **Feed.**
  - **Issue groups** contain **subissues**.
  - The default **Focus** view shows open issues. **All** adds auto-triaged and ignored
    items.
  - Statuses: New (under 7 days), To Do, Task Open, PR Open.
  - Spot-checked §17. Source:
    [src](https://help.aikido.dev/getting-started/core-functionalities/main-feed.md).
- **Auto-solved.** An issue moves to Solved when a later scan no longer detects it
  [src](https://help.aikido.dev/docs/docs-ja/hajimeni/core-functionalities/why-was-an-issue-marked-as-solved.md).
- **Severity score, 0–100.** Adjusted for exploitability and context; clicking the score
  shows its **breakdown**
  [src](https://help.aikido.dev/getting-started/core-functionalities/how-is-severity-score-calculated.md).
- **Auto-ignore is auditable.**
  - An "N auto ignored" tile opens a list where each item shows its reason.
  - A funnel chart shows what was removed.
  - Source:
    [src](https://help.aikido.dev/workflows-and-guides/resolve-dependency-vulnerabilities-with-autotriage-and-ai-autofix.md).
- **Retest.**
  - Pentest findings carry the request and response.
  - A retest that cannot reproduce the issue closes it as Solved; one that reproduces it
    marks it "Not fixed".
  - Sources: [src](https://help.aikido.dev/pentests/aikido-pentest.md)
    [src](https://help.aikido.dev/pentests/coverage-and-findings/retest-pentest-findings.md).

### 8.4 Run / scan launch flow
- **Minimal path.** Add Domain → scan type → URL. REST and GraphQL options sit under an
  **"Advanced"** expander
  [src](https://help.aikido.dev/dast-surface-monitoring/api-scanning/rest-api-scanning.md).
- **Authenticated scan.**
  - Domain menu → "Authenticate Domain" → login URL and credentials → **Test** → confirm.
  - Source:
    [src](https://help.aikido.dev/dast-surface-monitoring/front-end-scanning/authenticated-scanning-for-front-end-apps.md).

### 8.5 Operation vs configuration (Aikido's tuning)
- **Ignore-scope picker.**
  - Choices: this issue, this path, this CVE everywhere, or this rule everywhere.
  - A single triage click thereby becomes a persistent rule.
  - Source:
    [src](https://help.aikido.dev/getting-started/core-functionalities/ignore-issues-to-remove-issues-from-main-feed.md).
- **Snooze** with an expiry
  [src](https://help.aikido.dev/getting-started/core-functionalities/snooze-issues-for-later.md).
- **Severity changes need a reason**
  [src](https://help.aikido.dev/getting-started/core-functionalities/manually-adjust-issue-severity.md).
- **Approval inbox.** Ignore requests from users without permission go to an approval
  inbox. It is enabled in Settings → Triage
  [src](https://help.aikido.dev/getting-started/core-functionalities/approval-inbox-for-ignored-issues.md).
- **SLA settings.** Days per severity, plus "Out of SLA" views
  [src](https://help.aikido.dev/getting-started/core-functionalities/enable-slas-in-aikido.md).
- **No benchmark mode.** There is no user-facing scoring against a known-vulnerable target
  (autotriage src) **(inference)**.

### 8.6 Navigation and layout
- **Feed and sidebar.** The feed has a team selector, type filters and predefined views.
  Selecting an issue opens a detail sidebar
  [src](https://help.aikido.dev/getting-started/core-functionalities/main-feed.md).
- **Overview vs settings.** Domains have separate Overview and Settings pages
  [src](https://help.aikido.dev/dast-surface-monitoring/front-end-scanning/scan-front-end-app-domains-with-aikido.md).

### 8.7 Reporting and export
- **Feed export.** CSV or PDF of chosen issues
  [src](https://help.aikido.dev/getting-started/core-functionalities/main-feed.md).
- **Security Audit Report.** You pick its sections, which include OWASP Top 10 and
  framework summaries
  [src](https://help.aikido.dev/compliance-and-reporting/reports/security-audit-report.md).

### 8.8 Praise and complaints
- **Praise:** low noise, setup in minutes
  [src](https://g2.com/products/aikido-security/reviews_and_filters?page=5) (snippet).
- **Complaints:**
  - **auto-triage sometimes hides real issues**, and fix advice is generic
    [src](https://www.peerspot.com/products/comparisons/aikido-security_vs_appknox);
  - the issues table hides detection age
    [src](https://g2.com/products/aikido-security/reviews_and_filters?page=10) (snippet).

---

## 9. Comparison table

| Dimension | Burp | ZAP | Nessus | Greenbone | Huntress | NinjaOne | Aikido |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Project/session file | Yes. Auto-saving; temporary or disk (Save copy converts); recent list; saving is Pro-only | Yes. Persist prompt, then auto-save; snapshots; recent list | No. A saved scan plus run history; .nessus / .db export | No. Task → reports; container tasks for imports | No. Organization is the container | No. Organization plus Favorites/Recents | No. Connected resources plus continuous monitoring |
| URL/site tree | Host → dir → file → request; grey = unvisited; worst-severity dot per branch | Host → path → `METHOD:leaf(params)`; structural / data-driven nodes; separate Client Map for `#` | None for web apps (sitemap CSV) | None (host → port → application) | n/a | Org → location → device (drill-down) | Flat per-domain lists (subdomains, routes) |
| Hash/SPA routes | `#` start URLs with browser crawler | Client Map only | n/a | n/a | n/a | n/a | OpenAPI spec, no crawl |
| Severity × confidence | High–Info × Certain/Firm/Tentative | High–Info × FP/Low/Med/High/Confirmed | Critical–Info (CVSS); VPR | CVSS bands × **QoD 0–100, default ≥70** | Low/High/Critical with plain definitions | CVSS | 0–100 score with breakdown |
| Cross-run de-dup / diff | First-find only (Pro); DAST: New/Present/Regressed/Fixed | 2.17 de-dup by node name | Diff (new only, vs a baseline) | **Delta: New/Gone/Same/Changed** | Signals bundled into investigations | Re-import marks missing CVEs remediated | Issue groups; auto-Solved when gone |
| Triage status | Pro: set severity/FP; DAST: FP, Accepted, Verified, Fixed (persistent) | Confidence = FP/Confirmed; alert filters | Modify / Snooze / Plugin rules | Overrides (scoped), notes, tickets (appliance) | Active/Resolved; resolve blocked by pending steps | Ticket statuses | Ignore-scope picker, snooze, severity with reason |
| Evidence | Advisory; request/response highlighted; path to issue | Request/response with evidence highlighted | Plugin output | Detection result + method + check ID | Narrative + timeline | Activities feed | Request/response; retest |
| URL → results | New scan → Crawl and audit → URL → preset → Scan | Quick Start: URL → Attack | Gallery → template → name + target → Launch | **Wizard: 1 field → Start** | Deploy agent | Play → Run Automation | Add Domain → type → URL |
| Advanced hidden by | Presets; optional panels | "Show Advanced Options" | Template subset | Wizard vs full dialog | n/a (SOC tunes) | Policy inheritance | "Advanced" expander |
| Operation vs config | Configuration library; user vs project settings | Context / policy / options; modes; automation plans | **Policies (locked) vs scans** | **Scans menu vs Configuration menu** | Settings; SOC tuning | **Policies in Administration; inheritance; device overrides counted** | Settings → Triage / SLA; ignore rules |
| Test / benchmark lane | **Isolated scan** | — | Live Results (marked) | — | **Incident Simulation (stamped)** | — | — |
| Reporting | HTML/XML; by type/severity/URL | Template × theme × risk/confidence filter; SARIF | PDF/HTML/CSV from current filter | Many formats; export uses active filter | Scheduled; executive one-pager | PDF/CSV; scheduled | CSV/PDF; audit report |
| Top user complaint | File bloat; freezes; learning curve | Clutter; slow sessions | Dated UI; reporting | Outdated UI; confusing overrides | Thin reporting | Thin reporting; no folders | Auto-triage hides real issues |

---

## 10. fuzzlab today: structure and pain points

Everything in this section was read from the code at `cdde39f`. File and line references
are to that tree.

### 10.1 What the user sees

**Web UI** (`fuzzlab web`, `fuzzlab/web/app.py`). The sidebar is the `NAV` list
(`fuzzlab/web/app.py:216`): two groups and eight sections.

| Group | Section | Route | What it shows today |
| --- | --- | --- | --- |
| Workbench | Overview | `/` | KPI tiles: findings by derived severity, runs, last run, **detection quality F1/MCC**, **requests per finding**. Recent runs. Findings-by-severity chart (`templates/sections/overview.html`) |
| Workbench | Launcher | `/launcher` | Master/detail list of 12 activities. Each detail is a form **generated from the tool's argparse parser** (`web/commandspec.py`), with Dry-run, Run, Stop and live output |
| Workbench | Lab | `/lab` | On/off switches for the lab's containers |
| Workbench | Proxy | `/proxy` | History, Intercept, Repeater, Scope and Match-Replace |
| Workbench | Findings | `/findings` | Facets (severity, vuln class, method, mechanism, endpoint), quick filter, chips, saved views, table. Detail page at `/findings/{id}` |
| Workbench | Results | `/results` | A flat table of runs. The run page `/runs/{id}` mixes findings, model scores, oracle coverage, anomaly results, plugins and metrics |
| Analysis | ML | `/ml` | Conformal triage, calibration, PR curve, ranker, anomaly, active learning, bandit posteriors, mutation variants |
| Analysis | Diagnostics | `/diagnostics` | Cross-run trends, series, bandit arms, model registry, raw store explorer |

The top bar shows the target and scope **from the config file**, plus the authorized state
and the proxy state (`templates/base.html`). The Runs table's "target" column actually
shows `run.config_hash` (`web/results.py:101`).

**CLI** (`fuzzlab/cli.py`): 15 commands in one flat list: `web`, `session`, `crawl`,
`audit`, `fuzz`, `auto`, `greybox-run`, `proxy`, `mutate-run`, `report`, `reveal-holdout`,
`flow-anomaly`, `lab-generate`, `build-db`, `version`.

Launcher form sizes, counted with `commandspec.all_specs()` at this commit:

| Activity | Options in its form |
| --- | --- |
| `auto` | **33** |
| `greybox-run` | 16 |
| `mutate-run` | 15 |
| `crawl`, `fuzz`, `proxy` | 13 each |
| `audit` | 11 |
| `flow-anomaly`, `lab-generate` | 5 each |
| `report` | 3 |
| `session` | 2 subcommands (CLI only) |
| `build-db` | 0 |

**The store** is one SQLite file per run set (`store_path`, default `fuzzlab.db`;
`fuzzlab/core/config.py:36`). It already holds most of what a project file needs:
- a key/value `meta` table (`Store.set_meta` / `get_meta`, `fuzzlab/core/store.py:160`);
- runs and discovery: `run`, `target`, `endpoint`, `page` (with `template_cluster_id` and
  `discovered_from`), `parameter`, `form`;
- traffic: `flow` (with `host`, `in_scope`, raw request/response hashes and a full-text
  index);
- testing and results: `candidate` (with `oracle_status`), `attempt`, `finding`;
- UI and session state: `repeater_tab`, `saved_views`, `session_state`;
- ML and evaluation: `model`, `metric_series`, the holdout tables.

There is no project metadata, no run kind and no triage table.

### 10.2 Pain points

Each pain point is something observed in the code. The severity rating is our judgment
**(inference)**.

| # | Pain point | Evidence | Severity |
| --- | --- | --- | --- |
| P1 | **No URL → results path.** A working scan is two tools in sequence: `crawl --start URL`, then `auto --base-url URL --spider-db …`. `auto` imports that crawl but does not crawl itself, and with no ground truth it needs `--categories` or fails loudly (D15). The panel's one-click "Run full pipeline" button is an unwired stub: `fuzzlab web` passes no pipeline, so the button answers "pipeline not wired (use the CLI: fuzzlab auto)". | `harness/auto_cli.py:1-11`; `web/app.py:743-755`; `web_main` → `serve(cfg, proxy=…)` | High |
| P2 | **Forms are argparse dumps.** Every flag of every tool is a form field. There are no presets and no basic/advanced split. | `web/commandspec.py:1-14`; table above | High |
| P3 | **Working and training/benchmark options share one command and one form.** `auto` mixes target options (`--base-url`, `--identity`, `--browser`) with ground-truth benchmark options (`--ground-truth`, `--points ground-truth`) and model options (`--score`, `--rank`, `--train-on`, `--model-id`, `--calibrate`, `--holdout`, `--hybrid`, `--confirm-budget`, `--budget-method`, `--anomaly-*`). The model options do **not** need ground truth: they learn from oracle labels (this run's or earlier runs' against the same target), or, like `--anomaly`, from no labels at all. They are legitimate but advanced working-run features. | `fuzzlab auto --help` | High |
| P4 | **One concept, four names.** The target is `--start` (crawl), `--base-url` (audit, auto, greybox-run), `--url` (fuzz, mutate-run) or `--base` (mutate-run). The crawl result is `--db` on crawl and `--spider-db` elsewhere, alongside a separate `--store`. | each tool's `--help` | High |
| P5 | **No project concept.** The UI reads the one store named in config. It cannot create, open, switch, snapshot or list recent stores, and `fuzzlab web` has no `--store`. The only workaround is an environment override such as `FUZZLAB_STORE_PATH` (`core/config.py` `_from_env`). | `app.py` (every `_read_*` uses `cfg.get("store_path")`); `web_main` | High |
| P6 | **No site tree.** Endpoints, pages, parameters and flows are stored per run, but nothing groups them host → path → parameter. Findings filter only by an "endpoint" facet. | store schema; `templates/sections/findings.html` | High |
| P7 | **Training metrics on the operator's landing page.** The Overview gives a tile to detection-quality F1/MCC, a benchmark metric that shows only "— unscored" on a store with no ground truth. ML and Diagnostics sit beside operational sections in one sidebar. | `templates/sections/overview.html` | Medium |
| P8 | **No triage state.** A finding cannot be marked confirmed, false positive or accepted. `finding` is written only by the oracle (`docs/ARCHITECTURE.md`, "The store as the contract") and must stay that way. | `oracle/oracle.py` `_write_finding` | Medium |
| P9 | **Severity is derived, not stored**, from a substring match on `vuln_class`. Confidence is the confirming *mechanism* (e.g. `error-signature`), not a level. | `web/findingsview.py:1-45` | Medium |
| P10 | **Weak evidence view, and no links to build a better one.** A finding's evidence is a mechanism-specific key/value dict with no link to the flows that confirmed it, so there is no side-by-side request and response with the payload highlighted. `_write_finding` sets no `attempt_id` and no `location`. The `auto` pipeline writes no `attempt` rows; only the fuzz-CSV import and `greybox-run` do. `auto` candidates have a NULL `parameter_id`: their URL, parameter and location sit only in the evidence JSON. | `oracle/oracle.py:320-330`; `tools/store_adapter.py:742`; `greybox/run.py:223`; `audit/engine.py:107-111`; `templates/finding.html` | Medium |
| P11 | **No de-duplication across runs.** The same issue found in three runs appears three times. | `web/findingsview.list_findings` (`ORDER BY id DESC`, no grouping) | Medium |
| P12 | **"Results" means runs**, and it overlaps with Overview's recent-runs table. | `NAV`; `templates/sections/results.html` | Low |
| P13 | **Lab, benchmark and maintenance commands sit at the top level** beside operations. `lab-generate` (lab), `reveal-holdout` (benchmark), `flow-anomaly` (analysis) and `build-db` (rebuilds the auditor's indicator DB) sit beside `crawl` in the CLI, and Lab sits beside Findings in the sidebar. | `cli.py` usage; `NAV`; `tools/build_sql_db.py:1-12` | Low |
| P14 | **Columns a site tree would want are never written.** `page.template_cluster_id` and `page.discovered_from` exist only in the DDL. The one `page` writer sets `run_id, url, method, status, source`, and `TemplateClusterer` runs in memory only. Result URLs are stored path-only, so an endpoint's origin comes only from `target` rows (written by the pipeline) or `flow.host` (set by proxy history only). Crawl-only runs record no origin. | `core/migrations.py:58-59`; `tools/store_adapter.py:119`; `harness/pipeline.py:55-65, 147-157`; `proxy/history.py:134` | Medium |

**Keep these, which already work:**
- the Findings facets, chips and saved views, which are a powerfilter-like layer;
- the shared message editor, Repeater, and "send to Repeater" from a finding;
- full-text search over proxy history (`flow_fts`, `web/proxyview.py`);
- the safety chips in the top bar;
- dark mode and density settings;
- a dry-run preview of every launch;
- the server-rendered multi-page shell.

The previous redesign (`docs/UI_LAYOUT_REDESIGN.md`) set up that visual shell. It did not
address the project, site-tree or working/benchmark questions this document covers.

---

## 11. Gap map

| Pattern (where seen) | fuzzlab today | Gap | Rec. |
| --- | --- | --- | --- |
| Project file with new/open/recent/temporary, auto-save, snapshot (Burp §2.1, ZAP §3.1) | The store is already a file that saves as it goes; one fixed path from config | Lifecycle, chooser, recent list, snapshot, metadata | R1 |
| Tasks paused on reopen; "trust this file" (Burp §2.1) | No-auto-run (D11) already holds; nothing reads project-stored settings | Make it explicit: opening a project never sends traffic; project settings that send traffic need `--authorized` again | R1 |
| One-field quick scan (Greenbone §5.4, ZAP §3.4) | `crawl`, then a 33-field `auto` form; the panel's quick button is an unwired stub | URL field + profile + Scan that runs crawl → auto | R2 |
| Outcome-named presets / policy library (Burp §2.5, Nessus §4.5, ZAP §3.4) | None | Scan profiles | R3 |
| Inherited / Overridden / Revert (NinjaOne §7.5) | None | Profile editor shows its difference from the base profile | R3 |
| Host → path → `METHOD leaf(params)` tree (ZAP §3.2, Burp §2.2) | Data exists per run; no view | Site tree | R4 |
| Visited / unvisited / worst-severity roll-up (Burp §2.2) | `flow` and `finding` exist; `page.discovered_from` is in the schema but never written (P14) | Node states + roll-ups; a writer for discovered-not-requested; a per-run origin | R4 |
| Fragment routes (ZAP §3.2, Burp §2.2) | `to_route_path` stores `/#/route` | Show inline, with a route badge | R4 |
| Data-driven node collapse (ZAP §3.2) | `TemplateClusterer` (DOM MinHash) runs in memory; `page.template_cluster_id` is never written (P14) | Persist clusters, then suggest collapses | R4 |
| Isolated / simulated runs (Burp §2.4, Huntress §6.4) | Benchmark and working share runs, findings and Overview | Run kind + separate lane | R5 |
| Severity × confidence, confidence floor (Burp, ZAP, Greenbone QoD) | Severity derived; confidence = mechanism name | Mechanism → confidence tier, default floor | R6 |
| Cross-run issue identity + New/Gone/Same/Changed (Greenbone §5.3, ZAP 2.17, Burp DAST) | Per-run rows only | Issue key, occurrences, delta | R6, R8 |
| Persistent user triage, separate from scanner state (Burp DAST §2.3, Nessus §4.3, Aikido §8.5) | None; the oracle owns `label` | `finding_triage` side table | R6 |
| Evidence: request/response highlighted, path to issue (Burp, ZAP, Greenbone) | Key/value dump; finding not linked to candidate, attempt or flow (P10) | Record links when the finding is written; reuse msgeditor | R7 |
| Funnel / Focus vs All with reasons (Huntress §6.6, Aikido §8.3) | Endpoints, parameters, candidates (with `oracle_status`) and findings are stored; `auto` writes no attempts | Funnel strip; "not confirmed" reasons | R9 |
| Report = current filtered view (Nessus §4.7, Greenbone §5.7) | `fuzzlab report` exists for one run | Report from the Findings view | R10 |
| Global search with `/` (NinjaOne §7.6) | Full-text search over proxy history (`flow_fts`) and a quick filter on Findings; nothing project-wide | Project-wide search | R11 |

---

## 12. Recommendations

The recommendations are numbered R1 to R11. §15 ranks them. Each is tagged with the
redesign session it most concerns:
- **[PROJ]**: the project-file session;
- **[TREE]**: the URL-tree session;
- **[SPLIT]**: the working/benchmark session.

### 12.1 Information architecture (top-level navigation) [PROJ][TREE][SPLIT]

Organize around one noun hierarchy: **Project → Targets (site tree) → Findings**, with
runs as history. Move configuration, benchmarks/ML and the lab out of the operator's way.
This combines Greenbone's two menus (Scans vs Configuration), Nessus's Scans | Settings
split, and Huntress's separate simulation lane.

```
Title bar:  [fuzzlab] [Project: juice-shop ▾ · WORKING] [⌕ /search]  target · authorized · proxy · budget  [◐][▤]

Left nav
  ── Work ──────────────
  ◆ Dashboard          funnel, open findings by severity, coverage, recent runs
  🌐 Site map          host → path → leaf tree + contents table + node issues   (new)
  ⚑ Findings           de-duplicated issues, triage, Focus / All views
  ▶ Runs               history, run detail, diff two runs
  ── Tools ─────────────
  ⇄ Proxy              History · Intercept · Repeater · Scope · Match-Replace
  ⚙ Manual tools       today's per-tool forms (crawl / audit / fuzz / build-db …), "advanced"
  ── Configure ─────────
  ☰ Scan profiles      Quick / Standard / Deep + custom; inheritance badges
  ◎ Scope & identities scope rules, identities (keyring-backed names only)
  ── (benchmark projects only, or "Show research tools" toggle) ──
  ◈ Benchmark          ground truth, scoring, holdout reveal
  ◈ Models & ML        today's ML page (also shown in a working project once it has models)
  ◍ Diagnostics        trends, store explorer
  ── Environment (outside the project) ──
  ⏻ Lab                containers, lab-generate
```

Rules:
- **The Dashboard is operational.** Detection quality (F1/MCC) and requests per finding
  move to Benchmark (fixes P7).
- **Research tools are hidden for working projects by default.** One switch in Settings
  shows them; they are never deleted (fixes P13). This follows ZAP's progressive
  disclosure [src](https://www.zaproxy.org/docs/desktop/ui/).
- **Lab is environment, not project.** It controls containers and generators that exist
  outside any project.
- **Rename "Results" to "Runs"** (fixes P12).
- **Proxy keeps its internal tabs.** "Send to Repeater" now also works from site-tree nodes,
  as Burp's right-click menu does
  [src](https://portswigger.net/burp/documentation/desktop/tools).

### 12.2 Project-file model (R1) [PROJ]

**What a project is.** One SQLite file, the existing store, plus project metadata.
- **Where the metadata goes.** It can live in the existing key/value `meta` table
  (`Store.set_meta` / `get_meta`, `fuzzlab/core/store.py:160`) rather than a new table.
- **Layout is already decided.** D21 settled it: per-project SQLite files plus a small
  global config database (`docs/DECISIONS_AND_ROADMAP.md`). No global config DB exists in
  code yet; R1 is where it gets built.
- **Why the store fits.** It is already the contract (`docs/ARCHITECTURE.md`), and it
  already saves as it goes, like Burp and ZAP.
- **Extension.** Recommended: `.fuzzlab`, while still accepting `.db`.

| Inside the project file | Not inside the project file |
| --- | --- |
| Project metadata: name, project UUID, kind (`working` or `benchmark`, fixed at creation), created/modified time, fuzzlab and schema version, notes | Stored credentials: they stay in the OS keyring (D12), and the file stores identity **names**. But `repeater_tab.raw_request` is kept verbatim and can hold a cookie or `Authorization` header the user typed (`fuzzlab/proxy/repeater.py`) |
| Targets and scope rules (include/exclude), per project | Global user settings (theme, density, hotkeys, recent list), in the D21 global config DB |
| Scan profiles used, copied in as they were at run time (reproducibility) | The lab, its containers and generator output |
| All runs (with a `kind` column, R5) and their discovery, flows, candidates, attempts, findings and models | Ground-truth files (read out-of-band, D9); a benchmark project stores a **path and hash** to them |
| Triage state (R6), saved views, repeater tabs, site-tree structure overrides (R4) | Sealed holdout plaintext (existing sealing rules apply) |

**Lifecycle.** The start screen follows Burp's wizard and ZAP's persist prompt:

```
┌ fuzzlab ─────────────────────────────────────────────────────────────┐
│  Start                                                                 │
│  ( ) Temporary project      in scratch; discarded on exit unless saved │
│  (•) New project…           name [juice-shop      ]  kind (•)Working   │
│                                                          ( )Benchmark │
│  ( ) Open project…          [browse]                                  │
│                                                                        │
│  Recent                                                                │
│    juice-shop.fuzzlab      WORKING    3 runs · 12 open   2026-10-14   │
│    lab-bench-01.fuzzlab    BENCHMARK  41 runs · F1 0.82   2026-10-12   │
│    pff.fuzzlab             WORKING    1 run  · 0 open    2026-10-01   │
│                                                                        │
│  Opening a project never sends traffic. Runs are started only by you.  │
│                                                       [ Open ]         │
└────────────────────────────────────────────────────────────────────────┘
```

- **New / Open / Recent.** The recent list lives in the D21 global config DB, not in the
  project. A missing file shows as "not found", with a Remove action.
- **Temporary.** A temporary project lives in a scratch file. Offer **"Save as
  project…"** at any time, and then continue working in the saved file. SQLite's online
  backup API makes this straightforward **(inference)**. Burp offers Project → Save copy
  for the same purpose
  [src](https://portswigger.net/burp/documentation/desktop/troubleshooting/performance).
- **Auto-save.** There is no Save button; every write is already committed. Make that
  visible with a "saved · 2 s ago" indicator.
- **Snapshot as…** writes a timestamped copy via the backup API, as ZAP does
  [src](https://www.zaproxy.org/docs/desktop/ui/tlmenu/file). This is the versioning tool;
  there is no Save As.
- **Open is inert.**
  - Opening restores views and nothing else. No run, crawl or proxy starts (D11).
  - A run that was in flight when the app closed shows as **interrupted**, with a "Resume"
    action that needs the usual `--authorized` gate. Burp pauses tasks on reopen
    [src](https://portswigger.net/burp/documentation/desktop/dashboard). ZAP cannot resume
    at all [src](https://github.com/zaproxy/zaproxy/issues/4270).
- **Untrusted files.**
  - A project from elsewhere opens with its stored scope and profiles **shown but not
    applied** until the user confirms. This follows Burp's "trust this project file"
    [src](https://portswigger.net/burp/documentation/desktop/projects).
  - The loopback-only and `--authorized` checks always run against the *current*
    environment, never the file.
- **One project per web process.** This matches ZAP
  [src](https://github.com/zaproxy/zaproxy/issues/3772). Switching projects reloads the
  shell; `fuzzlab web --project PATH` opens one directly (fixes P5).
- **Export.**
  - The `.fuzzlab` file itself is the lossless format.
  - The export dialog warns that the lossless file can contain secrets typed into Repeater
    tabs.
  - Add a **redacted interchange** export (JSON/HAR). Headers are stripped with
    `fuzzlab/proxy/redact.py::redact`; parameter names and bodies with
    `fuzzlab.core.redaction`. This mirrors Nessus's credential-stripped `.nessus` vs
    complete `.db`
    [src](https://docs.tenable.com/nessus/Content/ScanReportFormats.htm).
- **Avoid known failures.**
  - Burp and ZAP files bloat
    [src](https://forum.portswigger.net/thread/huge-project-files-when-scanning-9d968752).
    Show the project size, as Burp does in its dock
    [src](https://portswigger.net/burp/documentation/desktop/dashboard).
  - Offer "Compact" (VACUUM) and "Drop response bodies older than…" as gated maintenance
    operations. Dropping bodies deletes tool output, so it needs an explicit
    NFR-UI-read-only amendment or must stay a CLI operation (§16).
  - ZAP sessions open slowly
    [src](https://github.com/zaproxy/zaproxy/issues/1364). Build the site tree from indexed
    tables, never by replaying flows (R4).
  - Huntress creates a duplicate organization on a mistyped key. Give each project a
    stable **project UUID** in metadata, so recents and snapshots can be matched to their
    origin **(inference)**.

**Migration, CLI and concurrency** [PROJ]:
- **Migration.** Today's `fuzzlab.db`, or any existing store, opens as a project as-is. The
  first open writes project metadata into `meta`. The config file's `target_base_url` and
  `scope_hosts` become the project's first target and scope.
- **CLI.** Every tool gains `--project PATH` as the one name for `--store`. The crawl's
  separate `--db` / `--spider-db` file folds into the project (P4). The old flags stay as
  aliases.
- **Concurrency.** A CLI run may write to a project that the UI has open. SQLite allows one
  writer at a time, and the store already runs in WAL mode (`fuzzlab/core/store.py:28-32`),
  so readers never block a running tool. The UI mostly reads; its few writes (saved views,
  Repeater) are brief. Show a "run in progress" badge for an unfinished `run` row
  **(inference)**.

### 12.3 Site-tree design (R4) [TREE]

**Node levels.** These follow ZAP's leaf identity and Burp's state and roll-up conventions.

| Level | Key | Source in the store | Notes |
| --- | --- | --- | --- |
| 0 Origin | `canonical_origin(url)` (`fuzzlab/core/urls.py:53`) | **Needs a per-run origin.** Result URLs (`endpoint.url`, `page.url`, `finding.url`) are stored path-only. `target.base_url` is written only by the pipeline and `flow.host` only by proxy history, so crawl-only runs record no origin. The [TREE] session must add one, e.g. a `target` row for every run (P14) | Loopback aliases are already one site |
| 1…n Path segment | `to_path(url)` split on `/` | `endpoint.url`, `page.url` | Directories are synthetic grouping nodes |
| `#` SPA route | `to_route_path(url)` → `/#/search` (`urls.py:24`) | endpoints stored with the route | A **`#` pseudo-segment** under the path part of the URL the route was seen on. `to_route_path` keeps that path, so `/app/#/x` sits under `/app/`. If several paths serve the same app, its routes appear under each. Route badge |
| Leaf | `METHOD name(query params)(body params)` | `endpoint.method` + `parameter` rows (`name`, `location`) | Identity uses parameter **names**, not values (ZAP); GET and POST are separate leaves (Burp) |
| Parameter (expandable) | `name @ location` | `parameter`; `auto` candidates carry it only in `candidate.evidence` | Location is one of `audit/rules.LOCATIONS`: query, body, header, cookie, json, fragment, path. **`fragment` params (a hash route's query) never reach the server**: show a "client-side" badge, as `spa_route` documents |

**SPA routes appear inline, not in a second tree.** ZAP needed a separate Client Map
because its Sites tree cannot hold fragments
[src](https://zaproxy.org/docs/desktop/addons/client-side-integration). fuzzlab already
stores `/#/route` as an endpoint path, so a single tree is simpler. For example:

```
▾ http://127.0.0.1:3000                               ● 4  ▓▓▓▓░ 78% tested
  ▾ /                                                  ● 2
    ▾ #  (single-page app routes)                      ● 2
      ▸ /#/search            GET  (q)ᶜ                 ● 1 high     ᶜ client-side param
      ▸ /#/login             GET  —                    ○
      ▸ /#/profile           GET  —                    ● 1 critical (via POST /profile)
  ▾ /rest
    ▾ /products
      ▸ search               GET  (q)                  ● 1 critical
  ▾ /profile
      ▸ profile              GET  —                    ○
      ▸ profile              POST ()(username)         ● 1 critical
  ░ /ftp                     (discovered, not requested)
```

**Node states.** Burp has two visual states
[src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map). fuzzlab
should show four:
1. **Discovered**, grey: known from a link or a crawl, but no `flow` has been recorded.
2. **Requested**, normal text: a flow exists.
3. **Tested**, a small tick: candidates exist for its parameters. This is a join on
   URL, parameter and location from `candidate.evidence`, because `auto` candidates have no
   `parameter_id`.
4. **Out of scope / excluded**, struck through: excluded by the project's scope rules.
   `flow.in_scope` is set only by proxy history, so it cannot be the only source.

Turning on "show discovered" is a filter, not a different tree. *Today nothing records
"discovered but not requested": `page.discovered_from` is never written. The [TREE]
session needs a writer for it in the crawler or store adapter (§16). The rest of this
state mapping is our inference.*

**Roll-ups on every non-leaf node:**
- **worst open severity**, shown as a coloured dot, as in Burp;
- **open issue count**, excluding false positives and accepted risk, as Burp DAST excludes
  false positives from charts
  [src](https://portswigger.net/burp/documentation/dast/user-guide/work-with-scan-results/managing-issues);
- **tested coverage**, as tested parameters ÷ known parameters. This is a fuzzlab
  differentiator: no surveyed product shows how much of a branch was actually attacked
  **(inference)**;
- **clickable counts** that open Findings pre-filtered to the node, as NinjaOne's counts do
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/dashboards-navigation/system-organization-dashboard-navigation/).

**Filters.** Filters only hide nodes; they never delete them
[src](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/site-map-filter).
- In scope only (default on).
- Has open findings.
- Has parameters.
- Untested.
- Method; status class.
- Show discovered (default on, greyed).
- Show SPA routes (default on).
- **Run lens:** all working runs (default), one run, or "diff run A vs B" (R8).
- Text or regex search.

**Structure overrides.** These are stored in the project.
- **Collapse data-like segments** (ZAP's data-driven nodes,
  [src](https://www.zaproxy.org/docs/desktop/start/features/sitestree/)).
  - fuzzlab could **suggest** collapses from its DOM MinHash clusters
    (`fuzzlab/core/dedup.py`) once they are persisted. `page.template_cluster_id` exists
    but is never written today (§16).
  - The user confirms each collapse; nothing collapses automatically.
- **Mark a parameter structural** (split by value).

**Node actions.**
- Scan this branch (opens the R2 dialog with the URL filled in).
- Send to Repeater.
- Include in / exclude from scope.
- Show findings.
- Copy URL.

**Layout.** The three panes ZAP and Burp share: tree on the left; contents table on the top
right (the leaves and flows under the selected node); issues and the message editor on the
bottom right.

### 12.4 Findings view (R6, R7, R8, R9) [TREE][SPLIT]

**R6, issue identity and status.**
- **Issue key** = `(vuln_class, canonical origin, route path, method, parameter name,
  location)`. Each `finding` row becomes an **occurrence** of an issue. This fixes P11.
  - **The key is anchored at the tree's parameter node, not the leaf.** A leaf is named by
    the full set of its parameter names, so a page that gains a parameter gets a new leaf,
    but its existing issues keep their keys. This is deliberate.
  - ZAP's de-duplication blog makes a similar move: it recommends a node-name field for
    comparing alerts across scans
    [src](https://www.zaproxy.org/blog/2025-09-30-alert-de-duplication/).
  - **Dependency:** `finding` has no `location` column today, so the oracle must record it
    (§16).
- **Scanner state**, computed and never stored, over the project's working runs:
  - **New**: only in the latest run that tested this leaf.
  - **Present**: in the latest run and an earlier one.
  - **Regressed**: present, then absent, then present again.
  - **Not reproduced**: tested in the latest run and not confirmed.

  These follow Burp DAST's states
  [src](https://portswigger.net/burp/documentation/dast/user-guide/reference/issue-statuses).
- **User triage state**, persistent per issue key:
  - **Open** (default), **Confirmed**, **False positive**, **Accepted risk**,
    **Fixed (unverified)**.
  - Stored with a reason and timestamp in a **new side table** (e.g. `finding_triage`). It
    never writes to `finding`, which only the oracle writes (`docs/ARCHITECTURE.md`, "The
    store as the contract").
  - Benchmark scoring must **not** read triage state unless a benchmark explicitly opts
    in.
  - Changing severity **requires a reason**, as in Aikido
    [src](https://help.aikido.dev/getting-started/core-functionalities/manually-adjust-issue-severity.md).
  - Scope choices: "this issue / this path / this vuln class on this origin", as in
    Aikido's ignore-scope picker
    [src](https://help.aikido.dev/getting-started/core-functionalities/ignore-issues-to-remove-issues-from-main-feed.md).
- **Two-axis rating.**
  - Keep severity (and say "derived" until it is stored).
  - Map the confirming **mechanism to a confidence tier**, as Greenbone ties QoD to the
    detection method [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
    For example **(inference; the oracle's owners must set the table)**:
    - **Certain**: OOB callback, evaluated template marker, browser-executed XSS.
    - **Firm**: error signature, differential boolean.
    - **Tentative**: timing only.
  - Default view: every confirmed finding. Offer a "Certain/Firm only" saved view.
- **Avoid the override confusion seen in Greenbone.**
  - Triage applies by default; there is no `apply_overrides` toggle.
  - The scope of each triage decision is shown on the row
    [src](https://forum.greenbone.net/t/none-of-my-overrides-appear-to-work/3639).

**R7, evidence.**
- A finding's detail uses the shared message editor to show the confirming **request and
  response side by side, payload and marker highlighted**, as Burp and ZAP do
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/results/issues)
  [src](https://www.zaproxy.org/pdf/ZAPGettingStartedGuide-2.15.pdf).
- It adds a **"Path to issue"** list: page → parameter → candidate rule → confirming
  probes → the confirming mechanism. Today this cannot be assembled: `_write_finding`
  records no candidate or attempt id, and `auto` runs write no `attempt` rows. Burp has an equivalent
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/results/issues).
- It adds a **Detection method** block (mechanism, strategy, version), as Greenbone does
  [src](https://raw.githubusercontent.com/greenbone/gsa/main/src/web/pages/results/ResultDetails.tsx).
- **Dependency.** This needs the confirming flow ids, the candidate id and the location
  recorded when the finding is written. That is a change to `fuzzlab/oracle/oracle.py`,
  which is currently locked (§16).

**R8, run diff.**
- Pick two runs in Runs (or use the tree's run lens) and see **New / Gone / Same /
  Changed**, as in Greenbone [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html).
- Diff **both ways in one view**, fixing Nessus's new-only diff
  [src](https://docs.tenable.com/nessus/Content/CompareScanReportResults.htm).

**R9, Focus / All and the funnel.** Focus/All needs R6's triage table. The funnel and the
not-confirmed reasons do not.
- **Focus** (default): Open and Confirmed issues.
- **All**: also false positives, accepted risk and *candidates the oracle did not confirm*,
  each with its reason. The reason comes from `candidate.oracle_status`
  (`fuzzlab/core/oracle_status.py`): `checked` (looked, no finding), `inconclusive`,
  `skipped_budget`, `no_confirmer` or `pending`. This
  follows Aikido's auto-ignored list with reasons
  [src](https://help.aikido.dev/workflows-and-guides/resolve-dependency-vulnerabilities-with-autotriage-and-ai-autofix.md).
- The Dashboard shows the **funnel**: endpoints → parameters → candidates → confirmed →
  open, with attempts only where a tool records them, as in Huntress's SOC Actions funnel
  [src](https://support.huntress.io/hc/en-us/articles/24001293720083-Huntress-Command-Center-Your-New-Homepage)
  (snippet).
- The funnel is the operator's equivalent of the benchmark's precision/recall, with no
  ground truth needed.

### 12.5 The shortest "URL → results" flow (R2, R3) [SPLIT]

**R2. One dialog, four fields, one button.** It is modelled on Greenbone's Task Wizard and
ZAP's Quick Start.

```
┌ Scan a URL ─────────────────────────────────────────────────────────┐
│ URL        [ http://127.0.0.1:3000/                              ]  │
│            ✓ loopback · in scope of this project                     │
│ Profile    [ Standard — crawl + audit + confirm, ~10 min      ▾ ]   │
│ Identity   [ anonymous                                         ▾ ]   │
│ Categories ☐ sql-injection ☐ xss ☐ server-side-template-injection …  │
│            required: choose at least one (D15; nothing preselected)  │
│                                                                      │
│ ▸ Advanced (scope prefix, budget, browser, OOB …)                    │
│ ▸ Show command    fuzzlab scan http://127.0.0.1:3000/ --profile …    │
│                                                                      │
│  ⚠ Sends traffic to the target. Requires authorized: true.           │
│                                        [ Cancel ]  [ ▶ Scan ]        │
└──────────────────────────────────────────────────────────────────────┘
```

- **Two actions:** type a URL, press Scan. A blank project additionally needs "New project".
- **Default scope** is the URL's directory, as in Burp
  [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
- **Safety stays where it is.**
  - The URL is checked as loopback **before** the button enables.
  - Without `authorized` the button is disabled and the reason is shown.
  - The dry-run preview is the collapsed "Show command" section.
  - The click is the explicit user action D11 requires.
- **One name for the target.** It is always `URL` in the UI. Add a CLI verb with the same
  shape, `fuzzlab scan URL [--profile P] [--identity I] --authorized`.
  - **What the wrapper runs.** It runs **`crawl` then `auto`** into the project, because
    `auto` does not crawl by itself (`harness/auto_cli.py:1-11`).
  - **Categories.** With no ground truth, automatic mode needs an explicit category
    selection and has **no "test everything" default** (D15). So the Scan dialog shows the
    categories as a required field with nothing preselected, and Scan stays disabled until
    at least one is ticked. A user-saved profile may carry a selection the user made
    explicitly. A built-in profile never carries "all". Whether an explicit one-click
    "select all" chip would satisfy D15 is a decision for the owner (§18 Q7).
  - **Authorization.** `crawl` and `audit` have no `--authorized` flag today, so the
    wrapper applies the authorized gate itself before the crawl step.
  - **Launching.** UI launches go through the gated subprocess runner (D18).
  - This fixes P1 and P4 for the common case. The existing tool flags stay for manual
    use.
- **Results appear live.** The site tree fills as the crawl runs, and findings stream into
  the Dashboard funnel, much as Burp's site map fills during a crawl **(inference)**.

**R3. Scan profiles instead of flag forms.**
- **Built-in profiles** are named for their outcome, as Burp's presets are
  [src](https://portswigger.net/burp/documentation/desktop/scanning/built-in-configurations):
  - **Quick**: crawl and audit only, no confirmation traffic beyond the audit's.
  - **Standard**: crawl → audit → oracle-confirm over the categories chosen at launch. No
    single command does this today; R2's wrapper does.
  - **Deep**: adds browser execution, header points and JSON-write fuzzing.
  - **Passive**: crawl only.
- **A profile is a partial overlay** on the defaults, as in Burp's configuration library
  [src](https://portswigger.net/burp/documentation/desktop/settings/library). It is
  stored as JSON, importable and exportable, and copied into the project when used.
- **Profile editor.** Shows each setting as **Inherited** or **Overridden**, with
  **Revert**, plus a count of runs that used the profile, as in NinjaOne
  [src](https://www.ninjaone.com/docs/policies-and-conditions/policies/policy-inheritance/)
  [src](https://www.ninjaone.com/docs/policies-and-conditions/policies/change-override-device-policy/).
- **Locked at run time.** A profile used by a run is copied into that run, so editing it
  never changes history. Nessus locks policy tuning in the same way
  [src](https://docs.tenable.com/nessus/Content/TemplateSettings.htm).
- **Ground-truth options belong to benchmark profiles only:** `--ground-truth` and
  `--points ground-truth`.
- **Model options stay available to working profiles, collapsed.**
  - The model options are `--score`, `--rank`, `--train-on`, `--model-id`, `--calibrate`,
    `--holdout`, `--hybrid`, `--confirm-budget`, `--budget-method` and `--anomaly*`.
  - They work without ground truth. They learn from oracle labels, either this run's
    (`--train-on run`) or earlier runs' against the same target (`--train-on earlier`).
    Some, like `--anomaly`, use no labels at all.
  - They are real operator features (budgeted confirmation, ranking), so a working profile
    may use them. They sit in a collapsed **Model-assisted** group, never in the basic
    form. This fixes P3.
  - Whether `--holdout` is benchmark-only is §18 Q6.
- **Folders and tags.** NinjaOne users complain that policies have no folders
  [src](https://capterra.com/p/184229/NinjaOne/reviews?page=1) (snippet), so profiles
  should support them.

### 12.6 Working vs benchmark separation (R5) [SPLIT]

This recommendation is for the session separating the two kinds of run. Combine Burp's
isolated scan with a stamped-output rule (Huntress's Incident Simulation is a similar,
less well-sourced idea):

- **Project kind** is fixed at creation and shown in the title bar.
  - A **Working** project targets a URL. It has no ground truth, and its Dashboard is
    operational.
  - A **Benchmark** project targets lab apps with ground truth. Its Dashboard shows
    F1/MCC, request efficiency, holdout state and model lineage.
  - ML/Models and Diagnostics show by default only in benchmark projects.
- **Run kind** is a new column with three values:
  - `working`;
  - `benchmark`;
  - `trial`: a run used to *test a profile*. Its results stay out of the site tree's
    default lens, Findings and the Dashboard, and are reachable only from Runs. ("Isolated"
    is avoided because it already names FR-SESS-17's `#isolated:<n>` identities and
    FR-FUZZ-44's isolated paths.) This is modelled on Burp's isolated scan
    [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/setting-pro-scope).
- **Allowed combinations.** A working project holds `working` and `trial` runs. A
  benchmark project holds `benchmark` and `trial` runs.
- **Benchmark output is stamped.** Benchmark findings and reports carry a visible
  **BENCHMARK** stamp, so a benchmark export can never pass for a real assessment. This is
  our design choice. Huntress's Incident Simulation is a similar idea, but its "Simulated"
  stamp was read only from a search snippet
  [src](https://support.huntress.io/hc/en-us/articles/30950483531539-EDR-ITDR-Incident-Simulation)
  (§17).
- **Where models live.** Models are rows in a project's `model` table, so they stay
  inside one project file. **(inference; the [SPLIT] session decides)**
  - **Training on earlier runs** against the same target (`--train-on earlier`) stays
    inside one project and needs no ground truth.
  - **Using a model trained elsewhere** means *exporting* it from one project and
    *importing* it into another. Its provenance (source project UUID, run ids, feature
    version) is copied along.
  - **No live cross-project read.** R1's one-project-per-process rule rules it out.
  - **Ground-truth scoring** happens only in benchmark projects.
- **The CLI mirrors the split.**
  - `fuzzlab scan` for working runs.
  - `fuzzlab bench …` gathers `auto --ground-truth` / `--points ground-truth`, `report` and
    `reveal-holdout`.
  - The model flags stay on `fuzzlab scan` as advanced options.
  - `fuzzlab lab …` gathers `lab-generate`. `build-db` rebuilds the auditor's indicator
    DB, so it stays a tool.
  - Existing commands stay as aliases (fixes P13).

### 12.7 What to hide by default

| Hide (reachable via Advanced / research toggle / benchmark project) | Keep visible |
| --- | --- |
| Ground-truth flags (benchmark projects only); model-assisted flags (collapsed); `greybox-run`, `mutate-run`, `flow-anomaly`, `reveal-holdout`, `lab-generate`, `build-db` | Scan a URL; Site map; Findings; Runs |
| The per-tool launcher forms (move to Tools → Manual tools) | Proxy (History, Intercept, Repeater) |
| Detection-quality and efficiency KPIs (move to Benchmark) | Safety chips: target, authorized, proxy, budget |
| Diagnostics and the raw store explorer | Project switcher and saved indicator |
| Bandit posteriors, plugins list, anomaly settings | Dry-run "Show command" (collapsed, one click away) |
| Advanced scan options (scope prefix, budget, browser, OOB, header points) | Profile, identity and category pickers (categories required, D15) |
| (Whether to hide Tentative findings by default is open: §18 Q3) | Focus/All toggle with counts |

---

## 13. Wireframes

The names, counts and scores in these wireframes are illustrative, not measured.

### 13.1 Main shell: Site map (three panes)

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│ fuzzlab │ juice-shop ▾  WORKING · saved 2s │ ⌕ /  │ 127.0.0.1:3000 · ● authorized · proxy off │
├──────────┬───────────────────────────────────────────────────────────────────────────────┤
│ Dashboard│ Site map   [In scope ✓][Discovered ✓][SPA ✓][Untested][Has findings]  run: All ▾ │
│▸Site map │ ┌──────────────────────────────┬───────────────────────────────────────────────┐ │
│ Findings │ │▾ http://127.0.0.1:3000  ●4 78%│ /rest/products/search  GET (q)                 │ │
│ Runs     │ │  ▾ #  SPA routes        ●2    │ method path              params  status  tested│ │
│──Tools───│ │    ▸ /#/search (q)ᶜ     ●1    │ GET   …/search?q=apple   q       200     ✓     │ │
│ Proxy    │ │  ▾ /rest                      │ GET   …/search?q='       q       500     ✓ ●   │ │
│ Manual   │ │    ▾ /products                │                                               │ │
│──Config──│ │      ▸ search GET (q)   ●1    │───────────────────────────────────────────────│ │
│ Profiles │ │  ▾ /profile                   │ Issues (1)  ● critical  sql-injection  Firm    │ │
│ Scope/IDs│ │      ▸ GET  —           ○     │ [Request | Response]  payload ⟦'⟧ highlighted  │ │
│          │ │      ▸ POST ()(username)●1    │ GET /rest/products/search?q=⟦'⟧ HTTP/1.1       │ │
│          │ │  ░ /ftp  (discovered)         │ … SQLITE_ERROR: ⟦near "'": syntax error⟧ …     │ │
│ [▶ Scan] │ └──────────────────────────────┴───────────────────────────────────────────────┘ │
└──────────┴───────────────────────────────────────────────────────────────────────────────┘
```

### 13.2 Dashboard (working project)

```
┌ Dashboard · juice-shop (WORKING) ────────────────────────────────────────────────────────┐
│ [▶ Scan a URL]                                                                             │
│ Funnel   endpoints 84 → params 211 → candidates 57 → confirmed 9 → open 7                 │
│ Open issues  ● 3 critical  ● 2 high  ● 2 medium        Coverage  ▓▓▓▓▓▓▓░░ 78% params tested│
│ Recent runs                                                                                │
│  #12 Standard  2026-10-14 14:02  done      +2 new  −1 gone  [diff vs #11]                  │
│  #11 Standard  2026-10-13 09:40  done                                                     │
│  #10 Quick     2026-10-12 17:11  interrupted  [Resume…]                                    │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 13.3 Findings (Focus view)

```
┌ Findings  (Focus ▾ | All)   ⌕ filter…   [Severity ▾][Class ▾][Confidence ▾][Status ▾]  Views: ★ Open crit ┐
│ sev  class          location                                conf     state    triage   seen  │
│ ●c   sql-injection  GET /rest/products/search · q          Firm     Present  Open     3 runs│
│ ●c   ssti           POST /profile · username → /#/profile  Certain  New      Open     1 run │
│ ●h   xss-reflected  GET /#/search · q (client)             Certain  Present  Confirmed 2 runs│
│ …                                                                                            │
│ ▸ 48 not confirmed (checked 31 · inconclusive 9 · skipped_budget 6 · no_confirmer 2) ← "All" │
│ [Report this view…]                                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 13.4 Finding detail

```
┌ sql-injection · GET /rest/products/search · q ─────────────── ● critical (derived) · Firm ┐
│ Triage [Open ▾]  reason [            ]  scope (•) this issue ( ) this path ( ) class/origin │
│ Seen in runs #10 #11 #12 (Present)          [Send to Repeater] [Rescan this leaf]          │
│ ── Evidence ─────────────────────────────────────────────────────────────────────────────── │
│ Request  ⟦payload⟧ highlighted          │ Response  ⟦marker⟧ highlighted                    │
│ ── Path to issue ───────────────────────────────────────────────────────────────────────── │
│ page /#/search → param q (query) → audit rule → 14 probes → error-signature ✓              │
│ ── Detection method ─────────────────────────────────────────────────────────────────────── │
│ mechanism error-signature · strategy SqliErrorStrategy · fuzzlab 0.x                       │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 13.5 Runs and diff

```
┌ Runs ────────────────────────────────────────────────────────────────────────────────────┐
│ ☐ #12 working  Standard  done         9 confirmed                                         │
│ ☐ #11 working  Standard  done         8 confirmed                                         │
│ ☐ #9  trial    Deep*     done         (kept out of Site map / Findings)                   │
│ [Diff selected]  →  New 2 · Gone 1 · Same 6 · Changed 0   (both directions)               │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### 13.6 Scan profile editor

```
┌ Profile: Standard (custom: "Standard + browser") ── base: Standard ── used by 4 runs ─────┐
│ Crawl     max depth        3          Inherited                                            │
│           engine           playwright Overridden  [Revert]                                 │
│ Confirm   browser (M6)     on         Overridden  [Revert]                                 │
│           OOB (M8)         off        Inherited                                            │
│ Budget    requests         5000       Inherited                                            │
│ (Ground-truth options: benchmark profiles only. Model-assisted options: collapsed.)        │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 13.7 Benchmark project Dashboard

```
┌ Dashboard · lab-bench-01 (BENCHMARK) ─────────────────────────────────────────────────────┐
│ Ground truth  lab/ground-truth @ sha 3f2c…   categories 14                                  │
│ Latest scored run #41   F1 0.82 · MCC 0.79 · P 0.86 · R 0.78 · req/finding 212              │
│ Holdout   sealed (v3) · revealed 0×   [Reveal… (counts the reveal)]                         │
│ Models    classifier m-17 (Platt) · ranker r-9  →  [Models & ML]  [Diagnostics]             │
│ Every export from this project is stamped BENCHMARK.                                        │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Additional recommendations

- **R10, reports equal the current view.** "Report this view…" on Findings produces
  HTML/JSON/Markdown/SARIF for exactly the filtered issues. This follows Nessus and
  Greenbone
  [src](https://docs.tenable.com/nessus/Content/CreateAScanReport.htm)
  [src](https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html), with ZAP's
  template set as a reference
  [src](https://www.zaproxy.org/docs/desktop/addons/report-generation/templates/).
  - Group by type, severity or URL, as Burp does
    [src](https://portswigger.net/burp/documentation/desktop/automated-scanning/reporting/report-settings).
  - Include a plain-language summary per finding, as Huntress does
    [src](https://support.huntress.io/hc/en-us/articles/54383533080979-In-Depth-Understanding-of-Huntress-EDR-and-ITDR-Incident-Reports)
    (snippet). Thin reporting is the most common complaint about Huntress and NinjaOne.
- **R11, global search with `/`.** Extend proxy history's existing full-text search
  (`flow_fts`) project-wide, across URLs, findings, runs and profiles. Support a `kind:` prefix and keep the query in the
  URL, as NinjaOne does
  [src](https://www.ninjaone.com/docs/new-to-ninjaone/search-tools/global-search-platform/).
- **Performance guardrails.** Burp and ZAP users complain about frozen tables and slow
  trees ([src](https://portswigger.net/blog/performance-improvements-to-table-sorting-and-repeater),
  [src](https://github.com/zaproxy/zaproxy/issues/3881)).
  - Load the tree lazily, one level per request, from indexed queries.
  - Page tables on the server above a few thousand rows.
  - The current Findings page loads up to 5,000 rows on the client
    (`web/findingsview.py`). That is fine today; set a threshold for when it changes.

---

## 15. Ranked recommendations (impact × effort)

Impact is how much each one reduces "unnecessarily complicated and hard to use".
- Effort: S = days; M = about a week; L = several weeks.
- Both ratings are our estimates **(inference)**.

| Rank | Rec. | What | Impact | Effort | Owner | Depends on |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | R2 | "Scan a URL" dialog + `fuzzlab scan` verb (crawl → auto, explicit categories, authorized gate) | **High** | S–M | [SPLIT] | R3 (can ship with hard-coded profiles first) |
| 2 | R1 | Project lifecycle: start screen, `--project`, recent list, temporary → save as, snapshot, saved indicator | **High** | M | [PROJ] | — |
| 3 | R5 | Project kind + run kind; Dashboard split; hide research tools in working projects | **High** | M | [SPLIT] | R1 |
| 4 | R4 | Site tree (origin → path → `#` route → leaf → params), states, roll-ups, filters | **High** | M–L | [TREE] | R1; per-run origin and discovered/cluster writers (§16) |
| 5 | R3 | Scan profiles (built-ins, overlay, editor with inherited/overridden, copy-on-run) | High | M | [SPLIT] | — |
| 6 | R6 | Issue key, cross-run states, `finding_triage` side table, confidence tiers | High | M | [TREE] | R4 (shared identity); finding location (§16) |
| 7 | R7 | Evidence: linked flows, highlighted request/response, path to issue | Medium–High | M | [TREE] | oracle change (locked file, §16) |
| 8 | R8 | Two-way run diff | Medium | S | [TREE] | R6 |
| 9 | R9 | Funnel on Dashboard; not-confirmed reasons; Focus/All views | Medium | S | [SPLIT] | R6 for Focus/All only |
| 10 | R11 | `/` global search | Medium | S–M | any | — |
| 11 | R10 | Report = current view | Medium | M | any | R6 |
| 12 | — | Rename Results → Runs; move Lab and generators out of the project nav | Low | S | any | — |

**Quick wins that need no new data:**
- R2 with fixed profiles, since it wraps existing commands;
- the funnel part of R9 (endpoints, parameters, candidates, findings);
- the Results → Runs rename;
- moving the F1/MCC tiles off a working project's Dashboard.

**Changes that need schema additions or new writes:**
- **R1:** project metadata in `meta`, plus the D21 global config DB.
- **R4:** a per-run origin, and persisting discovered-not-requested and template clusters.
- **R5:** `run.kind`.
- **R6:** `finding_triage`.
- **R6/R7:** finding location, plus links to the candidate and the confirming flows.

Each needs a migration and a `docs/ARCHITECTURE.md` "store as contract" update in the
session that builds it.

---

## 16. Constraints the designs must keep, and follow-up notes

**Invariants.** Every recommendation above keeps these:
- **D11, no auto-run.** Opening a project, a profile or a tree node never sends traffic.
- **Loopback only, and `--authorized` for anything that sends traffic.** These are checked
  against the current environment, never against the project file.
- **D12, credentials in the OS keyring.** A project stores identity names, never stored
  credentials. It can still contain secrets the user typed, because
  `repeater_tab.raw_request` is kept verbatim. The redacted export strips headers with
  `fuzzlab/proxy/redact.py::redact`, and parameter names and bodies with
  `fuzzlab.core.redaction`.
- **The oracle is the only writer of `finding`** (`docs/ARCHITECTURE.md`, "The store as
  the contract"), and ML writes scores, never labels. Triage is a separate, user-owned
  layer. D9/D10 add that the oracle never reads ground truth.
- **D14/D15, category selection.** A working scan without ground truth must name its
  categories, with no "test everything" default. R2 makes categories a required field with
  nothing preselected, and built-in profiles never carry "all".
- **D18, gated subprocess runner.** Every UI launch goes through it.
- **D21, storage layout.** Per-project SQLite files plus a small global config DB.
- **NFR-UI-read-only** (`docs/components/12-diagnostics-and-ui/requirements.md`). The UI
  never writes result tables (`finding`, `attempt`, `candidate`). The one documented
  exception is `saved_views`. The Repeater's `repeater_tab` / `run` / `flow` writes are
  recorded as a known gap ("Not yet enforced"), not an approved exception. A `finding_triage` table, stored profiles, scope edits
  and project metadata would be **new UI-written state**. The building session must amend
  that requirement explicitly, not work around it. Those writes go through the existing
  `SecurityGateMiddleware` POST rules and never touch the result tables. R1's Compact and
  Drop-bodies operations rewrite or delete tool output, so they need the same explicit
  amendment or must stay CLI-only.
- **PA-0003 / PA-0021, one definition.** The tree must reuse `canonical_origin`,
  `to_path`, `to_route_path`, `spa_route` and `url_key` from `fuzzlab/core/urls.py`, not
  reimplement them.

**Follow-up notes for locked files.**
- **Where the lock comes from.** This session's dispatching prompt locked these files,
  because another session has unpushed work in them.
- **When it lifts.** When `origin/ccr-27885270-9ahcdd` carries a BUG-0138 commit.
- **No in-repo record.** BUG-0138 does not exist in this repository yet, so nothing
  in-repo records the lock.
- These files are not changed here.
- **`fuzzlab/oracle/oracle.py`** (`_write_finding`). Record:
  - the confirming flow ids;
  - the strategy name and version;
  - the candidate id (`finding.attempt_id` is never set today);
  - the parameter `location` (no `finding` column carries it).

  R6 and R7 depend on this.
- **`fuzzlab/harness/auto_cli.py`**:
  - accept `--profile`, or let a new `fuzzlab scan` wrapper in `fuzzlab/cli.py` translate a
    profile into today's flags (R2, R3). Either way the wrapper runs `crawl` first, since
    `auto` does not crawl;
  - move the ground-truth flags (`--ground-truth`, `--points ground-truth`) to the
    benchmark entry point (R5), and group the model flags as advanced.
- **`fuzzlab/tools/spider.py`, `fuzzlab/tools/store_adapter.py`, `fuzzlab/harness/pipeline.py`.**
  - **Unwritten columns.** Nothing writes `page.discovered_from` or
    `page.template_cluster_id` today. The only `page` writer is `store_adapter.py:119`,
    and `TemplateClusterer` runs in memory in the pipeline.
  - **Needed for R4.** The discovered state and collapse suggestions need those columns
    written, plus a per-run origin (`target` rows are written only by the pipeline).
- **`fuzzlab/session/cli.py`, `fuzzlab/session/manager.py`.**
  - Identities already used are recorded in `session_state` (host, identity). These can
    feed R2's identity picker without touching the locked files.
  - Listing identities that are stored but never used needs a names-only listing from the
    keyring layer.
- **`fuzzlab/core/urls.py`**. Nothing needs to change; R4 only reads its helpers.

---

## 17. Method, verification and limits

**Mechanism.** Seven research sub-agents ran in parallel, one per product. Each used public
web sources only (WebSearch + WebFetch) and was told to cite every claim, mark inference,
and stop rather than answer from memory if the tools failed. All seven reported the tools
worked.

| Product | WebSearch queries | WebFetch attempts (succeeded) | Blocked sources |
| --- | --- | --- | --- |
| Burp Suite | ~18 | 22 (most) | G2 (403); some docs URLs 404, alternatives used |
| ZAP | 10 | 51 (47) | G2 (403) |
| Nessus | ~28 | 24 (22) | G2, Capterra (403) |
| Greenbone | 10 | 24 (most) | G2, Capterra (403); some GitHub raw paths 404 |
| Huntress | 25 | 13 (7) | support.huntress.io, feedback.huntress.com, G2, Capterra, Gartner (403); Reddit blocked |
| NinjaOne | 20 | 25 (21) | G2, Capterra, Gartner (403) |
| Aikido | 15 | 41 (38) | G2, Capterra, Software Advice (403); Reddit blocked |

Notes on sources:
- The ZAP agent also ran three read-only searches of public `zaproxy/zaproxy` GitHub issues
  through the GitHub integration. Every GitHub issue cited is a public page.
- Several Aikido help pages contained embedded instructions addressed to automated agents.
  The agent ignored them.

**Independent verification.** The orchestrating session re-fetched 8 load-bearing claims
itself. All 8 matched:
1. Burp's isolated-scan purpose, its fragment support and its default directory scope.
2. ZAP's leaf naming, structural parameters and data-driven nodes.
3. ZAP's Client Map showing fragments the Sites tree cannot.
4. ZAP's persist-session options.
5. Nessus locking Discovery/Assessment/Report/Advanced/Compliance/SCAP/Plugins in scans
   built from a policy, with credentials the exception.
6. Greenbone's QoD ≥ 70 default, the four delta states, and override precedence (overrides
   are off by default).
7. Aikido's Focus vs All views and its status values.
8. NinjaOne's Inherited / Overridden labels and hover-to-Revert.

The fuzzlab facts in §10 were read directly from the code. The form sizes were counted with
`fuzzlab.web.commandspec.all_specs()`.

**Not verified, or verified only from search snippets.** Do not lean on these alone:
- **Review-site content.** All G2, Capterra and Gartner material, and every claim marked
  (snippet).
- **Huntress help pages.** Most support.huntress.io content (snippet), including the
  Incident Simulation page. The pattern is still useful, but confirm its details before
  citing it as fact.
- **Burp:**
  - how Pro matches issues across separate scans;
  - whether 4xx responses are hidden in the site map by default;
  - default resource-pool values.
- **ZAP:**
  - whether Sites-tree nodes carry alert flags;
  - the exact keyboard shortcuts.
- **Nessus:**
  - whether editing a policy changes scans already created from it;
  - whether the "Resources" left-nav label exists.
- **Greenbone:**
  - whether appliance-only features (Tickets, Compliance) exist in the Community Edition;
  - the exact "Dashboards" menu label.
- **NinjaOne:** the complete current left nav (dashboards are being redesigned).
- **Aikido:**
  - the exact left-nav labels;
  - keyboard shortcuts;
  - whether AutoFix applies to DAST findings;
  - the vendor's noise-reduction percentages.

**Independent review.** Two read-only reviewer sub-agents reviewed the first version
(commit `14372a4`).
- **Reviewer A** checked every fuzzlab claim against the code. It reported 7 blocking
  findings, including:
  - the "Run full pipeline" button is a stub;
  - `auto` does not crawl;
  - several schema columns are never written;
  - `auto` writes no attempt rows;
  - stored URLs are path-only;
  - the ML flags work without ground truth;
  - D21 already exists.
- **Reviewer B** re-fetched 34 product claims and checked internal consistency. It
  reported 2 blocking findings: Burp's temporary projects *can* be converted, and NinjaOne
  policies are not edited "only" under Administration.
- **Resolution.** The orchestrating session verified each blocking finding against the code
  or the source, then applied every finding, minor items included, in the next commit.
- **Re-review.** Reviewer B approved the fixed version. Reviewer A confirmed all 23 of its
  original findings resolved, and raised one new blocking point: the first fix's
  "all categories" default contradicted D15. That point and the remaining nits were fixed
  in a third commit.

**What this document is not.** It is not a specification. Requirement IDs, schema DDL and
UI acceptance criteria belong to the sessions that build R1 to R11, with their own
change-control and `requirements.md` updates.

## 18. Open questions for the owner

1. **Project kind.** Is kind fixed per project (Working vs Benchmark, as recommended), or
   should one project be able to hold both kinds of run, kept apart only by run kind?
2. **File extension.** Should the project extension be `.fuzzlab`, or should it stay `.db`?
3. **Default confidence.** Should Tentative (timing-only) findings show by default, or sit
   behind a filter as Greenbone's QoD floor does?
4. **Triage scope.** Should user triage be allowed to feed benchmark scoring as an explicit
   opt-in, or never?
5. **Temporary project as default.** Should `fuzzlab web` with no arguments open a
   temporary project, as Burp Community does, or show the start screen?
6. **Holdout.** Should `--holdout` (a sealed evaluation split) be available in working
   projects, or only in benchmark projects?
7. **"Select all" categories.** D15 forbids a "test everything" default for runs without
   ground truth. Would an explicit one-click "select all categories" chip in the Scan
   dialog satisfy D15, or should D15 be amended, or should users always tick categories
   one by one?
