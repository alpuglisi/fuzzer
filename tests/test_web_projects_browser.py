"""Project files in a real browser (CC-UI-0450; PA-0065: "renders" needs a browser).

Drives the start screen and the project lifecycle through Chromium against a live app
started with the **built-in default config** from an empty working directory, and asserts
zero page errors, console errors and CSP violations on every page it visits:

- first launch: `/` → the start screen (Temporary first; the default store offered);
- New → home, the topbar chip names the project;
- a temporary project: leaving it without ticking "discard" is blocked by the browser
  (the box is `required`) and refused by the server when forced; ticking it deletes it;
- Save as keeps the runs and opens the copy; Snapshot is listed and the project stays;
- Remove from list leaves the file; a leftover temporary's Discard needs its box.

Skips only when the browser cannot run, and fails instead under
`FUZZLAB_REQUIRE_BROWSER=1` (`tests/_browser.py`).
"""

from __future__ import annotations

import os
from pathlib import Path

from tests._browser import Server, free_port, launch_browser_or_skip, require_modules

require_modules()
from playwright.sync_api import sync_playwright  # noqa: E402

from fuzzlab.core.config import load_config  # noqa: E402
from fuzzlab.core.store import Store  # noqa: E402
from fuzzlab.web.app import create_app  # noqa: E402

_CSP_COLLECTOR = """
window.__cspViolations = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`);
});
"""


def test_project_lifecycle_in_a_real_browser(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)                       # the default ./fuzzlab.db lives here
    port = free_port()
    projects_dir = tmp_path / "projects"
    cfg = load_config(overrides={"web_port": port, "projects_dir": str(projects_dir)},
                      environ={})
    server = Server(create_app(cfg), port)
    server.start()
    base = f"http://127.0.0.1:{port}"
    problems: list[str] = []
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            ctx = browser.new_context()
            ctx.add_init_script(_CSP_COLLECTOR)
            page = ctx.new_page()
            page.set_default_timeout(15000)
            page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
            page.on("console", lambda m: problems.append(f"console: {m.text}")
                    if m.type == "error" else None)

            def check():
                problems.extend(f"csp: {v}" for v in
                                page.evaluate("window.__cspViolations || []"))

            # first launch: the start screen
            page.goto(base + "/")
            assert page.url == base + "/projects"
            assert page.locator("#start-temporary").is_visible()
            assert str(work / "fuzzlab.db") in page.locator("#start-default").inner_text()
            assert "none" in page.locator("#project-chip").inner_text()
            check()

            # New → home, chip shows it
            page.fill("#start-new input[name=name]", "alpha")
            page.click("#start-new button[type=submit]")
            page.wait_for_url(base + "/")
            assert "alpha" in page.locator("#project-chip").inner_text()
            check()
            with Store(projects_dir / "alpha.fuzzlab", create=False) as store:
                store.start_run("crawl", "h")     # some data to carry through Save as

            # Snapshot: listed, project stays open
            page.goto(base + "/projects")
            page.click("#project-current form[action='/projects/snapshot'] button")
            page.wait_for_url(base + "/projects")
            assert "Snapshot saved as alpha-snapshot-" in page.content()
            assert "alpha-snapshot-" in page.locator("#project-files").inner_text()
            assert "alpha" in page.locator("#project-chip").inner_text()
            check()

            # a temporary project: leaving needs the discard box
            page.click("#start-temporary button[type=submit]")
            page.wait_for_url(base + "/")
            chip = page.locator("#project-chip").inner_text()
            assert "temporary" in chip and "not saved" in chip
            page.goto(base + "/projects")
            tmp_files = list((projects_dir / ".temporary").glob("tmp-*.fuzzlab"))
            assert len(tmp_files) == 1
            with Store(tmp_files[0], create=False) as store:
                store.start_run("crawl", "h")     # Save as must carry this run over
            page.fill("#start-new input[name=name]", "beta")
            page.click("#start-new button[type=submit]")     # box unticked: blocked
            assert page.url == base + "/projects" and tmp_files[0].exists()
            invalid = page.evaluate(
                "document.querySelector('#start-new input[name=discard]').validity.valid")
            assert invalid is False
            # forced past the browser: the server refuses too
            page.evaluate("document.querySelector('#start-new input[name=discard]')"
                          ".removeAttribute('required')")
            page.click("#start-new button[type=submit]")
            page.wait_for_url(base + "/projects")
            assert "leaving it deletes it" in page.content() and tmp_files[0].exists()
            # Save as keeps it (and its identity), then Close
            page.fill("#project-current input[name=name]", "kept")
            page.click("#project-current form[action='/projects/save-as'] button")
            page.wait_for_url(base + "/projects")
            assert not tmp_files[0].exists() and (projects_dir / "kept.fuzzlab").exists()
            assert "kept" in page.locator("#project-chip").inner_text()
            check()

            # Remove from list leaves the file
            row = page.locator("#project-recent tr", has_text="alpha").first
            row.locator("form[action='/projects/forget'] button").click()
            page.wait_for_url(base + "/projects")
            assert "Removed from the recent list" in page.content()
            assert (projects_dir / "alpha.fuzzlab").exists()
            check()

            # a temporary closed with its box ticked is gone
            page.click("#start-temporary button[type=submit]")
            page.wait_for_url(base + "/")
            page.goto(base + "/projects")
            tmp2 = list((projects_dir / ".temporary").glob("tmp-*.fuzzlab"))
            assert len(tmp2) == 1
            page.check("#project-current form[action='/projects/close'] input[name=discard]")
            page.click("#project-current form[action='/projects/close'] button")
            page.wait_for_url(base + "/projects")
            assert not tmp2[0].exists()
            assert page.locator("h1#projects-h1").inner_text().strip() == "Start"

            # every page renders with the project open
            page.locator("#project-files input[value='kept.fuzzlab']").check()
            page.click("#start-open button[type=submit]")
            page.wait_for_url(base + "/")
            for path in ("/", "/projects", "/project", "/launcher", "/results",
                         "/findings"):
                page.goto(base + path)
                assert "kept" in page.locator("#project-chip").inner_text(), path
                check()
            page.goto(base + "/project")
            assert "crawl" in page.locator("#project-history").inner_text()
            browser.close()
    finally:
        server.stop()
    assert problems == [], problems
    assert not (work / "fuzzlab.db").exists()      # nothing created the default store
    assert os.listdir(work) == []


def test_a_leftover_temporary_discard_needs_its_box_in_a_real_browser(tmp_path, monkeypatch):
    import asyncio

    from fuzzlab.web import projects
    monkeypatch.chdir(tmp_path)
    projects_dir = tmp_path / "projects"
    cfg = load_config(overrides={"store_path": "", "projects_dir": str(projects_dir)},
                      environ={})
    earlier = projects.ProjectManager(cfg)                 # an earlier session's leftover
    asyncio.run(earlier.temporary())
    leftover = Path(earlier.store_path())
    projects._release_owner(earlier.current.owner_fd)
    earlier.current.owner_fd = None
    port = free_port()
    cfg = load_config(overrides={"store_path": "", "projects_dir": str(projects_dir),
                                 "web_port": port}, environ={})
    server = Server(create_app(cfg), port)
    server.start()
    base = f"http://127.0.0.1:{port}"
    try:
        with sync_playwright() as pw:
            browser = launch_browser_or_skip(pw)
            page = browser.new_page()
            page.set_default_timeout(15000)
            page.goto(base + "/projects")
            card = page.locator("#project-leftovers")
            assert leftover.name in card.inner_text()
            card.locator("form[action='/projects/discard-temporary'] button").click()
            assert page.url == base + "/projects" and leftover.exists()   # box required
            card.locator("form[action='/projects/discard-temporary'] input[name=discard]").check()
            card.locator("form[action='/projects/discard-temporary'] button").click()
            page.wait_for_url(base + "/projects")
            assert "Temporary project discarded" in page.content()
            assert not leftover.exists()
            browser.close()
    finally:
        server.stop()
