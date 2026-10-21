"""The composed UI tree a crawler's page script reads (SP-70; BUG-0551, FR-CRAWL-39).

A page's interactive surface is not only its document's light tree: a web component
renders into a shadow root, and an embedded frame holds a document of its own.
``document.querySelectorAll`` sees neither. Both crawlers enumerated with it, so a search
form inside an open shadow root was absent from disco's candidate list and from the
spider's form list (BUG-0551).

`COMPOSED_JS` is the one walk every crawler page script that discovers or locates UI
builds on: function definitions a script concatenates at the top of its body, as
`spa._LABELS_FN` is. They are:

* ``composedWalk(root, visit, max)`` -- every element under ``root`` (a Document, a
  ShadowRoot or an Element; ``root`` itself excluded) in tree order, each **open** shadow
  tree right after its host and before the host's light children. ``visit`` returning
  ``false`` stops it. It returns whether it stopped at ``max`` elements. On a page with
  no shadow root the order is document order, so ``composedAll(document, s)`` is
  ``document.querySelectorAll(s)``.
* ``composedAll(root, selector, max)`` and ``composedFind(root, selector)`` -- matches in
  that order.
* ``composedParent(el)`` -- the parent element, or the host at a shadow tree's top.
  ``composedClosest(el, selector)`` is ``closest`` continued at each host.
* ``composedHosts(root)`` -- the set of elements that are, or hold, an open shadow host.
  ``deepAll(deep, root, selector, max)`` and ``deepFind(deep, root, selector)`` query
  ``root``'s composed subtree, and use the native light-tree query when ``deep`` says
  no shadow host is below it. A page without shadow roots costs what it did before.
  ``root`` may be a shadow root itself (a widget whose controls sit directly under it
  has no container element, BUG-0551 review B1): it is always walked, since ``deep``
  holds elements only.

What a page script cannot reach is stated, never claimed:

* A **closed** shadow root is unreachable (``host.shadowRoot`` is ``null``). disco
  counts every host of one through DevTools (`disco.compose._census`).
* A **frame's** document is another realm. It is read by the same script run in that
  frame, never by walking into ``contentDocument`` (the DevTools listener query only
  sees its own realm's listeners: measured, BUG-0551). Which frames are read is the
  caller's decision: disco reads same-origin, in-scope frames (`disco.compose`).

A light-tree-only query in a crawler page script is a reviewed allowance with its count
and its reason (`tests/test_composed_tree_guard.py`).
"""

from __future__ import annotations

#: The composed-tree helpers (see the module doc), for concatenation into a page
#: script's body.
COMPOSED_JS = r"""
  const composedParent = (e) => e.parentElement
    || (e.parentNode && e.parentNode.nodeType === 11 && e.parentNode.host) || null;
  const composedClosest = (e, sel) => {
    for (let x = e; x; ) {
      const hit = x.closest(sel);
      if (hit) return hit;
      const root = x.getRootNode();
      x = root && root.host ? root.host : null;
    }
    return null;
  };
  const composedWalk = (root, visit, max) => {
    const stack = [];
    const push = (p) => {
      const kids = p.children || [];
      for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
    };
    push(root);
    if (root.shadowRoot) push(root.shadowRoot);
    let n = 0;
    while (stack.length) {
      if (max && n >= max) return true;
      const e = stack.pop();
      n++;
      if (visit(e) === false) return false;
      push(e);
      if (e.shadowRoot) push(e.shadowRoot);
    }
    return false;
  };
  const composedAll = (root, sel, max) => {
    const out = [];
    composedWalk(root, (e) => { if (e.matches(sel)) out.push(e); }, max);
    return out;
  };
  const composedFind = (root, sel) => {
    let hit = null;
    composedWalk(root, (e) => { if (e.matches(sel)) { hit = e; return false; } });
    return hit;
  };
  const composedHosts = (root) => {
    const deep = new Set();
    composedWalk(root, (e) => {
      if (!e.shadowRoot) return;
      for (let x = e; x && !deep.has(x); x = composedParent(x)) deep.add(x);
    });
    return deep;
  };
  const deepAll = (deep, root, sel, max) => (deep.has(root) || root.shadowRoot
      || root.nodeType === 11)
    ? composedAll(root, sel, max) : Array.from(root.querySelectorAll(sel));
  const deepFind = (deep, root, sel) => (deep.has(root) || root.shadowRoot
      || root.nodeType === 11)
    ? composedFind(root, sel) : root.querySelector(sel);
"""
