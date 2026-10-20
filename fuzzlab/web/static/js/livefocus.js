// The user's place across a live refresh (FR-UI-514, CC-UI-0068, BUG-0534): the one
// helper every page that re-renders itself while open uses to remember and restore the
// focused control (tests/test_web_live_focus.py keeps it the only one).
//
// A focusable control a live region re-renders carries a focus key (`data-focus-key`)
// naming its identity -- what it is, never its position -- unique in its region. Before a
// re-render the focused control's key is read; after it, focus goes back to the control
// with that key, else to the first usable fallback the caller names, ending at the
// region's pane (a container with tabindex="-1" that is always rendered), never the page
// body. Focus counts only where it actually landed, and restoring never scrolls.

// a candidate focus may land on: connected, not inside [hidden], rendered
function usable(el) {
  return el instanceof Element && el.isConnected && !el.closest("[hidden]")
    && el.getClientRects().length > 0;
}

// focus `el` without scrolling; true only if focus is now on it
function tryFocus(el) {
  if (!usable(el)) return false;
  el.focus({ preventScroll: true });
  return document.activeElement === el;
}

// the focus key of the control focused inside `root` (`root` included), "" when that
// element has no key, or null when focus is not inside `root`
export function focusKeyIn(root) {
  const a = document.activeElement;
  if (!a || a === document.body || !root.contains(a)) return null;
  const keyed = a.closest("[data-focus-key]");
  return keyed && root.contains(keyed) ? keyed.getAttribute("data-focus-key") : "";
}

// After a re-render of `root`: when focus was inside it (`key` is not null) and is no
// longer on a connected element inside it, focus the control with `key`, else the first
// usable fallback (an element, or a function returning one), else `root` itself. Returns
// the element focused (the one still focused when nothing was lost), or null when focus
// was elsewhere or even `root` refused it. It never takes focus from outside `root`.
export function restoreFocus(root, key, ...fallbacks) {
  if (key === null || key === undefined) return null;
  const a = document.activeElement;
  if (a && a !== document.body && a.isConnected && root.contains(a)) return a;
  const candidates = [];
  if (key) candidates.push(() => root.querySelector(`[data-focus-key="${CSS.escape(key)}"]`));
  candidates.push(...fallbacks, root);
  for (const c of candidates) {
    const el = typeof c === "function" ? c() : c;
    if (el && tryFocus(el)) return el;
  }
  return null;
}

// remember the focused control's key, run `draw()` (synchronous), restore
export function rerender(root, draw, ...fallbacks) {
  const key = focusKeyIn(root);
  draw();
  return restoreFocus(root, key, ...fallbacks);
}

function copyAttributes(to, from) {
  for (const at of [...to.attributes]) if (!from.hasAttribute(at.name)) to.removeAttribute(at.name);
  for (const at of [...from.attributes]) {
    if (to.getAttribute(at.name) !== at.value) to.setAttribute(at.name, at.value);
  }
}

// Put `newEl` in `oldEl`'s place. When `oldEl` holds the focused control and `newEl`
// holds its counterpart (the same focus key), nothing on the focused control's path is
// removed (a removed node loses focus, and a screen reader announces it again): those
// nodes are kept and take their counterparts' attributes, the focused control its text,
// and every other child is replaced around them. Returns the element now in place.
export function patchInPlace(oldEl, newEl) {
  const a = document.activeElement;
  const keyed = a && oldEl.contains(a) ? a.closest("[data-focus-key]") : null;
  const key = keyed && oldEl.contains(keyed) && keyed !== oldEl
    ? keyed.getAttribute("data-focus-key") : null;
  const twin = key ? newEl.querySelector(`[data-focus-key="${CSS.escape(key)}"]`) : null;
  if (!twin) {
    oldEl.replaceWith(newEl);
    return newEl;
  }
  let keep = oldEl, model = newEl;
  for (;;) {
    copyAttributes(keep, model);
    if (keep === keyed) {
      if (keep.textContent !== model.textContent) keep.textContent = model.textContent;
      return oldEl;
    }
    const holder = [...keep.childNodes].find((c) => c.contains(keyed));
    const twinHolder = [...model.childNodes].find((c) => c.contains(twin));
    const kids = [...model.childNodes];
    const at = kids.indexOf(twinHolder);
    for (const c of [...keep.childNodes]) if (c !== holder) c.remove();
    holder.before(...kids.slice(0, at));
    holder.after(...kids.slice(at + 1));
    keep = holder;
    model = twinHolder;
  }
}
