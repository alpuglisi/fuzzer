<?php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 8 of 10). Derived from
// vulnerable-2-altered.php's real CommentRenderer structure. Minimal-pair
// discipline: identical class/method name, identical output shape. The
// ONLY mechanism difference: strip_tags() is called with NO allowed-tags
// list at all (so every tag, and therefore every attribute an attacker
// could hide on one, is removed) and the fully-stripped result is then
// passed through htmlspecialchars() as well, so any leftover angle
// brackets from a malformed/partial tag strip_tags() couldn't fully parse
// are rendered as inert text rather than live markup.

class CommentRenderer {

    function renderComment($comment) {
        // IDIOMATIC: no allowed-tags argument at all means strip_tags()
        // removes every HTML tag (and, with it, every attribute that
        // could otherwise carry a payload), and htmlspecialchars() on top
        // neutralizes any remaining '<'/'>'/'"' characters strip_tags()
        // itself leaves behind on malformed input -- defense in depth,
        // rather than relying on strip_tags()'s allowed-tags list to also
        // police attributes, which it was never designed to do.
        $safeBody = htmlspecialchars(strip_tags($comment['body']));
        return '<div class="comment-body">' . $safeBody . '</div>';
    }
}
