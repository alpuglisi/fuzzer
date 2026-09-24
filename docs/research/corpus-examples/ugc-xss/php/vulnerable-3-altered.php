<?php
// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 8 of 10). Genuinely distinct
// third variant from vulnerable-1.php (raw, zero-sanitization echo),
// idiomatic-1.php (wp_kses_post() allowlist sanitizer), and idiomatic-2.php
// (per-field htmlspecialchars() escaping): a comment-rendering function
// that DOES call a sanitizer -- strip_tags() with an allowed-tags list --
// but strip_tags() only ever removes disallowed TAG NAMES; it never
// inspects or strips ATTRIBUTES on tags it allows through, a well-
// documented, real-world strip_tags() misuse.

class CommentRenderer {

    function renderComment($comment) {
        // VULNERABLE: strip_tags() with an allowed-tags list removes any
        // tag NOT in that list, but does nothing to attributes on the tags
        // it DOES allow -- an <img> or <a> tag survives with any
        // attributes an attacker included, e.g. <img src=x onerror=...>
        // or <a href="javascript:...">, since neither `onerror` nor a
        // `javascript:` URL scheme is a tag name strip_tags() would ever
        // consider stripping.
        $safeBody = strip_tags($comment['body'], '<b><i><a><img>');
        return '<div class="comment-body">' . $safeBody . '</div>';
    }
}
