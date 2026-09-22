<?php
/**
 * Source: common-repository/bp-groupblog (WordPress.org plugin "BP GroupBlog",
 * SVN-mirror), themes/p2/inc/ajax.php, function get_comment().
 * License: GNU GPL v3.0 (see repository license.txt) — copyleft: this is a
 * minimal excerpt (single function + its immediate class context), not a
 * wholesale file copy, per this corpus's copyleft-handling rule.
 *
 * Pattern: an authenticated AJAX endpoint (post-comment inline-edit UI) fetches
 * a stored comment and echoes its raw comment_content straight into the AJAX
 * response with no escaping and no sanitizer of any kind. Any HTML/script an
 * attacker embedded in a comment when it was first submitted is replayed
 * verbatim to whoever opens the inline-edit UI for that comment — a stored-XSS
 * shape sitting inside a real, published comment-moderation/edit pipeline,
 * distinct from fuzzlab's existing basic reflected html_body case.
 */

class BP_GroupBlog_P2_Ajax {

	// ... (surrounding class members omitted; see repository for full file)

	function get_comment() {
		check_ajax_referer( 'ajaxnonce', '_inline_edit' );
		if ( !is_user_logged_in() ) {
			die( '<p>'.__( 'Error: not logged in.', 'p2' ).'</p>' );
		}
		$comment_id = esc_attr($_GET['comment_ID']);
		$comment_id = substr( $comment_id, strpos( $comment_id, '-' ) + 1);
		$comment = get_comment($comment_id);
		echo $comment->comment_content;
	}
}
