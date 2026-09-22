<?php
/**
 * Source: common-repository/reckoning (WordPress.org plugin "Reckoning",
 * SVN-mirror), reckoning.php, function display_reckoning_admin_page_individual().
 * License: MIT
 * Copyright (c) 2014 Shawn Patrick Rice <rice@shawnrice.org>
 * (author's public attribution email, from the plugin's own file header —
 * kept verbatim as the required MIT attribution line; not third-party PII)
 *
 * Pattern: same shape as vulnerable-1.php (a WordPress admin page that lists
 * a user's stored comments), but here comment_content is passed through
 * wp_kses_post() — WordPress's allowlist-based HTML sanitizer (strips
 * <script>, event-handler attributes, etc., while still permitting the
 * "post" tag/attribute allowlist) — before being concatenated into the
 * output. This is the idiomatic/safe counterpart to vulnerable-1.php's raw
 * echo of the same comment_content field.
 */

function display_reckoning_admin_page_individual( $user ) {
	// ... (surrounding admin-page rendering omitted; see repository for full file)

	$comments = get_comments( array( 'user_id' => $user->ID ) );

	if ( empty( $comments ) ) {
		echo '"' . esc_html( ucwords( $user->display_name ) ) . '" ';
		echo esc_html( __( 'has not posted a comment', 'reckoning' ) );
		echo '.</h3>';
	} else {
		echo '<h3>' . esc_html( __( 'Total Comments', 'reckoning' ) ) . ': ' . count( $comments ) . '</h3>';
		echo "<table class = 'reckoning-table'>";
		echo "<tr><th colspan='2'>User Comments</th></tr>";
		foreach (  $comments as $comment ) :
			$post = get_post( $comment->comment_post_ID );
			preg_match( '/([0-9]{4})-([0-9]{2})-([0-9]{2})/', $comment->comment_date, $matches );
			$date = "{$matches[2]}/{$matches[3]}/{$matches[1]}";
			echo '<tr>';
			echo '<td>';
			echo esc_html( __( 'On', 'reckoning' ) );
			echo ' <a href="' . esc_url( $post->guid . '#comment-' . $comment->comment_ID ) . '">';
			echo esc_html( $post->post_title ) . '</a></td>';
			echo '<td>' . esc_html( $date ) . '</td>';
			echo '</tr>';
			echo '<tr><td colspan="2">' . wp_kses_post( $comment->comment_content ) . '</td></tr>';
		endforeach;
		echo '</table>';
	}
}
