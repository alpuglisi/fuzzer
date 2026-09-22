<?php
/**
 * Source: GiovanniSalmeri/yellow-comment (Yellow CMS "comment" plugin),
 * comment.php.
 * License: GNU GPL v2.0 (see repository LICENSE.md) — copyleft: this is a
 * minimal excerpt (the comment-rendering fragment of one method), not a
 * wholesale file copy, per this corpus's copyleft-handling rule.
 *
 * Pattern: a real CMS comment-plugin renders each stored comment's author
 * name and metadata through htmlspecialchars() before interpolating it into
 * the HTML output — the plain, idiomatic per-field-escaping counterpart to
 * vulnerable-1.php's raw echo of an unescaped comment field. (Uses classic
 * htmlspecialchars escaping rather than an allowlist sanitizer like
 * idiomatic-1.php's wp_kses_post(), showing a second real idiomatic shape.)
 */

class YellowCommentPlugin {

	// ... (surrounding plugin class/method context omitted; see repository
	// for full file)

	function renderCommentHtml($comment) {
		$output = "";
		if ($comment["meta"]["published"] !== "No") {
			$output .= "<div class=\"comment\" id=\"" . htmlspecialchars($comment["meta"]["uid"]) . "\">\n";
			$output .= "<div class=\"comment-icon\"><img src=\"" . $this->getUserIcon($comment["meta"]["from"]) . "\" width=\"" . $iconSize . "\" height=\"" . $iconSize . "\" alt=\"Image\" /></div>\n";
			$output .= "<div class=\"comment-main\">\n";
			$output .= "<div class=\"comment-name\">" . htmlspecialchars($comment["meta"]["name"]) . "</div>\n";
			$output .= "<div class=\"comment-date\">".$this->yellow->language->getDateFormatted(strtotime($comment["meta"]["created"]), $this->yellow->language->getText("coreDateFormatLong")) . "</div>\n";
		}
		return $output;
	}
}
