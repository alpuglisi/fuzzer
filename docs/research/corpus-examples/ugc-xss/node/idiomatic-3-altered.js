// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 7 of 10). Derived from
// vulnerable-3-altered.js's real markdown-it structure. Minimal-pair
// discipline: identical import, identical renderCommentBody() shape. The
// ONLY mechanism difference is the `html` constructor option: `false` (this
// file, and also markdown-it's own documented default) instead of `true`,
// so any literal HTML tags typed into a comment's Markdown source are
// escaped as inert text in the rendered output instead of being emitted as
// live markup.
const MarkdownIt = require('markdown-it');

// IDIOMATIC: `html: false` -- markdown-it's own documented default --
// means raw HTML embedded in the Markdown source is escaped rather than
// passed through, so a comment body can never introduce a live <script>/
// event-handler-bearing tag via this render path, regardless of what a
// user types.
const md = new MarkdownIt({ html: false });

function renderCommentBody(commentMarkdown) {
  return md.render(commentMarkdown);
}

module.exports = { renderCommentBody };
