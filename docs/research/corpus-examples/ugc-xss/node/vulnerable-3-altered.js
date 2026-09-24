// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 7 of 10). Genuinely distinct third
// variant from vulnerable-1.js/vulnerable-2.js (raw innerHTML/
// dangerouslySetInnerHTML of an unsanitized comment) and idiomatic-1.jsx
// (DOMPurify.sanitize() interposed): a server-rendered comment pipeline
// using markdown-it, a real, widely-used Markdown-to-HTML library, with its
// own documented `html` option left at its constructor default.
const MarkdownIt = require('markdown-it');

// VULNERABLE: markdown-it's `html` option controls whether raw HTML tags
// embedded in the Markdown source pass through into the rendered output
// unchanged. It defaults to `false`, but here it is explicitly enabled
// (`html: true`) -- a real, documented real-world misconfiguration
// (commonly turned on so users can embed things like <br> or <sup> in
// comments), which also lets an attacker's comment body embed a literal
// `<script>`/`<img onerror=...>` tag that markdown-it will emit verbatim.
const md = new MarkdownIt({ html: true });

function renderCommentBody(commentMarkdown) {
  return md.render(commentMarkdown);
}

module.exports = { renderCommentBody };
