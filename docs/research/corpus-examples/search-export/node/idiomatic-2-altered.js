/**
 * MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
 * mechanics". Missing idiomatic counterpart for vulnerable-2.js's
 * CWE-1336 SSTI (this cell's own manifest.yaml entry: jeffreyPG/node-api's
 * _getElement(), which compiles user-authored report-editor content AS a
 * Handlebars template via `extendedHandlebars.compile(content)`). Per
 * this cell's manifest.yaml own note, no license-clean real-world
 * counterpart of "the same app rendering user content as data into a
 * FIXED precompiled template" was found in the original collection pass,
 * so this is manufactured from vulnerable-2.js's own real structure per
 * the plan's methodology, using exactly the mitigation shape that note
 * itself names as missing.
 *
 * Minimal-pair discipline: identical imports, identical helper
 * (`list`), identical `formatEditorText()`, identical overall
 * `_getElement()` control flow and exports. The ONLY mechanism
 * difference is in the "p" branch: instead of compiling the
 * user-authored `content` itself as a Handlebars template (making it
 * template CODE), this version compiles a single FIXED, developer-authored
 * template ONCE at module load and passes the user's formatted content
 * into it purely as template DATA (`{{content}}`), which Handlebars
 * HTML-escapes by default and never evaluates as template syntax --
 * closing the SSTI hole while producing the same paragraph-wrapped
 * output shape.
 */
"use strict";

const Handlebars = require("handlebars");
const {
  allowInsecurePrototypeAccess
} = require("@handlebars/allow-prototype-access");
const sanitizeHtml = require("sanitize-html");

function escapeHtml(html) {
  return sanitizeHtml(html, { allowedAttributes: false, allowedTags: false });
}

// Widens Handlebars to allow prototype property access from templates --
// itself a known SSTI-adjacent footgun when the template source isn't trusted.
const extendedHandlebars = allowInsecurePrototypeAccess(Handlebars);

extendedHandlebars.registerHelper("list", function(items, options) {
  if (!items || items.length === 0) {
    const text = options.fn();
    return `<span>${text}</span>`;
  }
  const itemsText = items.reduce((acc, item) => {
    const value = options.fn(item);
    if (value) acc.push(value);
    return acc;
  }, []);
  return `<span>${itemsText.join(", ")}</span>`;
});

function formatEditorText(content = "") {
  content = content.replace(/(?:\r\n|\r|\n)/g, "<br>") || "-";
  content = content.replace(/&lt;/g, "<");
  content = content.replace(/&gt;/g, ">");
  content = content.replace(/<p><br><\/p>/g, "<p> </p>");
  return content;
}

// SAFE: this is the ONLY developer-authored template source ever passed
// to `extendedHandlebars.compile()`. It is fixed at module load time and
// never built from `elementObj.content` -- contrast vulnerable-2.js,
// which compiles the untrusted content itself as the template source.
const FIXED_PARAGRAPH_TEMPLATE = extendedHandlebars.compile("{{content}}");

/*
 * Generate one report element's HTML. `elementObj.content` originates
 * from the user-facing report editor (saved report definitions), not
 * from a fixed template file.
 */
const _getElement = async function(elementObj, data, customDate, building) {
  if (elementObj.ele === "p") {
    // ... (report-specific data enrichment omitted; see full source)

    let content = elementObj.content || "";
    content = formatEditorText(content);

    // SAFE: `content` is passed to the FIXED, precompiled
    // FIXED_PARAGRAPH_TEMPLATE purely as template DATA (the `{{content}}`
    // placeholder) -- Handlebars HTML-escapes it by default and it is
    // never itself compiled/executed as a template, so any Handlebars
    // syntax an author embeds in their report text (helper calls,
    // `{{#with}}`, etc.) renders as inert literal text instead of
    // running server-side.
    let compiledData = FIXED_PARAGRAPH_TEMPLATE({ content, ...data });

    compiledData = compiledData.replace(/\&\#x27\;/g, `'`);
    compiledData = compiledData.replace(/\&quot;/g, `"`);
    return (
      "<" + elementObj.ele + ">" + compiledData + "</" + elementObj.ele + ">"
    );
  }
  if (elementObj.ele) {
    return (
      "<" + elementObj.ele + ">" + (elementObj.content || "-") + "</" + elementObj.ele + ">"
    );
  }
  return "";
};

module.exports = { _getElement, formatEditorText, escapeHtml };
