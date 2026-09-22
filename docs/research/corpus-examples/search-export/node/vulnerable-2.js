/**
 * Fragment from a PDF/HTML report-builder controller
 * (app/controllers/api/api.report.server.controller.js). Trimmed from the
 * full ~3000-line file to the relevant imports and the one function that
 * matters for this cell -- see this directory's manifest.yaml for the
 * full source attribution and commit.
 *
 * Shape: an end user builds a report in a rich-text "report editor" UI.
 * The saved editor HTML for each report element (`elementObj.content`)
 * is compiled AS A HANDLEBARS TEMPLATE -- not rendered as literal data --
 * and then executed against the report's own data object. Because the
 * template source is attacker/user-controlled editor content rather than
 * a fixed .hbs file on disk, any Handlebars helper/expression an author
 * embeds in their report text (e.g. `{{#with}}`/prototype-access via
 * @handlebars/allow-prototype-access, which this file explicitly enables)
 * is evaluated server-side when the report is rendered/exported -- classic
 * SSTI in an export-generation pipeline (CWE-1336), not a one-off "user
 * input reaches a template" toy case: it is threaded through a whole
 * report-composition system (helpers, per-element handlers, table/chart
 * builders) that treats untrusted editor content as trusted template code.
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

    // VULNERABLE: compiles user-editable report content AS a Handlebars
    // template, then executes it against `data` -- if `content` contains
    // Handlebars syntax (e.g. a helper call reaching a prototype property
    // via allowInsecurePrototypeAccess above), it runs server-side at
    // export/render time. A safe equivalent would treat `content` as
    // plain data (e.g. interpolate it into a *fixed* pre-compiled
    // template rather than compiling the user content itself).
    const template = extendedHandlebars.compile(content);
    let compiledData = template(data);

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
