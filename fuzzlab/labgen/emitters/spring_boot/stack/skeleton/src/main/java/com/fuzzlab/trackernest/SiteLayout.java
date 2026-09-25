package com.fuzzlab.trackernest;

import java.nio.charset.StandardCharsets;

import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;

/**
 * The shared HTML layout every browsable page of a spring_boot lab app
 * renders into (CC-LAB-0244 / FR-LAB-164, Browsable Labs Lane 4).
 *
 * <p>Generic on purpose: the app's name, brand colour and nav are passed in
 * as arguments by generated code (the page complexity and the generated
 * {@code SiteController}), derived from one place, the Python
 * {@code APP_REGISTRY} ({@code fuzzlab/labgen/emitters/spring_boot/app_site.py}).
 * A page's vulnerable and secure twins therefore get a byte-identical layout
 * by construction: nothing here reads the request or the cell.
 *
 * <p>Inline CSS only, no external assets (the lab stays offline and
 * loopback-only). The layout's string literals carry no run of 3 or more
 * digits (plan S7: an SSTI arithmetic-product canary must never find a
 * coincidental match in the chrome), which is checked offline.
 */
public final class SiteLayout {

    private SiteLayout() {
    }

    private static final String CSS = String.join("\n",
        // CC-LAB-0244 (S7): a digit-only hex triplet like #222 is itself a
        // 3+-digit run, so this dark grey mixes in a letter instead.
        "body{margin:0;font-family:system-ui,sans-serif;color:#2a2a2a;background:#f6f6f6}",
        "header{color:#fff;padding:0.8em 1.5em}",
        "header h1{margin:0;font-size:1.4em}",
        "header h1 a{color:#fff;text-decoration:none}",
        "nav{margin-top:0.5em}",
        "nav a{color:#fff;margin-right:1em;text-decoration:underline}",
        "main{max-width:60em;margin:1.5em auto;padding:1em 1.5em;background:#fff}",
        "footer{text-align:center;color:#7a7a7a;font-size:0.8em;padding:1em}",
        "pre{background:#f0f0f0;padding:0.8em;white-space:pre-wrap;word-break:break-all}",
        // CC-LAB-0244 (S7): width stays just under full width here -- a
        // 3+-digit run in the layout chrome could coincidentally match an
        // SSTI arithmetic-product canary; every other CSS value here
        // already stays under 3 digits.
        "textarea{width:99%;min-height:8em;font-family:monospace}",
        "input[type=text]{width:30em;max-width:99%}",
        "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:0.3em 0.6em;text-align:left}");

    /** HTML-escapes any text before it goes into a page. */
    public static String esc(String text) {
        return HtmlUtils.htmlEscape(text == null ? "" : text, StandardCharsets.UTF_8.name());
    }

    /** The whole document: header (app name + nav), main, footer. */
    public static String html(String appName, String brand, String navHtml, String title, String mainHtml) {
        return "<!DOCTYPE html>\n"
            + "<html lang=\"en\">\n"
            + "<head>\n"
            + "<meta charset=\"utf-8\">\n"
            + "<title>" + esc(title) + " - " + esc(appName) + "</title>\n"
            + "<style>\n" + CSS + "\nheader{background:" + brand + "}\n</style>\n"
            + "</head>\n"
            + "<body>\n"
            + "<header><h1><a href=\"/\">" + esc(appName) + "</a></h1>\n"
            + "<nav>" + navHtml + "</nav></header>\n"
            + "<main>\n" + mainHtml + "\n</main>\n"
            + "<footer>" + esc(appName) + " is a deliberately vulnerable, lab-only demo app.</footer>\n"
            + "</body>\n"
            + "</html>\n";
    }

    /** A {@code text/html} response with an explicit content type (never negotiated, plan S2). */
    public static ResponseEntity<String> htmlResponse(int status, String html) {
        return ResponseEntity.status(status)
            .header("Content-Type", "text/html;charset=UTF-8")
            .body(html);
    }

    /**
     * A page-classified route's response (plan §2b): the page's form, plus --
     * only when the handler actually ran the source/sink -- the sink's own
     * body, HTML-escaped into a result block, at the sink's own status code.
     * {@code result == null} is the declared absent-input branch
     * ({@code form_when_absent}): the form alone, 200, no sink run.
     */
    public static ResponseEntity<String> page(String appName, String brand, String navHtml, String title,
                                              String formHtml, ResponseEntity<String> result) {
        String main = formHtml;
        int status = 200;
        if (result != null) {
            status = result.getStatusCode().value();
            String body = result.getBody() == null ? "" : result.getBody();
            main = main + "\n<section class=\"result\"><h2>Result</h2><pre>" + esc(body) + "</pre></section>";
        }
        return htmlResponse(status, html(appName, brand, navHtml, title, main));
    }

    /**
     * A declared absent-input rejection (plan §2e), returned before any sink
     * runs: a short, static plain-text message (never request-derived), with
     * an explicit content type.
     */
    public static ResponseEntity<String> missingInput(int status, String message) {
        return ResponseEntity.status(status)
            .header("Content-Type", "text/plain;charset=UTF-8")
            .body(message);
    }
}
