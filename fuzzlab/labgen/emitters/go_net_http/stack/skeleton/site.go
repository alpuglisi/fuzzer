package main

import (
	"html"
	"net/http"
)

// CC-LAB-0243 (FR-LAB-162, Browsable Labs Lane 3): the shared HTML layout
// every browsable page of this stack's lab app renders into. Hand-written,
// identical in every build -- no per-cell content lives here (the minimal
// pair's own transform/sink region is untouched, BUG-0027).
//
// Inline CSS only, no external assets (the lab stays offline and
// loopback-only). The layout's own string literals carry no standalone
// 3-digit decimal token (R4: guards against a coincidental match by the
// SSTI cell's arithmetic-product canary) and no word from
// AccessControlIdorStrategy's own denial-marker list (R4).
const siteCSS = `body{margin:0;font-family:system-ui,sans-serif;color:#222;background:#f6f6f6}
header{background:#6441a5;color:#fff;padding:0.8em 1.5em}
header h1{margin:0;font-size:1.4em}
header h1 a{color:#fff;text-decoration:none}
nav{margin-top:0.5em}
nav a{color:#fff;margin-right:1em;text-decoration:underline}
main{max-width:60em;margin:1.5em auto;padding:1em 1.5em;background:#fff}
footer{text-align:center;color:#777;font-size:0.8em;padding:1em}
table{border-collapse:collapse}
td,th{border:1px solid #ccc;padding:0.3em 0.6em;text-align:left}
input[type=text]{width:30em;max-width:100%}
form p{margin:0.6em 0}`

// siteNav lists every real page URL, sorted, used by the homepage and by
// every rendered page's own nav bar (R5: a plain, static list, not derived
// from the mux at request time).
var siteNav = []struct{ path, label string }{
	{"/", "Home"},
	{"/api/clips/thumbnail", "Clip thumbnail"},
	{"/auth/login-redirect", "Login redirect"},
	{"/channels/analytics", "Analytics"},
	{"/channels/commands", "Chat commands"},
	{"/channels/emotes/upload", "Upload emote"},
	{"/channels/profile", "Edit profile"},
	{"/channels/redirect", "Channel redirect"},
	{"/channels/settings", "Settings"},
	{"/channels/subscribers", "Subscribers"},
	{"/clips/download", "Download clip"},
	{"/dashboard", "Dashboard"},
	{"/clips/export", "Export clips"},
	{"/sessions/refresh", "Session refresh"},
	{"/subscriptions/purchase", "Subscribe"},
	{"/webhooks/eventsub", "EventSub webhook"},
}

func navHTML() string {
	out := ""
	for _, item := range siteNav {
		out += "<a href=\"" + item.path + "\">" + html.EscapeString(item.label) + "</a>"
	}
	return out
}

// renderPage writes the whole document: header (brand + nav), main, footer.
// Called by generated source/sink code (CC-LAB-0243) for every declared
// absent-input page and for the HTML-converted dashboard pages -- always
// with static or already-escaped content, never raw request input.
func renderPage(w http.ResponseWriter, status int, title, bodyHTML string) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!DOCTYPE html>\n" +
		"<html lang=\"en\">\n" +
		"<head>\n" +
		"<meta charset=\"utf-8\">\n" +
		"<title>" + html.EscapeString(title) + " - LoopCast</title>\n" +
		"<style>\n" + siteCSS + "\n</style>\n" +
		"</head>\n" +
		"<body>\n" +
		"<header><h1><a href=\"/\">LoopCast</a></h1>\n" +
		"<nav>" + navHTML() + "</nav></header>\n" +
		"<main>\n" + bodyHTML + "\n</main>\n" +
		"<footer>LoopCast is a deliberately vulnerable, lab-only demo app.</footer>\n" +
		"</body>\n" +
		"</html>\n"))
}

// sitePageSpec is one form_on_get route's static page content -- title, a
// short description, and the form itself. The form has no `action`
// attribute and its own fetch()/submission always targets
// `location.pathname` (R1): rendered identically whether the request
// reached the vulnerable route's own path or a secure twin's suffixed
// path, so the two stay byte-identical.
type sitePageSpec struct {
	title string
	body  string
}

// siteFormPages holds one entry per `absent_input: form_on_get` route
// (CC-LAB-0243 §2d), keyed by the route's canonical `route.path` -- the
// same key `sitePage` is called with for both a route's vulnerable cell
// and its secure twin, so the page is a pure function of that key and the
// two are byte-identical (R1).
var siteFormPages = map[string]sitePageSpec{
	"/webhooks/eventsub": {
		title: "EventSub webhook",
		body: "<h2>EventSub webhook</h2>" +
			"<p>This endpoint receives Twitch-style EventSub notifications. " +
			"Send a signed <code>POST</code> with a JSON body to this URL.</p>",
	},
	"/channels/profile": {
		title: "Edit profile",
		body: "<h2>Edit profile</h2>" +
			"<form method=\"post\">" +
			"<p><label>Display name<br><input type=\"text\" name=\"display_name\"></label></p>" +
			"<p><label>Bio<br><input type=\"text\" name=\"bio\"></label></p>" +
			"<p><button type=\"submit\">Save</button></p>" +
			"</form>",
	},
	"/channels/emotes/upload": {
		title: "Upload emote",
		body: "<h2>Upload emote</h2>" +
			"<form method=\"post\" enctype=\"multipart/form-data\">" +
			"<p><label>Emote image<br><input type=\"file\" name=\"emote\"></label></p>" +
			"<p><button type=\"submit\">Upload</button></p>" +
			"</form>",
	},
	"/subscriptions/purchase": {
		title: "Subscribe",
		body: "<h2>Subscribe</h2>" +
			"<form method=\"post\">" +
			"<p><label>Plan<br><input type=\"text\" name=\"plan\" value=\"tier1\"></label></p>" +
			"<p><button type=\"submit\">Subscribe</button></p>" +
			"</form>",
	},
	"/channels/commands": {
		title: "Chat commands",
		body: "<h2>Chat commands</h2>" +
			"<form method=\"post\">" +
			"<p><label>Command<br><input type=\"text\" name=\"command\"></label></p>" +
			"<p><button type=\"submit\">Run</button></p>" +
			"</form>",
	},
	// Every POST route gets a GET client page (the accumulator registers
	// one for every POST cell, CC-LAB-0243 §2b), not only the routes
	// classified `form_on_get`: /sessions/refresh's own absent-input
	// declaration is `no_input` (its source reads nothing), so this page
	// has no form fields to submit, just a plain POST button.
	"/sessions/refresh": {
		title: "Session refresh",
		body: "<h2>Session refresh</h2>" +
			"<p>Refresh your session token.</p>" +
			"<form method=\"post\">" +
			"<p><button type=\"submit\">Refresh</button></p>" +
			"</form>",
	},
}

// sitePage returns the GET handler for a form_on_get route's page, keyed by
// its canonical `route.path` (CC-LAB-0243 §2b). It never runs the route's
// own source/sink -- a bare GET always serves the static form, identically
// on both twins.
func sitePage(routePath string) http.HandlerFunc {
	spec, ok := siteFormPages[routePath]
	if !ok {
		// Every accumulator call site names a route actually present in
		// siteFormPages (offline-checked); this is an emitter-internal
		// contract violation, not a request-time condition.
		panic("site.go: sitePage: no page registered for " + routePath)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, http.StatusOK, spec.title, spec.body)
	}
}

// homepageBody links every real page (siteNav), grouped as dashboard pages
// and account/content actions -- no other content.
const homepageBody = `<h2>Welcome to LoopCast</h2>
<p>A small streaming-platform demo. Use the nav above, or the links below,
to reach every page.</p>
<h3>Dashboard</h3>
<ul>
<li><a href="/channels/analytics">Channel analytics</a></li>
<li><a href="/channels/subscribers">Subscribers</a></li>
<li><a href="/channels/settings">Account settings</a></li>
</ul>
<h3>Channel</h3>
<ul>
<li><a href="/channels/profile">Edit profile</a></li>
<li><a href="/channels/emotes/upload">Upload emote</a></li>
<li><a href="/channels/commands">Chat commands</a></li>
</ul>
<h3>Clips &amp; subscriptions</h3>
<ul>
<li><a href="/clips/export">Export clips</a></li>
<li><a href="/clips/download">Download a clip</a></li>
<li><a href="/subscriptions/purchase">Subscribe</a></li>
</ul>`

func homepageHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, "Home", homepageBody)
}

// dashboardHandler is the real page `/auth/login-redirect`'s own declared
// default (R7) sends an absent `next` value to -- it must actually exist
// and answer 200 (the secure twin's own allowlist regex also requires a
// slash followed by an alphanumeric character, which "/" alone fails).
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, "Dashboard", homepageBody)
}

// registerSiteRoutes wires the routes the site layer owns outright: the
// homepage (`GET /{$}`, R5, an exact match -- Go 1.22+ `ServeMux` treats a
// bare `GET /` as a catch-all subtree, which would swallow every unknown
// path with a 200 instead of the mux's own 404) and `/dashboard`.
func registerSiteRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", homepageHandler)
	mux.HandleFunc("GET /dashboard", dashboardHandler)
}
