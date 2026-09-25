package main

import (
	"net/http"
	"os"
)

// webhookSecret is a fixed, per-run shared secret for this stack's Phase A
// illustrative cell (an HMAC-signature-verified webhook receiver). Real
// per-deployment secret management is out of this lab skeleton's scope --
// every other stack's own skeleton similarly hardcodes lab-only fixed
// values (e.g. a fixed DB path) rather than modeling real secret rotation.
var webhookSecret = []byte("fuzzlab-go-net-http-lab-fixed-demo-secret")

// jwtSecret is this stack's own fixed, per-run shared HMAC key for its
// JWT-protected illustrative cell -- the same "lab-only, no real secret
// rotation" simplification webhookSecret above already is, kept as its
// own variable (not reused from webhookSecret) since they model two
// conceptually distinct secrets a real deployment would never share.
var jwtSecret = []byte("fuzzlab-go-net-http-lab-fixed-demo-jwt-secret")

func main() {
	mux := http.NewServeMux()
	// CC-LAB-0243 (FR-LAB-162, R5): the site layer's own route (the
	// homepage) registers before the generated per-cell routes so a
	// pattern conflict at startup (R5) surfaces from either side equally.
	registerSiteRoutes(mux)
	registerRoutes(mux)

	addr := "127.0.0.1:" + port()
	if err := http.ListenAndServe(addr, mux); err != nil {
		panic(err)
	}
}

func port() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "8080"
}
