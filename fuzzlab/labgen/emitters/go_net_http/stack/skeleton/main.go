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

func main() {
	mux := http.NewServeMux()
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
