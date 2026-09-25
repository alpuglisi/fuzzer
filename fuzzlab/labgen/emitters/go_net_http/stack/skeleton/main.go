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

	addr := host() + ":" + port()
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

// host defaults to 127.0.0.1 -- unchanged behavior for every existing
// direct-host-process caller (this stack's own live-boot/navigability test
// harnesses). CC-LAB-0247 (Lane 7, Gate D)'s container entrypoint sets
// HOST=0.0.0.0 so the platform's port-publish (`-p 127.0.0.1:<host>:8080`)
// can actually reach this process: binding the process itself to
// 127.0.0.1 *inside* a container is unreachable from the host's
// port-forwarding path (verified live -- a published port's traffic never
// arrives at a loopback-only listener in the container's own netns). The
// loopback-only guarantee is enforced by the host-side compose bind, not
// by this process's own listen address.
func host() string {
	if h := os.Getenv("HOST"); h != "" {
		return h
	}
	return "127.0.0.1"
}
