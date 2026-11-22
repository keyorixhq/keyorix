package main

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

// TestEdgeInstall_TalksOnlyToItsOwnServer is the regression test for #4356:
// another process of the CI job holds the port the install's config names
// when the server starts, and answers /health and /system/init like an
// initialised Keyorix. The edge helpers must reach the server they started,
// never that process: bootstrap and login against it are what failed in the
// queue ("already_initialized", login 401).
func TestEdgeInstall_TalksOnlyToItsOwnServer(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real server processes")
	}
	e := newEdgeInstall(t, buildServerBinary(t), true)

	// The foreign process takes the install's port before the start.
	ln, err := net.Listen("tcp", "127.0.0.1:"+e.port)
	if err != nil {
		t.Fatalf("occupy the install's port %s: %v", e.port, err)
	}
	foreign := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:gosec // test server, closed below
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_, _ = fmt.Fprint(w, `{"status":"ok"}`)
		case "/system/init":
			_, _ = fmt.Fprint(w, `{"data":{"already_initialized":true},"message":"System already initialised","success":true}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})}
	go func() { _ = foreign.Serve(ln) }()
	t.Cleanup(func() { _ = foreign.Close() })

	p := e.start("", "KEYORIX_BOOTSTRAP_TOKEN="+edgeBootTok)
	e.waitHealthy(p)
	a := e.api()
	a.bootstrap(t)
	a.login(t)
	e.kill9(p)
}
