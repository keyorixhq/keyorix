package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProxyForwardsRequestTargetVerbatim sends raw request lines through the proxy and asserts the
// upstream receives exactly the same request-target (and not an absolute URI built from a "//"
// prefix), so the server answers the request that was recorded.
func TestProxyForwardsRequestTargetVerbatim(t *testing.T) {
	got := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.RequestURI + " host=" + r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()

	p, err := NewProxy()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetUpstream(up.URL)
	upHost := up.Listener.Addr().String()

	for _, target := range []string{
		"/api/v1/projects",
		"//api/v1/projects",
		"///api/v1/projects",
		"///auth/login?x=1&y=%2F",
		"/a%2Fb//c",
		"//a%2Fb",
	} {
		conn, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target, p.Addr())
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("%q: %v", target, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%q: status %d, want 204 from upstream", target, resp.StatusCode)
		}
		select {
		case g := <-got:
			if want := target + " host=" + upHost; g != want {
				t.Errorf("upstream saw %q, want %q", g, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%q: upstream saw no request", target)
		}
		recs := p.Drain()
		if len(recs) != 1 || recs[0].RequestURI != target {
			t.Errorf("%q: recorded %+v", target, recs)
		}
	}
}
