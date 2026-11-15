// Fast unit test for the per-client mount-version cache: a Client targets exactly one mount, so
// a whole Walk must resolve the KV mount version at most once, never once per list/read. See
// INV-VAULTSOURCE-mount-version-resolved-once (campaign FINDING F2).
package vaultsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestWalk_ResolvesMountVersionOnce walks a small multi-leaf KV v2 tree (root -> a, b, c/; c ->
// d) and asserts the client hit sys/internal/ui/mounts exactly once across the whole walk.
func TestWalk_ResolvesMountVersionOnce(t *testing.T) {
	var mountHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts"):
			mountHits.Add(1)
			_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata"):
			sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata"), "/")
			switch sub {
			case "":
				_, _ = w.Write([]byte(`{"data":{"keys":["a","b","c/"]}}`))
			case "c":
				_, _ = w.Write([]byte(`{"data":{"keys":["d"]}}`))
			default:
				_, _ = w.Write([]byte(`{"data":{"keys":[]}}`))
			}
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data"):
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"v"},"metadata":{"version":1}}}`))
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusTeapot)
		}
	}))
	defer srv.Close()

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, _, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 3 { // a, b, c/d
		t.Fatalf("Walk returned %d entries, want 3 (a, b, c/d)", len(entries))
	}
	if got := mountHits.Load(); got != 1 {
		t.Fatalf("Walk resolved the mount version %d times; want exactly 1 (the per-client cache must hit)", got)
	}
}
