// Fast unit test for Walk's recursion-depth cap: a Vault that returns a folder key at every
// level must not drive unbounded-depth recursion. See INV-VAULTSOURCE-walk-depth-bounded
// (campaign FINDING F4).
package vaultsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWalk_DepthCapped stands up a KV v2 server that lists a single sub-folder at every level
// (so the tree never terminates on its own until a fixed, cap-exceeding depth). Walk must stop
// with a depth error well before that, rather than recursing without bound.
func TestWalk_DepthCapped(t *testing.T) {
	// The server would return a folder for this many levels before finally serving a leaf; it is
	// past maxWalkDepth so a correct Walk errors out before ever reaching the leaf. (Finite so a
	// regression that removed the cap fails this test cleanly instead of overflowing the stack.)
	const treeDepth = maxWalkDepth + 10

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts"):
			_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
		case strings.HasPrefix(r.URL.Path, "/v1/secret/metadata"):
			sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata"), "/")
			depth := 0
			if sub != "" {
				depth = strings.Count(sub, "/") + 1
			}
			if depth < treeDepth {
				_, _ = w.Write([]byte(`{"data":{"keys":["s/"]}}`)) // another folder, one level deeper
			} else {
				_, _ = w.Write([]byte(`{"data":{"keys":[]}}`)) // finally a leaf
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
	_, _, err = c.Walk(context.Background(), "", false)
	if err == nil {
		t.Fatalf("Walk descended a %d-level folder tree without error; want a depth-cap error at %d", treeDepth, maxWalkDepth)
	}
	if !strings.Contains(err.Error(), "maximum walk depth") {
		t.Fatalf("Walk error = %q, want it to report the maximum walk depth", err.Error())
	}
}
