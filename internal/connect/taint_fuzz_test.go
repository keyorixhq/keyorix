//go:build taintoverlay

package connect

// Input-to-sink taint harness for the Vault connector's ref handling (see
// internal/fuzzutil/taint). The ref is caller-supplied (?ref= / gRPC field) and
// must only ever contribute a path segment after the validated connector
// address. Contract: the marker may reach the request URL's path (class
// urltail, recorded and not fatal); it must not reach the host, a file path, a
// command or a query.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintVaultRef ./internal/connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/taint"
)

func FuzzTaintVaultRef(f *testing.F) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	f.Cleanup(srv.Close)
	f.Add("secret/data/app", uint8(0))
	f.Add("a", uint8(1))
	f.Fuzz(func(t *testing.T, ref string, mode uint8) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		defer taint.Check(t.Fatalf)
		c := NewVaultConnector("v", srv.URL, "tok", nil)
		if mode%2 == 0 {
			ref = taint.Str(ref)
		} else {
			ref = taint.PathStr(ref)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = c.GetSecret(ctx, ref)
	})
}
