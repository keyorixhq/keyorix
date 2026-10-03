package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestWrites_SendClientOriginHeader is #2545's client-side guard: every write this tool makes
// carries the client-origin header naming keyorix-migrate and the source locator, so the
// server can record it on the audit event — and never the value.
func TestWrites_SendClientOriginHeader(t *testing.T) {
	const canary = "canary-secret-value-xyz"
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Method] = r.Header.Get(clientOriginHeader)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":5}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":5}}`))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)

	ctx := WithSourceOrigin(context.Background(), "vault:secret/team-a/db\n#password")
	if _, err := c.Create(ctx, "n", canary, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.UpdateValue(ctx, 5, canary); err != nil {
		t.Fatalf("UpdateValue: %v", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		h := got[method]
		if !strings.HasPrefix(h, "keyorix-migrate/") || !strings.Contains(h, "source=vault:secret/team-a/db#password") {
			t.Errorf("%s: %s = %q, want keyorix-migrate/<ver> source=<path> (control chars stripped)", method, clientOriginHeader, h)
		}
		if strings.Contains(h, canary) {
			t.Errorf("%s: origin header carries the secret value", method)
		}
	}
}

// TestClientOriginHeaderMatchesServer pins the mirrored header name to the server's
// core.ClientOriginHeader (read as source text from this checkout).
func TestClientOriginHeaderMatchesServer(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "core", "audit_context.go"))
	if err != nil {
		t.Fatalf("read server source: %v", err)
	}
	if want := `const ClientOriginHeader = "` + clientOriginHeader + `"`; !strings.Contains(string(src), want) {
		t.Errorf("server's internal/core/audit_context.go has no %q — the header name drifted", want)
	}
}
