package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// setPATCreds points patAPIClient at an httptest server via env vars (highest
// precedence in resolveServerAndToken), so tests never touch the real credential file.
func setPATCreds(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok-abc")
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	os.Stdout = orig
	w.Close()
	buf := make([]byte, 64*1024)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

// TestRunPATList_MatchesOldCLIOutputShape is a golden-output parity check
// (docs/cli-split-inventory.md §7 PR 2's own test requirement): the header row and
// column values must match the old CLI's remote-mode table byte-for-byte for the
// same server response.
func TestRunPATList_MatchesOldCLIOutputShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/tokens" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":7,"name":"ci-token","token_prefix":"kx_pat_ab","revoked":false,"created_at":"2026-01-02T00:00:00Z","expires_at":null,"last_used_at":null,"scopes":[],"project_scope":0,"environment_scope":0,"allowed_cidrs":[]}]}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runPATList(patListCmd, nil); err != nil {
			t.Fatalf("runPATList: %v", err)
		}
	})

	if !containsAll(out, "ID", "NAME", "PREFIX", "CREATED", "LAST USED", "EXPIRES", "REVOKED", "SCOPE") {
		t.Fatalf("header row missing expected columns, got: %q", out)
	}
	if !containsAll(out, "7", "ci-token", "kx_pat_ab…", "2026-01-02", "never", "false", "full access") {
		t.Fatalf("row missing expected fields, got: %q", out)
	}
}

func TestRunPATList_EmptyPrintsNoTokensMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)

	out := captureStdout(t, func() {
		if err := runPATList(patListCmd, nil); err != nil {
			t.Fatalf("runPATList: %v", err)
		}
	})
	if out != "You have no personal access tokens.\n" {
		t.Fatalf("output = %q, want the old CLI's exact empty-state message", out)
	}
}

// TestRunPATCreate_PrintsRawTokenOnceToStdoutOnly guards the DO instruction: a
// command that mints a new secret prints it once, to stdout only, with the
// existing warning text.
func TestRunPATCreate_PrintsRawTokenOnceToStdoutOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"data":{"token":"kx_pat_the_raw_secret","pat":{"id":9,"name":"new-token"}}}`)
	}))
	defer srv.Close()
	setPATCreds(t, srv)
	patCreateName = "new-token"
	defer func() { patCreateName = "" }()

	out := captureStdout(t, func() {
		if err := runPATCreate(patCreateCmd, nil); err != nil {
			t.Fatalf("runPATCreate: %v", err)
		}
	})

	if !containsAll(out, "copy it now, it will not be shown again", "kx_pat_the_raw_secret") {
		t.Fatalf("output missing the one-time-secret warning or the token itself: %q", out)
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}
