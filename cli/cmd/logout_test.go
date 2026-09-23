package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
)

// TestRunLogout_RevokesServerSideThenDeletesLocalCredentials proves logout does not
// regress to the old CLI's behavior (docs/cli-split-inventory.md §8 Finding S12: "auth
// logout" only cleared local config and never told the server). Asserting the local
// file is gone alone would pass even if the POST /auth/logout call were never made --
// the httptest server's own hit counter is the only thing that can tell "the server was
// told" from "the client just forgot locally," per CLAUDE.md's fails-open testing rule.
func TestRunLogout_RevokesServerSideThenDeletesLocalCredentials(t *testing.T) {
	var logoutCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/logout" && r.Method == http.MethodPost {
			logoutCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer tok-abc" {
				t.Errorf("Authorization header = %q, want %q", got, "Bearer tok-abc")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")

	path, err := credstore.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	store := credstore.NewFileStore(path)
	if err := store.Save(credstore.Credentials{ServerURL: srv.URL, Token: "tok-abc"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := runLogout(logoutCmd, nil); err != nil {
		t.Fatalf("runLogout: %v", err)
	}

	if logoutCalls != 1 {
		t.Fatalf("server-side POST /auth/logout was called %d times, want 1", logoutCalls)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("local credentials still present after logout, want them deleted")
	}
}

// TestRunLogout_StillDeletesLocalCredentialsWhenServerUnreachable is the fail-open half
// of the DO instruction ("if the server call fails, still delete locally and say so"):
// an unreachable server must not leave a stale, still-usable credential on disk.
func TestRunLogout_StillDeletesLocalCredentialsWhenServerUnreachable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")

	path, err := credstore.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	store := credstore.NewFileStore(path)
	// 127.0.0.1:1 is never listening -- a fast, deterministic "unreachable" without a
	// real network dependency.
	if err := store.Save(credstore.Credentials{ServerURL: "http://127.0.0.1:1", Token: "tok-abc"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := runLogout(logoutCmd, nil); err != nil {
		t.Fatalf("runLogout: %v", err)
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("local credentials still present after logout against an unreachable server, want them deleted")
	}
}

func TestRunLogout_NotLoggedInIsANoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	if err := runLogout(logoutCmd, nil); err != nil {
		t.Fatalf("runLogout with nothing stored: %v", err)
	}
}
