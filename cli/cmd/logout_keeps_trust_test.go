package cmd

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
)

// PILOT-FIRSTRUN-FIXES-1 (#3735): `keyorix logout` forgets the session but keeps the
// operator's trust setting (ca_file) and the server URL, so the next `keyorix login` against a
// private-CA server works without repeating `keyorix config set ca_file`.

func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	caPath := filepath.Join(t.TempDir(), "server.crt")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath
}

func credstoreWith(serverURL, token, caFile string) credstore.Credentials {
	return credstore.Credentials{ServerURL: serverURL, Token: token, CAFile: caFile}
}

// tlsSessionServer is a TLS server with a login/profile/logout surface that counts the
// POST /auth/logout calls, so a test can tell "the server was told" from "the client forgot".
func tlsSessionServer(t *testing.T) (srv *httptest.Server, caPath string, logoutCalls *atomic.Int32) {
	t.Helper()
	logoutCalls = new(atomic.Int32)
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case "/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"token": "tok-session-secret"}})
		case "/api/v1/auth/profile":
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":1,"username":"admin"}}`))
		case "/auth/logout":
			if got := r.Header.Get("Authorization"); got != "Bearer tok-session-secret" {
				t.Errorf("logout Authorization = %q, want the stored token", got)
			}
			logoutCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, writeServerCA(t, srv), logoutCalls
}

func TestLogout_KeepsCAFileAndServerURL_ForgetsToken(t *testing.T) {
	store := isolateCLI(t)
	srv, caPath, logoutCalls := tlsSessionServer(t)
	t.Setenv("KEYORIX_PASSWORD", "pw")

	if _, err := runCLI(t, "config", "set", "ca_file", caPath); err != nil {
		t.Fatalf("config set ca_file: %v", err)
	}
	if _, err := runCLI(t, "login", "--server", srv.URL, "--username", "admin"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if creds, err := store.Load(); err != nil || creds.Token != "tok-session-secret" {
		t.Fatalf("after login: creds=%+v err=%v, want the session token stored", creds, err)
	}

	if _, err := runCLI(t, "logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if n := logoutCalls.Load(); n != 1 {
		t.Fatalf("server-side POST /auth/logout called %d times, want 1", n)
	}

	// The security invariant: no token byte survives on disk. Assert on the raw file, not on
	// what Load returns (Load could hide a field the file still carries).
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatalf("credentials file must survive logout (it holds ca_file): %v", err)
	}
	if strings.Contains(string(raw), "tok-session-secret") || strings.Contains(string(raw), "token:") {
		t.Fatalf("credentials file still carries session material after logout:\n%s", raw)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials file mode = %#o after logout, want 0600", perm)
	}

	creds, err := store.Load()
	if err != nil {
		t.Fatalf("Load after logout: %v", err)
	}
	if creds.Token != "" {
		t.Fatalf("token survived logout: %+v", creds)
	}
	if creds.CAFile != caPath || creds.ServerURL != srv.URL {
		t.Fatalf("logout dropped the trust setting or server URL: %+v, want ca_file %q server_url %q", creds, caPath, srv.URL)
	}

	out, err := runCLI(t, "config", "get", "ca_file")
	if err != nil || !strings.Contains(out, caPath) {
		t.Fatalf("config get ca_file after logout = %q, %v; want %q", out, err, caPath)
	}

	// A second login needs no --ca-file and no --server: both were kept.
	if _, err := runCLI(t, "login", "--username", "admin"); err != nil {
		t.Fatalf("second login after logout: %v", err)
	}
	if creds, err := store.Load(); err != nil || creds.Token != "tok-session-secret" || creds.CAFile != caPath {
		t.Fatalf("after second login: creds=%+v err=%v", creds, err)
	}
}

// With no credentials file at all, logout still succeeds and creates nothing.
func TestLogout_NoCredentialsFileSucceedsAndCreatesNothing(t *testing.T) {
	store := isolateCLI(t)

	if _, err := runCLI(t, "logout"); err != nil {
		t.Fatalf("logout with no credentials file: %v", err)
	}
	if _, err := os.Stat(store.Path()); !os.IsNotExist(err) {
		t.Fatalf("logout created %s (stat err = %v)", store.Path(), err)
	}
}

// A stored session on a server that cannot be reached is still forgotten locally.
func TestLogout_UnreachableServerStillForgetsTokenKeepsTrust(t *testing.T) {
	store := isolateCLI(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credstoreWith("http://127.0.0.1:1", "tok-stale", caPath)); err != nil {
		t.Fatal(err)
	}

	if _, err := runCLI(t, "logout"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	raw, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tok-stale") {
		t.Fatalf("token survived an unreachable-server logout:\n%s", raw)
	}
	if !strings.Contains(string(raw), caPath) {
		t.Fatalf("ca_file lost on logout:\n%s", raw)
	}
}

// login checks TLS trust BEFORE asking for the password: against a server whose certificate
// the CLI does not trust, the operator sees the certificate error without typing anything.
func TestLogin_ChecksTrustBeforePrompting(t *testing.T) {
	isolateCLI(t)
	srv, _, _ := tlsSessionServer(t)
	t.Setenv("KEYORIX_PASSWORD", "")
	t.Setenv("KEYORIX_PASSWORD_FILE", "")

	_, err := runCLI(t, "login", "--server", srv.URL, "--username", "admin")
	if err == nil {
		t.Fatal("login against an untrusted server succeeded")
	}
	if strings.Contains(err.Error(), "read password") {
		t.Fatalf("login prompted for the password before checking TLS trust: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("want a certificate error that names ca_file, got: %v", err)
	}
}

// A configured CA file that cannot be loaded is reported before the password prompt too.
func TestLogin_BadCAFileReportedBeforePrompting(t *testing.T) {
	isolateCLI(t)
	srv, _, _ := tlsSessionServer(t)
	t.Setenv("KEYORIX_PASSWORD", "")
	t.Setenv("KEYORIX_PASSWORD_FILE", "")

	_, err := runCLI(t, "login", "--ca-file", filepath.Join(t.TempDir(), "missing.pem"),
		"--server", srv.URL, "--username", "admin")
	if err == nil || !strings.Contains(err.Error(), "--ca-file") || !strings.Contains(err.Error(), "missing.pem") {
		t.Fatalf("want the CA file error (naming --ca-file and the path), got: %v", err)
	}
	if strings.Contains(err.Error(), "read password") {
		t.Fatalf("login prompted for the password before checking the CA file: %v", err)
	}
}
