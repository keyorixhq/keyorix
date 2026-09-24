// Fast unit tests against an httptest fake Vault — no docker, no real Vault, always part of
// default CI. vault_integration_test.go covers the same client against a real Vault instance;
// these tests cover mechanics that are awkward to provoke against a real server (redirect
// refusal, exact header values) with a fake that can assert on the raw request.
package vaultsource

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNew_RequiresAddr(t *testing.T) {
	_, err := New(context.Background(), Config{Token: "t"})
	if err == nil {
		t.Fatal("New with no Addr returned no error")
	}
}

func TestNew_RequiresTokenOrAppRole(t *testing.T) {
	_, err := New(context.Background(), Config{Addr: "http://127.0.0.1:1"})
	if err == nil {
		t.Fatal("New with neither token nor AppRole returned no error")
	}
}

func TestClient_RefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was followed: %s %s (X-Vault-Token=%q) — a followed redirect leaks the live token to whatever host it points at", r.Method, r.URL.Path, r.Header.Get("X-Vault-Token"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/sys/internal/ui/mounts/secret", http.StatusFound)
	}))
	defer redirector.Close()

	c, err := New(context.Background(), Config{Addr: redirector.URL, Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// resolveKVMountVersion is what issues the first real request; a redirect response
	// (302, no usable body) fails to decode as the expected JSON, which is the correct
	// outcome here — what matters is that `target` (asserted via t.Errorf above) was never hit.
	_, _ = c.resolveKVMountVersion(context.Background(), "")
}

func TestClient_SendsNamespaceHeader(t *testing.T) {
	var gotNamespace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotNamespace = r.Header.Get("X-Vault-Namespace")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
	}))
	defer srv.Close()

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t", Namespace: "team-a-ns"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.resolveKVMountVersion(context.Background(), ""); err != nil {
		t.Fatalf("resolveKVMountVersion: %v", err)
	}
	if gotNamespace != "team-a-ns" {
		t.Errorf("X-Vault-Namespace = %q, want team-a-ns", gotNamespace)
	}
}

func TestClient_AppRoleLoginSendsCredentialsAndUsesReturnedToken(t *testing.T) {
	var loginBody, usedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			body, _ := io.ReadAll(r.Body)
			loginBody = string(body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth":{"client_token":"minted-token-abc"}}`))
		default:
			usedToken = r.Header.Get("X-Vault-Token")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
		}
	}))
	defer srv.Close()

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", RoleID: "role-1", SecretID: "secret-1"})
	if err != nil {
		t.Fatalf("New (AppRole): %v", err)
	}
	if !strings.Contains(loginBody, "role-1") || !strings.Contains(loginBody, "secret-1") {
		t.Errorf("AppRole login body = %q, want it to carry role_id/secret_id", loginBody)
	}
	if _, err := c.resolveKVMountVersion(context.Background(), ""); err != nil {
		t.Fatalf("resolveKVMountVersion: %v", err)
	}
	if usedToken != "minted-token-abc" {
		t.Errorf("subsequent request used token %q, want the AppRole-minted token", usedToken)
	}
}

func TestClient_AppRoleLoginFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", RoleID: "bad", SecretID: "bad"})
	if err == nil {
		t.Fatal("New with a rejected AppRole login returned no error")
	}
}
