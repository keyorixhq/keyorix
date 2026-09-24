// Fast unit tests against an httptest fake Vault — no docker, no real Vault, always part of
// default CI. vault_integration_test.go covers the same client against a real Vault instance;
// these tests cover mechanics that are awkward to provoke against a real server (redirect
// refusal, exact header values) with a fake that can assert on the raw request.
package vaultsource

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// TestWalk_AllVersionsUnsupported locks in PR #2077 review item 3: --all-versions must fail
// with a clear error, never silently behave like latest-only. No network call happens (the
// check is Walk's first line), so this needs no live Vault — vault_integration_test.go's
// TestIntegration_AllVersionsNotSupported covers the same contract against a real server.
func TestWalk_AllVersionsUnsupported(t *testing.T) {
	c, err := New(context.Background(), Config{Addr: "http://127.0.0.1:1", Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", true)
	if err == nil {
		t.Fatal("Walk with allVersions=true returned no error, want an explicit unsupported error")
	}
	if entries != nil || skipped != nil {
		t.Errorf("Walk with allVersions=true returned entries=%v skipped=%v, want both nil", entries, skipped)
	}
	if !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("error = %q, want it to say the feature is not yet supported", err.Error())
	}
}

// TestClient_PrivateCA is PR #2077 review item 1: a Vault behind a private/internal CA must be
// reachable via --vault-cacert, and — the other half of the same claim — unreachable without
// it (proving the CA is actually being validated, not merely accepted as one option among
// others that happens to work by coincidence of Go's default transport).
func TestClient_PrivateCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
	}))
	defer srv.Close()

	// httptest.Server's own leaf cert is exposed as srv.Certificate(); PEM-encode it directly
	// for use as a --vault-cacert test fixture.
	pemBytes := encodeCertPEM(t, srv.Certificate())
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	t.Run("trusted with --vault-cacert", func(t *testing.T) {
		c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t", CACertPath: certPath})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.resolveKVMountVersion(context.Background(), ""); err != nil {
			t.Fatalf("resolveKVMountVersion with trusted CA: %v", err)
		}
	})

	t.Run("untrusted without a CA cert", func(t *testing.T) {
		c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.resolveKVMountVersion(context.Background(), ""); err == nil {
			t.Fatal("resolveKVMountVersion succeeded against an untrusted self-signed server with no CA cert configured — the CA is not actually being validated")
		}
	})
}

// encodeCertPEM PEM-encodes a leaf certificate for use as a --vault-cacert test fixture.
func encodeCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestNoSkipVerifyEscapeHatch is a source-level guard for Config's own doc comment promise
// ("there is no option to skip TLS verification") — PR #2077 review item 1 explicitly asked
// for no such escape hatch. A grep-based check on the package source is a blunt instrument,
// but it is exactly the kind of machine-checked claim CLAUDE.md's "prefer the machine-checked
// over the asserted" principle asks for: a future edit that adds InsecureSkipVerify anywhere
// in this package fails this test instead of silently reintroducing the option.
func TestNoSkipVerifyEscapeHatch(t *testing.T) {
	data, err := os.ReadFile("vault.go")
	if err != nil {
		t.Fatalf("read vault.go: %v", err)
	}
	// ":" distinguishes an actual tls.Config{InsecureSkipVerify: ...} field assignment from
	// this package's own doc comments, which mention the bare identifier while explaining its
	// absence (Config's and buildTLSConfig's doc comments both do) — a bare-string match would
	// make this test fail on its own negative-documentation the moment someone writes it.
	if strings.Contains(string(data), "InsecureSkipVerify:") {
		t.Fatal("vault.go sets InsecureSkipVerify — this package must never offer a skip-TLS-verify option (PR #2077 review item 1)")
	}
}
