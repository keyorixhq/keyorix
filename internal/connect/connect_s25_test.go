package connect

// connect_s25_test.go — coverage blitz targeting the remaining fully- or
// mostly-uncovered functions after the s21-s24 rounds:
//
//   - connect.go RefWithinPrefix (the exported wrapper) was 0% — every existing
//     test calls the unexported refWithinPrefix directly.
//   - vault.go CheckTokenTTL was 0% — no test exercised the token self-lookup at
//     all.
//   - vault.go validateConnectorURL was missing its "bad scheme" and "missing
//     host" branches (only the url.Parse-error branch was covered).
//   - azurekv.go client()'s NewDefaultAzureCredential-error branch was
//     environment-dependent (coverage_test.go accepts "either outcome" because
//     the SDK's lazy credential chain does not fail by default). Setting the
//     SDK's own AZURE_TOKEN_CREDENTIALS selector to an invalid value makes
//     NewDefaultAzureCredential return a deterministic, hermetic error with no
//     network access — reliably covering that branch.
//   - gcpsm.go client()'s success return (`return cl, nil`) was uncovered
//     because secretmanager.NewClient fails without ADC in this sandbox
//     (coverage_test.go's TestGCPSM_ClientRealPath already covers the error
//     branch). Pointing GOOGLE_APPLICATION_CREDENTIALS at a syntactically valid
//     but freshly-generated (never real) service-account key lets the client
//     construct successfully — the gRPC channel dials lazily, so no network
//     call or real credential is required to reach the success path.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── connect.go: RefWithinPrefix (exported wrapper) ──────────────────────────

// TestRefWithinPrefix_S25_ExportedWrapper proves the exported RefWithinPrefix
// delegates to the same logic as the unexported refWithinPrefix that every
// other test exercises directly — the wrapper itself was never called.
func TestRefWithinPrefix_S25_ExportedWrapper(t *testing.T) {
	assert.True(t, RefWithinPrefix("db/prod", "db/prod"), "exact match")
	assert.True(t, RefWithinPrefix("db/prod", "db/prod/config"), "segment-boundary extension")
	assert.False(t, RefWithinPrefix("db/prod", "db/production-other-team"),
		"must not match on a bare substring across the segment boundary")
	assert.False(t, RefWithinPrefix("db/prod", "db/other"), "unrelated sibling")
}

// ── vault.go: CheckTokenTTL ──────────────────────────────────────────────────

// fakeVaultTokenLookup stands up an in-process Vault endpoint that only serves
// the token self-lookup path, keyed on the expected token.
func fakeVaultTokenLookup(t *testing.T, expectedToken, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Vault-Token") != expectedToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestVault_S25_CheckTokenTTL_Success proves a normal, renewable token returns
// its TTL and renewable flag from the Data envelope.
func TestVault_S25_CheckTokenTTL_Success(t *testing.T) {
	srv := fakeVaultTokenLookup(t, "tok", `{"data":{"ttl":3600,"renewable":true}}`, http.StatusOK)
	c := NewVaultConnector("v", srv.URL, "tok", nil)

	ttl, renewable, err := c.CheckTokenTTL(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3600, ttl)
	assert.True(t, renewable)
}

// TestVault_S25_CheckTokenTTL_RootToken proves a root token (TTL 0, not
// renewable) is reported back verbatim rather than treated as an error.
func TestVault_S25_CheckTokenTTL_RootToken(t *testing.T) {
	srv := fakeVaultTokenLookup(t, "root-tok", `{"data":{"ttl":0,"renewable":false}}`, http.StatusOK)
	c := NewVaultConnector("v", srv.URL, "root-tok", nil)

	ttl, renewable, err := c.CheckTokenTTL(context.Background())
	require.NoError(t, err)
	assert.Zero(t, ttl)
	assert.False(t, renewable)
}

// TestVault_S25_CheckTokenTTL_NonOKStatus proves a non-200 response (e.g. an
// invalid/expired token) surfaces as an error carrying the status code.
func TestVault_S25_CheckTokenTTL_NonOKStatus(t *testing.T) {
	srv := fakeVaultTokenLookup(t, "tok", `{"errors":["permission denied"]}`, http.StatusForbidden)
	c := NewVaultConnector("v", srv.URL, "wrong-tok", nil)

	_, _, err := c.CheckTokenTTL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned 403")
}

// TestVault_S25_CheckTokenTTL_InvalidJSON proves a malformed response body is
// reported as a parse error rather than panicking or silently zeroing the TTL.
func TestVault_S25_CheckTokenTTL_InvalidJSON(t *testing.T) {
	srv := fakeVaultTokenLookup(t, "tok", `not json`, http.StatusOK)
	c := NewVaultConnector("v", srv.URL, "tok", nil)

	_, _, err := c.CheckTokenTTL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse error")
}

// TestVault_S25_CheckTokenTTL_NetworkError proves a connector pointed at an
// address nothing is listening on surfaces the transport failure wrapped with
// the "token TTL lookup failed" prefix, rather than the request-construction
// error.
func TestVault_S25_CheckTokenTTL_NetworkError(t *testing.T) {
	// Bind an ephemeral port, note its address, then close it immediately — the
	// port is guaranteed to have nothing listening on it, so a connection
	// attempt fails fast with "connection refused" without depending on any
	// real network access.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	c := NewVaultConnector("v", "http://"+addr, "tok", nil)
	_, _, err = c.CheckTokenTTL(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token TTL lookup failed")
}

// TestVault_S25_CheckTokenTTL_RequestConstructionError proves the branch where
// http.NewRequestWithContext itself fails (a malformed connector address)
// surfaces the raw construction error rather than attempting a request.
func TestVault_S25_CheckTokenTTL_RequestConstructionError(t *testing.T) {
	// A control character in the URL makes url.Parse (used internally by
	// http.NewRequestWithContext) fail before any network I/O is attempted.
	c := NewVaultConnector("v", "http://exa\x7fmple.com", "tok", nil)
	_, _, err := c.CheckTokenTTL(context.Background())
	require.Error(t, err)
}

// ── vault.go: validateConnectorURL ───────────────────────────────────────────

func TestValidateConnectorURL_S25(t *testing.T) {
	t.Run("valid https", func(t *testing.T) {
		require.NoError(t, validateConnectorURL("https://vault.example.com:8200"))
	})
	t.Run("valid http", func(t *testing.T) {
		require.NoError(t, validateConnectorURL("http://127.0.0.1:8200"))
	})
	t.Run("unparseable", func(t *testing.T) {
		err := validateConnectorURL("://")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid connector address")
	})
	t.Run("non-http(s) scheme is rejected", func(t *testing.T) {
		err := validateConnectorURL("ftp://vault.example.com")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must use http or https")
	})
	t.Run("file scheme is rejected", func(t *testing.T) {
		err := validateConnectorURL("file:///etc/passwd")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must use http or https")
	})
	t.Run("missing host is rejected", func(t *testing.T) {
		err := validateConnectorURL("http:///v1/secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing a host")
	})
}

// ── azurekv.go: client() real path, deterministic credential error ─────────

// TestAzureKV_S25_ClientRealPath_CredentialErrorIsDeterministic covers the
// NewDefaultAzureCredential-error branch of client() hermetically. The SDK's
// own AZURE_TOKEN_CREDENTIALS selector env var, when set to a value it does
// not recognize, makes NewDefaultAzureCredential return a synchronous error
// with no network access at all — unlike leaving the ambient chain to its
// default (lazy) behavior, which coverage_test.go's TestAzureKV_ClientRealPath
// must treat as "either outcome" because it doesn't fail predictably.
func TestAzureKV_S25_ClientRealPath_CredentialErrorIsDeterministic(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "not-a-real-credential-type")

	c := NewAzureKeyVaultConnector("az-real-s25", "https://myvault.vault.azure.net/", nil)
	cl, err := c.client(context.Background())
	require.Error(t, err, "an unrecognized AZURE_TOKEN_CREDENTIALS value must make credential construction fail")
	assert.Nil(t, cl)
	assert.Contains(t, err.Error(), "azure-key-vault: default credential")
}

// ── gcpsm.go: client() real path, deterministic success ────────────────────

// fakeGCPServiceAccountKeyFile writes a syntactically valid, freshly generated
// (never real) service-account JSON key to a temp file and returns its path.
// google.golang.org/api's credential loader parses and holds the key without
// making any network call — the underlying gRPC channel dials lazily — so
// client construction succeeds deterministically without any real GCP
// credential or network access, letting the test hit gcpsm.go's `return cl,
// nil` success branch that coverage_test.go's TestGCPSM_ClientRealPath cannot
// reach in a sandbox with no ADC available.
func fakeGCPServiceAccountKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	sa := map[string]string{
		"type":                        "service_account",
		"project_id":                  "s25-fake-project",
		"private_key_id":              "s25fakekeyid",
		"private_key":                 string(keyPEM),
		"client_email":                "s25-fake@s25-fake-project.iam.gserviceaccount.com",
		"client_id":                   "100000000000000000000",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/s25-fake%40s25-fake-project.iam.gserviceaccount.com",
	}
	blob, err := json.Marshal(sa)
	require.NoError(t, err)

	dir := t.TempDir()
	p := filepath.Join(dir, "fake-sa.json")
	require.NoError(t, os.WriteFile(p, blob, 0o600))
	return p
}

func TestGCPSM_S25_ClientRealPath_SucceedsWithSyntacticallyValidKey(t *testing.T) {
	keyPath := fakeGCPServiceAccountKeyFile(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)

	c := NewGCPSecretManagerConnector("gcp-real-s25", "", nil)
	cl, err := c.client(context.Background())
	require.NoError(t, err, "a syntactically valid key file must let the client construct without any network call")
	require.NotNil(t, cl)
	_ = cl.Close()
}
