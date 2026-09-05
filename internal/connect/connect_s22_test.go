package connect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── connect.go: Manager edge cases ──────────────────────────────────────────

// TestManager_NilSlice_S22 verifies that NewManager accepts a nil connector
// slice without panicking and returns a usable (empty) Manager.
func TestManager_NilSlice_S22(t *testing.T) {
	m := NewManager(nil)
	require.NotNil(t, m)
	assert.Empty(t, m.Names())
	_, ok := m.Get("x")
	assert.False(t, ok)
}

// ── vault.go: uncovered GetSecret branches ──────────────────────────────────

// TestVault_GetSecret_EmptyAddress_S22 covers the branch that rejects a
// connector with no configured address — a defensive guard for a misconfigured
// deployment.
func TestVault_GetSecret_EmptyAddress_S22(t *testing.T) {
	c := NewVaultConnector("v", "", "tok", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/myapp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address is not configured")
}

// TestVault_GetSecret_InvalidJSON_S22 covers the json.Unmarshal failure branch
// in GetSecret: a 200 response whose body is not valid JSON returns an error
// containing "has no data".
func TestVault_GetSecret_InvalidJSON_S22(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	t.Cleanup(srv.Close)

	c := NewVaultConnector("v", srv.URL, "tok", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/myapp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no data")
}

// TestVault_GetSecret_MissingDataKey_S22 covers the branch where the JSON body
// is valid but the top-level "data" key is absent (len(env.Data) == 0).
func TestVault_GetSecret_MissingDataKey_S22(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		// Valid JSON, but no "data" key at all.
		_, _ = w.Write([]byte(`{"lease_id":"","renewable":false}`))
	}))
	t.Cleanup(srv.Close)

	c := NewVaultConnector("v", srv.URL, "tok", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/myapp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no data")
}

// TestVault_GetSecret_KVv2DataWithoutMetadata_S22 covers the KV v2 detection
// fallback: when the inner object has a "data" sub-key but no "metadata"
// sub-key (len(kv2.Metadata) == 0), the code falls back to the KV v1 path
// and returns the outer data map as-is.
func TestVault_GetSecret_KVv2DataWithoutMetadata_S22(t *testing.T) {
	// Inner object has "data" but no "metadata" — not recognised as KV v2.
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/secret/legacy": `{"data":{"data":{"apikey":"abc"}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/legacy")
	require.NoError(t, err)
	// Falls back to KV v1: the outer data map (which happens to contain a
	// nested "data" key) is returned as raw JSON.
	assert.JSONEq(t, `{"data":{"apikey":"abc"}}`, val)
}

// TestVault_GetSecret_KVv2MetadataWithoutData_S22 is a symmetric case: the
// inner object has "metadata" but no "data" — still not KV v2, falls to KV v1.
func TestVault_GetSecret_KVv2MetadataWithoutData_S22(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/secret/legacy": `{"data":{"metadata":{"version":1}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/legacy")
	require.NoError(t, err)
	assert.JSONEq(t, `{"metadata":{"version":1}}`, val)
}

// TestSanitizeVaultRef_Tilde_S22 verifies that a tilde character (0x7e) is
// accepted — it sits just below DEL (0x7f) and must not be mistaken for a
// control character.
func TestSanitizeVaultRef_Tilde_S22(t *testing.T) {
	got, err := sanitizeVaultRef("secret/data/~myapp")
	require.NoError(t, err)
	assert.Contains(t, got, "~myapp")
}

// TestSanitizeVaultRef_SpaceIsEncoded_S22 verifies that a space character
// (ASCII 0x20 — one above the control-character cutoff) is accepted by the
// character filter and then percent-escaped by url.PathEscape.
func TestSanitizeVaultRef_SpaceIsEncoded_S22(t *testing.T) {
	got, err := sanitizeVaultRef("secret/my app/key")
	require.NoError(t, err)
	assert.Contains(t, got, "%20", "space must be percent-escaped in the path")
	assert.NotContains(t, got, " ")
}

// ── awssm.go: client-builder error path ─────────────────────────────────────

// TestAWSSM_GetSecret_ClientError_S22 exercises the branch in
// AWSSecretsManagerConnector.GetSecret where the client factory itself returns
// an error (e.g., AWS config load failure).
func TestAWSSM_GetSecret_ClientError_S22(t *testing.T) {
	c := NewAWSSecretsManagerConnector("aws", "us-east-1", nil)
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) {
		return nil, errors.New("no AWS credentials configured")
	}
	_, err := c.GetSecret(context.Background(), "prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no AWS credentials configured")
}

// ── azurekv.go: client-builder error path ───────────────────────────────────

// TestAzureKV_GetSecret_ClientError_S22 exercises the branch in
// AzureKeyVaultConnector.GetSecret where the client factory itself returns an
// error (e.g., Azure credential resolution failure).
func TestAzureKV_GetSecret_ClientError_S22(t *testing.T) {
	c := NewAzureKeyVaultConnector("az", "https://v.vault.azure.net/", nil)
	c.newClient = func(_ context.Context) (azSecretGetter, error) {
		return nil, errors.New("no Azure credential found")
	}
	_, err := c.GetSecret(context.Background(), "db-password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Azure credential found")
}

// ── gcpsm.go: client-builder error and empty-payload branches ───────────────

// TestGCPSM_GetSecret_ClientError_S22 exercises the branch in
// GCPSecretManagerConnector.GetSecret where the client factory returns an
// error (e.g., ADC credential failure).
func TestGCPSM_GetSecret_ClientError_S22(t *testing.T) {
	c := NewGCPSecretManagerConnector("gcp", "p", nil)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) {
		return nil, errors.New("ADC: no credentials")
	}
	_, err := c.GetSecret(context.Background(), "projects/p/secrets/db/versions/latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ADC: no credentials")
}

// TestGCPSM_GetSecret_EmptyPayloadData_S22 covers the
// len(out.GetPayload().GetData()) == 0 branch: the response contains a
// non-nil SecretPayload whose Data slice is empty.
func TestGCPSM_GetSecret_EmptyPayloadData_S22(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte{}},
	}}
	c := gcpConnectorWith("gcp", fake)
	_, err := c.GetSecret(context.Background(), "projects/p/secrets/db/versions/latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

// TestGCPSM_GetSecret_PinnedProject_NoSlashAfterProjectID_S22 covers the
// gcpRefProjectID branch where the ref starts with "projects/" but has no
// further slash (strings.Cut does not find the separator), returning ok=false.
func TestGCPSM_GetSecret_PinnedProject_NoSlashAfterProjectID_S22(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")},
	}}
	c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
	// "projects/my-proj" — has the "projects/" prefix but no subsequent "/" so
	// strings.Cut(..., "/") returns found=false, gcpRefProjectID returns ok=false.
	_, err := c.GetSecret(context.Background(), "projects/my-proj")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not start with projects/PROJECT")
	assert.Empty(t, fake.got, "a ref that cannot be parsed must not reach the backend")
}
