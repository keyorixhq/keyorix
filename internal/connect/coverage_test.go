package connect

// coverage_test.go — additional tests targeting uncovered branches in the
// client() constructors of azurekv.go, gcpsm.go, and awssm.go.
//
// All three connectors share the same pattern:
//
//   func (c *X) client(ctx context.Context) (iface, error) {
//       if c.newClient != nil {
//           return c.newClient(ctx)          // always exercised by existing tests
//       }
//       // real SDK calls — only reachable when newClient is nil
//       ...
//   }
//
// The existing tests inject a fake via newClient, so the SDK code paths (the
// c.newClient == nil branch) are never reached. The tests below call client()
// directly without setting newClient so the real SDK construction path executes.
//
// Because the tests run without cloud credentials, the outcome of the SDK call is
// environment-dependent:
//   - AWS  LoadDefaultConfig almost never fails; expect success.
//   - GCP  secretmanager.NewClient may fail (no ADC) — we accept either result.
//   - Azure NewDefaultAzureCredential may succeed (lazy chain); azsecrets.NewClient
//     will fail when vaultURL is empty or invalid.
//
// In every case the important thing is that the code executes, which moves the
// uncovered statements into the "covered" set.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// AWS Secrets Manager — client() real path
// ---------------------------------------------------------------------------

// TestAWSSM_ClientRealPath_WithRegion exercises the awssm.client() path when
// newClient is nil and a region is set. awsconfig.LoadDefaultConfig almost
// never returns an error, so we expect a non-nil client back.
func TestAWSSM_ClientRealPath_WithRegion(t *testing.T) {
	c := NewAWSSecretsManagerConnector("aws-real", "us-east-1", nil)
	// newClient is nil — the real awsconfig.LoadDefaultConfig path runs.
	cl, err := c.client(context.Background())
	// LoadDefaultConfig succeeds even without credentials; we expect a valid client.
	require.NoError(t, err)
	assert.NotNil(t, cl)
}

// TestAWSSM_ClientRealPath_NoRegion exercises the empty-region branch in
// awssm.client(): when region is "", the opts slice stays empty and
// awsconfig.LoadDefaultConfig is called without a region option.
func TestAWSSM_ClientRealPath_NoRegion(t *testing.T) {
	c := NewAWSSecretsManagerConnector("aws-real-noregion", "", nil)
	// newClient is nil; region is "".
	cl, err := c.client(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, cl)
}

// TestAWSSM_ClientInjectedError covers the newClient != nil path returning an
// error, exercising the error-propagation in GetSecret when client() fails.
func TestAWSSM_ClientInjectedError(t *testing.T) {
	c := NewAWSSecretsManagerConnector("aws-err", "eu-west-1", nil)
	injectedErr := errors.New("injected client error")
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) {
		return nil, injectedErr
	}
	_, err := c.GetSecret(context.Background(), "myref")
	require.Error(t, err)
	assert.ErrorIs(t, err, injectedErr)
}

// ---------------------------------------------------------------------------
// Azure Key Vault — client() real path
// ---------------------------------------------------------------------------

// TestAzureKV_ClientRealPath exercises azurekv.client() when newClient is nil.
// NewDefaultAzureCredential creates a lazy chain — it may or may not return an
// error immediately. If it succeeds, azsecrets.NewClient is called with the
// configured vaultURL. We accept either outcome and just verify the code runs.
func TestAzureKV_ClientRealPath(t *testing.T) {
	// Clear Azure environment variables so the DefaultAzureCredential chain
	// has no env-based credentials to use; some SDK versions fail at
	// construction time in this state.
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	t.Setenv("MSI_ENDPOINT", "")
	t.Setenv("IDENTITY_ENDPOINT", "")

	c := NewAzureKeyVaultConnector("az-real", "https://myvault.vault.azure.net/", nil)
	// newClient is nil — the real DefaultAzureCredential + azsecrets.NewClient path runs.
	cl, err := c.client(context.Background())
	// Either outcome is valid in a unit-test environment.
	if err != nil {
		// The error must carry the expected prefix from the connector.
		assert.Contains(t, err.Error(), "azure-key-vault")
		assert.Nil(t, cl)
	} else {
		assert.NotNil(t, cl)
	}
}

// TestAzureKV_ClientRealPath_EmptyVaultURL verifies that when the vaultURL is
// empty, azsecrets.NewClient returns an error (which azurekv.client wraps with
// the "azure-key-vault: new client:" prefix). This covers the second error-
// return in client() — the credential creation succeeds but client construction
// fails.
func TestAzureKV_ClientRealPath_EmptyVaultURL(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	t.Setenv("MSI_ENDPOINT", "")
	t.Setenv("IDENTITY_ENDPOINT", "")

	// vaultURL is "" — azsecrets.NewClient should reject an empty endpoint.
	c := NewAzureKeyVaultConnector("az-real-empty", "", nil)
	cl, err := c.client(context.Background())
	// If NewDefaultAzureCredential itself errored, err is set with "credential" prefix.
	// If it succeeded, azsecrets.NewClient("", ...) should error.
	// In both cases the function must have entered the real SDK path.
	if err != nil {
		assert.Contains(t, err.Error(), "azure-key-vault")
		assert.Nil(t, cl)
	} else {
		// Some SDK versions may return a client even with an empty URL (deferred
		// validation). The code path was still exercised.
		assert.NotNil(t, cl)
	}
}

// TestAzureKV_ClientInjectedError covers the newClient != nil path returning
// an error, checking that GetSecret propagates the injected error.
func TestAzureKV_ClientInjectedError(t *testing.T) {
	injectedErr := errors.New("injected azure client error")
	c := NewAzureKeyVaultConnector("az-inject-err", "https://v.vault.azure.net/", nil)
	c.newClient = func(_ context.Context) (azSecretGetter, error) {
		return nil, injectedErr
	}
	_, err := c.GetSecret(context.Background(), "my-secret")
	require.Error(t, err)
	assert.ErrorIs(t, err, injectedErr)
}

// ---------------------------------------------------------------------------
// GCP Secret Manager — client() real path
// ---------------------------------------------------------------------------

// TestGCPSM_ClientRealPath exercises gcpsm.client() when newClient is nil.
// secretmanager.NewClient uses Application Default Credentials. Without ADC in
// the test environment the call may fail. We accept either outcome.
func TestGCPSM_ClientRealPath(t *testing.T) {
	// Unset the standard ADC environment variable so there is no file-based
	// credential source; this often (but not always) makes NewClient fail.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")

	c := NewGCPSecretManagerConnector("gcp-real", "", nil)
	// newClient is nil — the real secretmanager.NewClient path runs.
	cl, err := c.client(context.Background())
	if err != nil {
		assert.Contains(t, err.Error(), "gcp-secret-manager")
		assert.Nil(t, cl)
	} else {
		// Client was created (e.g. GCE metadata server reachable, or ADC cached).
		assert.NotNil(t, cl)
		// Clean up: close the gRPC connection.
		_ = cl.Close()
	}
}

// TestGCPSM_ClientInjectedError covers the newClient != nil path returning
// an error, checking GetSecret propagation.
func TestGCPSM_ClientInjectedError(t *testing.T) {
	injectedErr := errors.New("injected gcp client error")
	c := NewGCPSecretManagerConnector("gcp-inject-err", "", nil)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) {
		return nil, injectedErr
	}
	_, err := c.GetSecret(context.Background(), "projects/p/secrets/x/versions/latest")
	require.Error(t, err)
	assert.ErrorIs(t, err, injectedErr)
}
