//go:build !noazure

package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureExecutor_ClientRealPath_CredentialError exercises the
// azidentity.NewDefaultAzureCredential error branch inside the real
// azureTokenSource (azure_sdk.go), reached from
// AzureAppSecretExecutor.client() when newClient is nil. Setting
// AZURE_TOKEN_CREDENTIALS to an unrecognized value makes credential
// construction fail deterministically, without any network I/O. Moved out of
// azure_test.go (ADR-109 step 6) because it exercises the real,
// azidentity-backed path specifically, which does not exist in a noazure
// build — see azure_noazure_test.go for that build's equivalent assertion.
func TestAzureExecutor_ClientRealPath_CredentialError(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "not-a-real-credential-type")

	e := NewAzureAppSecretExecutor("azure-test", nil)
	cl, err := e.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, cl)
	assert.Contains(t, err.Error(), "azure-app: default credential")
}
