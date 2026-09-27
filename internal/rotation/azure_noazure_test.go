//go:build noazure

package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureExecutor_ClientNoAzureBuild_FailsClosed proves that in a noazure
// build, AzureAppSecretExecutor.client() (reached whenever newClient is nil,
// i.e. a real, non-test caller) fails with a clear "not available in this
// build" error rather than panicking or silently succeeding — even though the
// AzureAppSecretExecutor type itself stays compiled in this build (ADR-109
// step 6; see azure.go's doc comment for why).
func TestAzureExecutor_ClientNoAzureBuild_FailsClosed(t *testing.T) {
	e := NewAzureAppSecretExecutor("azure-test", nil)
	cl, err := e.client(context.Background())
	require.Error(t, err)
	assert.Nil(t, cl)
	assert.Contains(t, err.Error(), "azure SDK not available in this build")
}

// TestLookupCloudExecutor_AzureApp_NotRegisteredInNoAzureBuild proves the
// registration seam itself: a noazure build never registers "azure-app", so
// rotation.LookupCloudExecutor reports not-found instead of silently returning a
// broken executor.
func TestLookupCloudExecutor_AzureApp_NotRegisteredInNoAzureBuild(t *testing.T) {
	_, ok := LookupCloudExecutor("azure-app", CloudExecutorParams{Name: "x"})
	assert.False(t, ok, "azure-app must not be registered in a noazure build")
}
