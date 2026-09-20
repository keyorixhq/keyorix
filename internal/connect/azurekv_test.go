package connect

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAzKV is an injected stand-in for the Azure Key Vault secrets client.
type fakeAzKV struct {
	value      *string
	err        error
	gotName    string
	gotVersion string
	called     bool
}

func (f *fakeAzKV) GetSecret(_ context.Context, name, version string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.called = true
	f.gotName, f.gotVersion = name, version
	if f.err != nil {
		return azsecrets.GetSecretResponse{}, f.err
	}
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: f.value}}, nil
}

func azKVConnectorWith(name, vaultURL string, fake *fakeAzKV, allowed ...string) *AzureKeyVaultConnector {
	c := NewAzureKeyVaultConnector(name, vaultURL, allowed)
	c.newClient = func(_ context.Context) (azSecretGetter, error) { return fake, nil }
	return c
}

func strptr(s string) *string { return &s }

func TestAzureKV_TypeAndName(t *testing.T) {
	c := NewAzureKeyVaultConnector("prod-az", "https://v.vault.azure.net/", nil)
	assert.Equal(t, "prod-az", c.Name())
	assert.Equal(t, "azure-key-vault", c.Type())
}

func TestAzureKV_GetSecret_Latest(t *testing.T) {
	fake := &fakeAzKV{value: strptr("az-s3cr3t")}
	val, err := azKVConnectorWith("az", "https://v.vault.azure.net/", fake).GetSecret(context.Background(), "db-password")
	require.NoError(t, err)
	assert.Equal(t, "az-s3cr3t", val)
	assert.Equal(t, "db-password", fake.gotName)
	assert.Equal(t, "", fake.gotVersion, "a bare name reads the current version")
}

func TestAzureKV_GetSecret_PinnedVersion(t *testing.T) {
	fake := &fakeAzKV{value: strptr("v2")}
	val, err := azKVConnectorWith("az", "https://v.vault.azure.net/", fake).GetSecret(context.Background(), "db-password/abc123")
	require.NoError(t, err)
	assert.Equal(t, "v2", val)
	assert.Equal(t, "db-password", fake.gotName)
	assert.Equal(t, "abc123", fake.gotVersion, "name/version pins the version")
}

// TestAzureKV_GetSecret_EmptyStringRejected is a dedicated, narrow regression
// test for the Azure sibling of the AWS SecretsManager empty-value bug: a
// non-nil pointer to "" is a real value's zero-length case, not "no value",
// so GetSecret must not treat it as success. The fuzzer's own oracle
// (FuzzAzureKVConnectorResponse) had the identical pointer-only blind spot
// and was strengthened alongside this fix, but this is deliberately a direct
// point test too, so this claim has its own unambiguous proving test in
// docs/security-closures.tsv rather than sharing FuzzAzureKVConnectorResponse
// with the unrelated connect-redirect-refusal-001 claim.
func TestAzureKV_GetSecret_EmptyStringRejected(t *testing.T) {
	fake := &fakeAzKV{value: strptr("")}
	_, err := azKVConnectorWith("az", "https://v.vault.azure.net/", fake).GetSecret(context.Background(), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

func TestAzureKV_GetSecret_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := azKVConnectorWith("az", "https://v.vault.azure.net/", &fakeAzKV{}).GetSecret(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("missing vault address", func(t *testing.T) {
		_, err := azKVConnectorWith("az", "", &fakeAzKV{}).GetSecret(context.Background(), "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no vault address")
	})
	t.Run("empty name", func(t *testing.T) {
		_, err := azKVConnectorWith("az", "https://v.vault.azure.net/", &fakeAzKV{}).GetSecret(context.Background(), "/v1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty secret name")
	})
	t.Run("backend error", func(t *testing.T) {
		_, err := azKVConnectorWith("az", "https://v.vault.azure.net/", &fakeAzKV{err: errors.New("Forbidden")}).GetSecret(context.Background(), "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Forbidden")
	})
	t.Run("no value", func(t *testing.T) {
		_, err := azKVConnectorWith("az", "https://v.vault.azure.net/", &fakeAzKV{value: nil}).GetSecret(context.Background(), "x")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no value")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeAzKV{value: strptr("x")}
		c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake, "keyorix-")
		_, err := c.GetSecret(context.Background(), "other-secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.False(t, fake.called, "a disallowed ref must not reach the backend")
	})
}
