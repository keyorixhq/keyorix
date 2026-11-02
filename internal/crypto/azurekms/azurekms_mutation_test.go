package azurekms

// Tests added for the gremlins survivors on internal/crypto/azurekms (#3612,
// MUTANT-CRYPTO-1).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// azurekms.go:212 — New's success path. A service-principal secret in the
// environment lets NewDefaultAzureCredential and azkeys.NewClient both build
// without any network access (credential construction and client construction
// are lazy; no token is requested until the first call).
func TestNew_SucceedsWithEnvironmentCredential(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "prod")
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000001")
	t.Setenv("AZURE_CLIENT_SECRET", "not-a-real-secret")

	got, err := New(context.Background(), "https://myvault.vault.azure.net/keys/kek/v7")
	require.NoError(t, err, "a valid key id with a constructible credential must yield a client")
	c, ok := got.(*client)
	require.True(t, ok)
	assert.Equal(t, "kek", c.keyName)
	assert.Equal(t, "v7", c.keyVersion)
	assert.NotNil(t, c.keys)
}

// azurekms.go:302 — an envelope written before the MAC field existed carries no
// MAC and must keep decrypting; the integrity check applies only when a MAC is
// present (len > 0). A `>= 0` check would compare against an empty MAC and
// reject every pre-MAC envelope.
func TestDecrypt_PinnedEnvelopeWithoutMACStillDecrypts(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "")

	wrapped, err := json.Marshal(fakeWrapped{Version: "v1", Plaintext: []byte("old-kek")})
	require.NoError(t, err)
	body, err := json.Marshal(envelope{Version: "v1", Ciphertext: wrapped}) // MAC omitted
	require.NoError(t, err)
	blob := append([]byte(envelopeMagic), body...)

	env, pinned, err := decodeEnvelope(blob)
	require.NoError(t, err)
	require.True(t, pinned)
	require.Empty(t, env.MAC, "fixture must model a pre-MAC envelope")

	pt, err := c.Decrypt(context.Background(), blob)
	require.NoError(t, err)
	assert.Equal(t, []byte("old-kek"), pt)
}

// And the other side of the same boundary: one byte of MAC is enough to engage
// the check, so a wrong MAC is refused.
func TestDecrypt_PinnedEnvelopeWithWrongMACRefused(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "")

	wrapped, err := json.Marshal(fakeWrapped{Version: "v1", Plaintext: []byte(testKEK32)})
	require.NoError(t, err)
	body, err := json.Marshal(envelope{Version: "v1", Ciphertext: wrapped, MAC: []byte{0x00}})
	require.NoError(t, err)

	_, err = c.Decrypt(context.Background(), append([]byte(envelopeMagic), body...))
	require.Error(t, err)
	assert.ErrorContains(t, err, "integrity check")
}
