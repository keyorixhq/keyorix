package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultRegistry_EmptyKeysNoError verifies that DefaultRegistry with no
// embedded keys returns a non-nil registry without error (fail-closed, not
// fail-hard), and that verification fails closed for both purposes.
func TestDefaultRegistry_EmptyKeysNoError(t *testing.T) {
	// In a non-release build, updateKeysB64 and licenseKeysB64 are both empty.
	// The function must succeed and return a registry that trusts nothing.
	r, err := DefaultRegistry()
	require.NoError(t, err, "DefaultRegistry must not error when no keys are embedded")
	require.NotNil(t, r)

	// Verification must fail closed for every purpose.
	assert.ErrorIs(t, r.Verify(PurposeUpdate, "any", []byte("msg"), []byte("sig")), ErrNoKeys)
	assert.ErrorIs(t, r.Verify(PurposeLicense, "any", []byte("msg"), []byte("sig")), ErrNoKeys)
}

// TestDefaultRegistry_WithValidUpdateKey verifies that DefaultRegistry correctly
// parses a valid embedded key spec and trusts it.  We temporarily set the
// package-level variable to simulate a release build.
func TestDefaultRegistry_WithValidUpdateKey(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)

	// Temporarily set the package-level variable (same package access).
	orig := updateKeysB64
	updateKeysB64 = "test-key-1=" + base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updateKeysB64 = orig })

	r, err := DefaultRegistry()
	require.NoError(t, err)
	require.NotNil(t, r)

	msg := []byte("test payload")
	sig := ed25519.Sign(priv, msg)
	require.NoError(t, r.Verify(PurposeUpdate, "test-key-1", msg, sig))

	// License purpose still has no keys → fails closed.
	assert.ErrorIs(t, r.Verify(PurposeLicense, "test-key-1", msg, sig), ErrNoKeys)
}

// TestDefaultRegistry_WithValidLicenseKey mirrors the update-key test for the
// license purpose so both map iterations are covered.
func TestDefaultRegistry_WithValidLicenseKey(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)

	origLic := licenseKeysB64
	licenseKeysB64 = "lic-key-1=" + base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { licenseKeysB64 = origLic })

	r, err := DefaultRegistry()
	require.NoError(t, err)

	msg := []byte("license data")
	sig := ed25519.Sign(priv, msg)
	require.NoError(t, r.Verify(PurposeLicense, "lic-key-1", msg, sig))
}

// TestDefaultRegistry_MalformedKeySpec exercises the error path in DefaultRegistry
// where parseKeySpec returns an error (malformed spec → build misconfiguration).
func TestDefaultRegistry_MalformedKeySpec(t *testing.T) {
	orig := updateKeysB64
	updateKeysB64 = "malformed-no-equals-sign"
	t.Cleanup(func() { updateKeysB64 = orig })

	_, err := DefaultRegistry()
	require.Error(t, err, "a malformed embedded key spec must surface as an error")
}

// TestDefaultRegistry_CrossPurposeKeyReuseErrors exercises the r.Add error path inside
// DefaultRegistry's parse loop: if the update and license specs embed the SAME public key
// (under different key-ids), the second Add call fails with ErrKeyReusedAcrossPurposes and
// DefaultRegistry must propagate that error rather than silently building a registry that
// violates the independent-blast-radii guarantee (see the Purpose doc comment).
func TestDefaultRegistry_CrossPurposeKeyReuseErrors(t *testing.T) {
	pub, _, err := GenerateKey()
	require.NoError(t, err)
	encoded := base64.StdEncoding.EncodeToString(pub)

	origUpdate := updateKeysB64
	origLicense := licenseKeysB64
	updateKeysB64 = "upd-shared=" + encoded
	licenseKeysB64 = "lic-shared=" + encoded
	t.Cleanup(func() {
		updateKeysB64 = origUpdate
		licenseKeysB64 = origLicense
	})

	r, err := DefaultRegistry()
	require.Error(t, err, "embedding the same public key for both purposes must be refused")
	assert.ErrorIs(t, err, ErrKeyReusedAcrossPurposes)
	assert.Nil(t, r, "DefaultRegistry must not return a partially-built registry on error")
}

// TestDefaultRegistry_MultipleKeys verifies that a comma-separated spec with
// several keys is parsed and all keys are usable.
func TestDefaultRegistry_MultipleKeys(t *testing.T) {
	pub1, priv1, err := GenerateKey()
	require.NoError(t, err)
	pub2, priv2, err := GenerateKey()
	require.NoError(t, err)

	orig := updateKeysB64
	updateKeysB64 = "k1=" + base64.StdEncoding.EncodeToString(pub1) +
		",k2=" + base64.StdEncoding.EncodeToString(pub2)
	t.Cleanup(func() { updateKeysB64 = orig })

	r, err := DefaultRegistry()
	require.NoError(t, err)

	msg := []byte("multi")
	require.NoError(t, r.Verify(PurposeUpdate, "k1", msg, ed25519.Sign(priv1, msg)))
	require.NoError(t, r.Verify(PurposeUpdate, "k2", msg, ed25519.Sign(priv2, msg)))
	assert.ElementsMatch(t, []string{"k1", "k2"}, r.KeyIDs(PurposeUpdate))
}
