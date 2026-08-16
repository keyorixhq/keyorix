package crypto_test

import (
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubProvider struct {
	name string
	key  []byte
	err  error
}

func (s *stubProvider) Name() string         { return s.name }
func (s *stubProvider) KEK() ([]byte, error) { return s.key, s.err }

func goodProvider(name string) *stubProvider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &stubProvider{name: name, key: key}
}

func badProvider(name string) *stubProvider {
	return &stubProvider{name: name, err: errors.New("provider unavailable")}
}

func TestMultiKeyProvider_EmptyListError(t *testing.T) {
	_, err := crypto.NewMultiKeyProvider(nil)
	require.Error(t, err)
}

func TestMultiKeyProvider_PrimarySucceeds(t *testing.T) {
	good := goodProvider("primary")
	bad := badProvider("fallback")
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{good, bad})
	require.NoError(t, err)
	key, err := m.KEK()
	require.NoError(t, err)
	assert.Equal(t, good.key, key)
}

func TestMultiKeyProvider_FallsBackOnPrimaryFailure(t *testing.T) {
	fbKey := make([]byte, 32)
	for i := range fbKey {
		fbKey[i] = 0xff
	}
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{
		badProvider("primary"),
		&stubProvider{name: "fallback", key: fbKey},
	})
	require.NoError(t, err)
	key, err := m.KEK()
	require.NoError(t, err)
	assert.Equal(t, fbKey, key)
}

func TestMultiKeyProvider_AllFail(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{badProvider("a"), badProvider("b")})
	require.NoError(t, err)
	_, err = m.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all key providers failed")
}

func TestMultiKeyProvider_Name(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{goodProvider("aws-kms"), goodProvider("file")})
	require.NoError(t, err)
	assert.Equal(t, "multi(aws-kms,file)", m.Name())
}

// ── ProviderTierOf / DetectFallbackDowngrade ─────────────────────────────────

func TestProviderTierOf_Ordering(t *testing.T) {
	hardware := []string{"tpm", "aws-kms", "gcp-kms", "azure-kms"}
	for _, name := range hardware {
		assert.Equal(t, crypto.TierHardware, crypto.ProviderTierOf(name), name)
	}
	assert.Equal(t, crypto.TierDistributed, crypto.ProviderTierOf("shamir"))
	software := []string{"password", "file", "env", "exec"}
	for _, name := range software {
		assert.Equal(t, crypto.TierSoftware, crypto.ProviderTierOf(name), name)
	}
	assert.Equal(t, crypto.TierUnknown, crypto.ProviderTierOf("some-future-provider-type"))

	// Ordering must hold for the downgrade check to mean anything.
	assert.Less(t, int(crypto.TierUnknown), int(crypto.TierSoftware))
	assert.Less(t, int(crypto.TierSoftware), int(crypto.TierDistributed))
	assert.Less(t, int(crypto.TierDistributed), int(crypto.TierHardware))
}

func TestDetectFallbackDowngrade_EmptyOrSingle(t *testing.T) {
	_, ok := crypto.DetectFallbackDowngrade(nil)
	assert.False(t, ok)
	_, ok = crypto.DetectFallbackDowngrade([]crypto.KeyProvider{goodProvider("tpm")})
	assert.False(t, ok)
}

func TestDetectFallbackDowngrade_KMSPrimary_PasswordFallback_Downgrades(t *testing.T) {
	d, ok := crypto.DetectFallbackDowngrade([]crypto.KeyProvider{
		goodProvider("aws-kms"), goodProvider("password"),
	})
	require.True(t, ok)
	assert.Equal(t, 1, d.Index)
	assert.Equal(t, "password", d.Provider)
	assert.Equal(t, crypto.TierHardware, d.FromTier)
	assert.Equal(t, crypto.TierSoftware, d.ToTier)
}

// TestDetectFallbackDowngrade_SameTier_NoDowngrade covers the legitimate,
// non-downgrading multi-provider use case (e.g. KMS-in-a-different-region
// fallback) that must keep working with no opt-in required.
func TestDetectFallbackDowngrade_SameTier_NoDowngrade(t *testing.T) {
	_, ok := crypto.DetectFallbackDowngrade([]crypto.KeyProvider{
		goodProvider("aws-kms"), goodProvider("gcp-kms"),
	})
	assert.False(t, ok)
}

func TestDetectFallbackDowngrade_Upgrade_NoDowngrade(t *testing.T) {
	_, ok := crypto.DetectFallbackDowngrade([]crypto.KeyProvider{
		goodProvider("password"), goodProvider("tpm"),
	})
	assert.False(t, ok)
}

// TestDetectFallbackDowngrade_LaterStepDowngradesFromEarlierPeak covers a chain
// where the weak step isn't directly after the primary: [password, tpm, password]
// — the strength ceiling set by the tpm step in the middle must still be
// enforced against the final password fallback, not just against the primary.
func TestDetectFallbackDowngrade_LaterStepDowngradesFromEarlierPeak(t *testing.T) {
	d, ok := crypto.DetectFallbackDowngrade([]crypto.KeyProvider{
		goodProvider("password"), goodProvider("tpm"), goodProvider("password"),
	})
	require.True(t, ok)
	assert.Equal(t, 2, d.Index)
	assert.Equal(t, crypto.TierHardware, d.FromTier)
	assert.Equal(t, crypto.TierSoftware, d.ToTier)
}

// ── MultiKeyProvider runtime downgrade hook ──────────────────────────────────

func TestMultiKeyProvider_KEK_FiresDowngradeHookOnRealFallback(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{
		badProvider("tpm"), goodProvider("password"),
	})
	require.NoError(t, err)

	var got *crypto.FallbackDowngrade
	m.SetDowngradeHook(func(d crypto.FallbackDowngrade) {
		got = &d
	})

	_, err = m.KEK()
	require.NoError(t, err)
	require.NotNil(t, got, "downgrade hook must fire when the provider that actually succeeds is weaker than an earlier provider in the chain")
	assert.Equal(t, "password", got.Provider)
	assert.Equal(t, crypto.TierHardware, got.FromTier)
	assert.Equal(t, crypto.TierSoftware, got.ToTier)
}

func TestMultiKeyProvider_KEK_NoDowngradeHookWhenPrimarySucceeds(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{
		goodProvider("tpm"), goodProvider("password"),
	})
	require.NoError(t, err)

	called := false
	m.SetDowngradeHook(func(d crypto.FallbackDowngrade) { called = true })

	_, err = m.KEK()
	require.NoError(t, err)
	assert.False(t, called, "the hook must not fire when the primary itself succeeds — no fallback happened")
}

func TestMultiKeyProvider_KEK_NoDowngradeHookOnSameTierFallback(t *testing.T) {
	m, err := crypto.NewMultiKeyProvider([]crypto.KeyProvider{
		badProvider("aws-kms"), goodProvider("gcp-kms"),
	})
	require.NoError(t, err)

	called := false
	m.SetDowngradeHook(func(d crypto.FallbackDowngrade) { called = true })

	_, err = m.KEK()
	require.NoError(t, err)
	assert.False(t, called, "a same-tier fallback (e.g. KMS in a different region) must not be treated as a downgrade")
}
