package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// validLocalConfig returns the minimal Config that passes every Validate()
// check ahead of the secrets.limits.max_secret_size checks under test here.
func validLocalConfig() *Config {
	c := &Config{}
	c.Storage.Type = "local"
	c.Storage.Database.Path = "/tmp/keyorix.db"
	return c
}

func TestValidate_MaxSecretSize_DefaultsWhenUnset(t *testing.T) {
	c := validLocalConfig()
	require.Zero(t, c.Secrets.Limits.MaxSecretSize, "test setup: expected zero-value MaxSecretSize")
	require.NoError(t, c.Validate())
	require.Equal(t, DefaultMaxSecretSize, c.Secrets.Limits.MaxSecretSize)
}

func TestValidate_MaxSecretSize_AcceptsExplicitValueUnderCeiling(t *testing.T) {
	c := validLocalConfig()
	c.Secrets.Limits.MaxSecretSize = 128 * 1024 // 128 KiB, under the 1 MiB ceiling
	require.NoError(t, c.Validate())
	require.Equal(t, 128*1024, c.Secrets.Limits.MaxSecretSize, "an explicitly configured value must not be overwritten")
}

func TestValidate_MaxSecretSize_AcceptsExactlyTheHardCeiling(t *testing.T) {
	c := validLocalConfig()
	c.Secrets.Limits.MaxSecretSize = MaxSecretSizeHardCeiling
	require.NoError(t, c.Validate(), "exactly at the ceiling must be accepted, not just under it")
}

func TestValidate_MaxSecretSize_RejectsAboveHardCeiling(t *testing.T) {
	c := validLocalConfig()
	c.Secrets.Limits.MaxSecretSize = MaxSecretSizeHardCeiling + 1
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_secret_size")
	require.Contains(t, err.Error(), "hard ceiling")
}

func TestValidate_MaxSecretSize_RejectsNegative(t *testing.T) {
	c := validLocalConfig()
	c.Secrets.Limits.MaxSecretSize = -1
	require.Error(t, c.Validate())
}

func TestDeriveMaxRequestBodySize_ExactBase64PlusHeadroom(t *testing.T) {
	// Verified against the exact documented formula rather than a hand-computed
	// literal, so this test fails loudly if the formula's shape ever changes
	// rather than silently drifting out of sync with it.
	got := DeriveMaxRequestBodySize(DefaultMaxSecretSize)
	wantBase64 := int64(((DefaultMaxSecretSize + 2) / 3) * 4)
	want := wantBase64 + secretSizeEnvelopeHeadroomBytes
	require.Equal(t, want, got)

	// A base64-encoded DefaultMaxSecretSize-byte value must actually fit under
	// the derived limit -- the property this function exists to guarantee.
	require.LessOrEqual(t, wantBase64, got,
		"a base64-encoded max-size secret would not fit under the derived body limit")
}

func TestDeriveMaxRequestBodySize_MonotonicInInput(t *testing.T) {
	small := DeriveMaxRequestBodySize(1024)
	large := DeriveMaxRequestBodySize(DefaultMaxSecretSize)
	require.Less(t, small, large, "the derived limit must grow with the configured secret size")
}
