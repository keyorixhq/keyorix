package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// #4395: a salt_path is only meaningful to the password provider.
func TestEncryptionConfig_SaltUse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kp       KeyProviderConfig
		wantUses bool
	}{
		{"default (empty type) is password", KeyProviderConfig{}, true},
		{"password", KeyProviderConfig{Type: "password"}, true},
		{"env", KeyProviderConfig{Type: "env"}, false},
		{"file", KeyProviderConfig{Type: "file"}, false},
		{"exec", KeyProviderConfig{Type: "exec"}, false},
		{"shamir", KeyProviderConfig{Type: "shamir"}, false},
		{"tpm", KeyProviderConfig{Type: "tpm"}, false},
		{"aws-kms", KeyProviderConfig{Type: "aws-kms"}, false},
		{"env with password fallback", KeyProviderConfig{Type: "env", Fallbacks: []KeyProviderConfig{{Type: "password"}}}, true},
		{"env with file fallback", KeyProviderConfig{Type: "env", Fallbacks: []KeyProviderConfig{{Type: "file"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &EncryptionConfig{Enabled: true, SaltPath: "keys/kek.salt", KeyProvider: tc.kp}
			require.Equal(t, tc.wantUses, e.UsesSalt())
			if tc.wantUses {
				require.Equal(t, "keys/kek.salt", e.EffectiveSaltPath())
				require.Empty(t, e.UnusedSaltPathWarning())
				return
			}
			require.Empty(t, e.EffectiveSaltPath())
			w := e.UnusedSaltPathWarning()
			require.Contains(t, w, "storage.encryption.salt_path")
			require.Contains(t, w, "unused by provider "+tc.kp.Type)
			require.False(t, strings.Contains(w, "\n"), "one line")
		})
	}
}

func TestEncryptionConfig_UnusedSaltPathWarning_QuietWhenNothingToSay(t *testing.T) {
	var nilCfg *EncryptionConfig
	require.Empty(t, nilCfg.UnusedSaltPathWarning())
	require.Empty(t, (&EncryptionConfig{Enabled: true, KeyProvider: KeyProviderConfig{Type: "env"}}).UnusedSaltPathWarning(), "no salt_path set")
	require.Empty(t, (&EncryptionConfig{SaltPath: "x", KeyProvider: KeyProviderConfig{Type: "env"}}).UnusedSaltPathWarning(), "encryption disabled")
}
