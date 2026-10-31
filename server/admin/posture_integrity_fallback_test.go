package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func tpmConfig(t *testing.T, fallbacks ...string) *config.Config {
	t.Helper()
	blob := filepath.Join(t.TempDir(), "kek.tpm")
	if err := os.WriteFile(blob, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	kp := &cfg.Storage.Encryption.KeyProvider
	kp.Type = "tpm"
	kp.WrappedKeyPath = blob
	for _, typ := range fallbacks {
		kp.Fallbacks = append(kp.Fallbacks, config.KeyProviderConfig{Type: typ})
	}
	if len(fallbacks) > 0 {
		kp.AllowWeakerFallback = true
	}
	return cfg
}

func TestIntegrityEnvReportsWeakerFallback(t *testing.T) {
	cases := []struct {
		name      string
		fallbacks []string
		want      string
	}{
		{"no fallback", nil, ""},
		{"password fallback", []string{"password"}, "password"},
		{"empty type means password", []string{""}, "password"},
		{"first weaker one is named", []string{"aws-kms", "file", "env"}, "file"},
		{"shamir is weaker than tpm", []string{"shamir"}, "shamir"},
		{"unknown type is treated as weaker", []string{"mystery"}, "mystery"},
		{"hardware fallback is not weaker", []string{"aws-kms"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := integrityEnv(tpmConfig(t, c.fallbacks...)).TPM.WeakerFallback; got != c.want {
				t.Fatalf("WeakerFallback = %q, want %q", got, c.want)
			}
		})
	}
	t.Run("non-tpm primary is not annotated", func(t *testing.T) {
		cfg := tpmConfig(t, "password")
		cfg.Storage.Encryption.KeyProvider.Type = "password"
		if got := integrityEnv(cfg).TPM.WeakerFallback; got != "" {
			t.Fatalf("WeakerFallback = %q, want empty when the primary is not tpm", got)
		}
	})
}
