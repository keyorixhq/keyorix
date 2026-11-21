package startup

import (
	"path/filepath"
	"strings"
	"testing"
)

// #4395: with a non-password provider the KEK salt is not part of the key set,
// so validateEncryption must neither require it nor refuse on a leftover
// salt_path; it says once that the key is ignored.
func TestValidateEncryption_NonPasswordProvider_SaltIgnored(t *testing.T) {
	dir := t.TempDir()
	dek := writeKeyFile(t, dir, "dek.key", 60)
	absentSalt := filepath.Join(dir, "kek.salt")

	for _, tc := range []struct {
		name     string
		salt     string
		wantWarn bool
	}{
		{"salt_path unset", "", false},
		{"salt_path set, file absent", absentSalt, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := encCfg(tc.salt, dek)
			cfg.Storage.Encryption.KeyProvider.Type = "env"
			res := &ValidationResult{}
			if err := validateEncryption(cfg, res, false); err != nil {
				t.Fatalf("env provider must not need a salt file: %v", err)
			}
			warned := false
			for _, w := range res.Warnings {
				if strings.Contains(w, "storage.encryption.salt_path") && strings.Contains(w, "unused by provider env") {
					warned = true
				}
			}
			if warned != tc.wantWarn {
				t.Fatalf("warning present = %v, want %v (warnings: %q)", warned, tc.wantWarn, res.Warnings)
			}
		})
	}
}

func TestValidateEncryption_NonPasswordProvider_DEKStillRequired(t *testing.T) {
	dir := t.TempDir()
	cfg := encCfg(filepath.Join(dir, "kek.salt"), filepath.Join(dir, "dek.key"))
	cfg.Storage.Encryption.KeyProvider.Type = "env"
	if err := validateEncryption(cfg, &ValidationResult{}, false); err == nil {
		t.Fatal("a missing wrapped DEK must still be refused")
	}
	// Tolerant (first boot): a missing DEK alone is "not provisioned yet".
	res := &ValidationResult{}
	if err := validateEncryption(cfg, res, true); err != nil {
		t.Fatalf("first boot must be tolerated: %v", err)
	}
}
