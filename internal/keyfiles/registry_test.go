package keyfiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRegistry_NilConfig(t *testing.T) {
	specs, err := Registry(nil, "")
	if err != nil {
		t.Fatalf("Registry(nil): %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("Registry(nil) = %+v, want empty", specs)
	}
}

func TestRegistry_SaltAndDEK(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("Registry = %+v, want exactly salt+DEK", specs)
	}
	wantSalt := filepath.Join(dir, "salt.key")
	wantDEK := filepath.Join(dir, "dek.key")
	var gotSalt, gotDEK bool
	for _, s := range specs {
		if s.Path == wantSalt {
			gotSalt = true
		}
		if s.Path == wantDEK {
			gotDEK = true
		}
		if s.Mode != 0600 {
			t.Errorf("spec %+v mode != 0600", s)
		}
	}
	if !gotSalt || !gotDEK {
		t.Fatalf("Registry = %+v, missing salt or DEK", specs)
	}
}

func TestRegistry_EmptyPathsSkipped(t *testing.T) {
	dir := t.TempDir()
	specs, err := Registry(&config.EncryptionConfig{}, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("Registry with no configured paths = %+v, want empty", specs)
	}
}

func TestRegistry_AbsolutePathPreserved(t *testing.T) {
	dir := t.TempDir()
	absSalt := filepath.Join(dir, "abs-salt.key")
	enc := &config.EncryptionConfig{SaltPath: absSalt}
	specs, err := Registry(enc, "/some/unrelated/base")
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(specs) != 1 || specs[0].Path != absSalt {
		t.Fatalf("Registry = %+v, want the absolute salt path preserved as-is (%s)", specs, absSalt)
	}
}

func TestRegistry_PendingFiles_OnlyIncludedWhenPresent(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}

	// No .pending files yet: must not appear (and must not be required either
	// -- Registry itself never stats the required salt/DEK paths, only the
	// optional .pending ones).
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("Registry with no .pending files = %+v, want just salt+DEK", specs)
	}

	// Create the DEK's .pending rotation-staging file: it must now appear.
	writeFile(t, filepath.Join(dir, "dek.key.pending"))
	specs, err = Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	wantPending := filepath.Join(dir, "dek.key.pending")
	var found bool
	for _, s := range specs {
		if s.Path == wantPending {
			found = true
		}
	}
	if !found {
		t.Fatalf("Registry after creating dek.key.pending = %+v, want it included", specs)
	}
	if len(specs) != 3 {
		t.Fatalf("Registry = %+v, want exactly salt+DEK+dek.pending", specs)
	}
}

func TestRegistry_TPMWrappedKeyPath(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "tpm", WrappedKeyPath: "tpm-wrapped.key"},
	}
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	want := filepath.Join(dir, "tpm-wrapped.key")
	var found bool
	for _, s := range specs {
		if s.Path == want && s.Mode == 0600 {
			found = true
		}
	}
	if !found {
		t.Fatalf("Registry (tpm) = %+v, want wrapped-key path %s at 0600", specs, want)
	}
}

func TestRegistry_KMSWrappedKeyPath_AllThreeCloudTypes(t *testing.T) {
	for _, providerType := range []string{"aws-kms", "gcp-kms", "azure-kms"} {
		t.Run(providerType, func(t *testing.T) {
			dir := t.TempDir()
			enc := &config.EncryptionConfig{
				KeyProvider: config.KeyProviderConfig{Type: providerType, WrappedKeyPath: "kms-wrapped.key"},
			}
			specs, err := Registry(enc, dir)
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			want := filepath.Join(dir, "kms-wrapped.key")
			var found bool
			for _, s := range specs {
				if s.Path == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("Registry (%s) = %+v, want wrapped-key path %s", providerType, specs, want)
			}
		})
	}
}

func TestRegistry_PasswordAndFileAndEnvAndExec_NoExtraPaths(t *testing.T) {
	for _, providerType := range []string{"", "password", "file", "env", "exec"} {
		t.Run(providerType, func(t *testing.T) {
			dir := t.TempDir()
			enc := &config.EncryptionConfig{
				KeyProvider: config.KeyProviderConfig{
					Type:        providerType,
					FilePath:    "/etc/keyorix/kek.key", // must NOT be added -- externally managed, self-checked elsewhere
					EnvVar:      "KEYORIX_KEK",
					ExecCommand: []string{"op", "read", "op://vault/kek"},
				},
			}
			specs, err := Registry(enc, dir)
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			if len(specs) != 0 {
				t.Fatalf("Registry (%q) = %+v, want no entries (no salt/DEK/wrapped-key configured, and FilePath/EnvVar/ExecCommand are deliberately not registered)", providerType, specs)
			}
		})
	}
}

func TestRegistry_ShamirShareFiles(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:             "shamir",
			ShamirShareFiles: []string{"share1.hex", "", "share3.hex"},
		},
	}
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	want1 := filepath.Join(dir, "share1.hex")
	want3 := filepath.Join(dir, "share3.hex")
	var got1, got3 bool
	for _, s := range specs {
		if s.Path == want1 {
			got1 = true
		}
		if s.Path == want3 {
			got3 = true
		}
	}
	if !got1 || !got3 {
		t.Fatalf("Registry (shamir) = %+v, want both non-empty share files included", specs)
	}
	if len(specs) != 2 {
		t.Fatalf("Registry (shamir) = %+v, want exactly 2 entries (the empty share entry must be skipped)", specs)
	}
}

func TestRegistry_Fallbacks_OneLevel(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			WrappedKeyPath: "primary-wrapped.key",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "aws-kms", WrappedKeyPath: "fallback-wrapped.key"},
			},
		},
	}
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	wantPrimary := filepath.Join(dir, "primary-wrapped.key")
	wantFallback := filepath.Join(dir, "fallback-wrapped.key")
	var gotPrimary, gotFallback bool
	for _, s := range specs {
		if s.Path == wantPrimary {
			gotPrimary = true
		}
		if s.Path == wantFallback {
			gotFallback = true
		}
	}
	if !gotPrimary || !gotFallback {
		t.Fatalf("Registry (with fallback) = %+v, want both primary and fallback wrapped-key paths", specs)
	}
}

func TestRegistry_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	const traversal = "sub/../../outside/salt.key"

	t.Run("salt", func(t *testing.T) {
		enc := &config.EncryptionConfig{SaltPath: traversal, DEKPath: filepath.Join(dir, "dek.key")}
		if _, err := Registry(enc, dir); err == nil {
			t.Fatal("expected error for a salt path containing '..'")
		}
	})
	t.Run("dek", func(t *testing.T) {
		enc := &config.EncryptionConfig{SaltPath: filepath.Join(dir, "salt.key"), DEKPath: traversal}
		if _, err := Registry(enc, dir); err == nil {
			t.Fatal("expected error for a DEK path containing '..'")
		}
	})
	t.Run("wrapped key path", func(t *testing.T) {
		enc := &config.EncryptionConfig{
			KeyProvider: config.KeyProviderConfig{Type: "tpm", WrappedKeyPath: traversal},
		}
		if _, err := Registry(enc, dir); err == nil {
			t.Fatal("expected error for a wrapped-key path containing '..'")
		}
	})
	t.Run("shamir share file", func(t *testing.T) {
		enc := &config.EncryptionConfig{
			KeyProvider: config.KeyProviderConfig{Type: "shamir", ShamirShareFiles: []string{traversal}},
		}
		if _, err := Registry(enc, dir); err == nil {
			t.Fatal("expected error for a shamir share path containing '..'")
		}
	})
}

func TestRegistry_DedupesRepeatedPaths(t *testing.T) {
	dir := t.TempDir()
	// A misconfiguration where the fallback's wrapped-key path happens to
	// equal the primary's -- must not produce two FixFilePerms entries for
	// the same file.
	enc := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			WrappedKeyPath: "same.key",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "aws-kms", WrappedKeyPath: "same.key"},
			},
		},
	}
	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("Registry = %+v, want the duplicate path deduped to a single entry", specs)
	}
}

func TestSafePath_RejectsTraversal(t *testing.T) {
	if _, err := SafePath("test", "sub/../../outside"); err == nil {
		t.Fatal("expected error for a traversal path")
	}
}

func TestSafePath_AcceptsCleanRelative(t *testing.T) {
	clean, err := SafePath("test", "sub/file.key")
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if clean != filepath.Clean("sub/file.key") {
		t.Fatalf("SafePath = %q, want %q", clean, filepath.Clean("sub/file.key"))
	}
}
