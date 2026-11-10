package keyfiles

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// PendingRotationFiles is what `admin backup` refuses on, and Registry is what
// it archives, so the two must agree on every staging file: a file only
// Registry knew would be archived again without a refusal (#4058).
func TestPendingRotationFiles_AgreesWithRegistry(t *testing.T) {
	enc := &config.EncryptionConfig{DEKPath: "dek.key", SaltPath: "kek.salt"}
	cases := []struct {
		name    string
		present []string
		salt    []bool
	}{
		{"none", nil, nil},
		{"dek only", []string{"dek.key.pending"}, []bool{false}},
		{"salt only", []string{"kek.salt.pending"}, []bool{true}},
		{"both", []string{"kek.salt.pending", "dek.key.pending"}, []bool{true, false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "dek.key"))
			writeFile(t, filepath.Join(dir, "kek.salt"))
			var want []string
			for _, name := range c.present {
				writeFile(t, filepath.Join(dir, name))
				want = append(want, filepath.Join(dir, name))
			}

			found, err := PendingRotationFiles(enc, dir)
			if err != nil {
				t.Fatalf("PendingRotationFiles: %v", err)
			}
			var got []string
			for i, f := range found {
				got = append(got, f.Path)
				if f.Salt != c.salt[i] {
					t.Errorf("%s: Salt = %v, want %v", f.Path, f.Salt, c.salt[i])
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("PendingRotationFiles = %v, want %v", got, want)
			}

			specs, err := Registry(enc, dir)
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			var extra []string
			for _, s := range specs {
				if s.Path != filepath.Join(dir, "dek.key") && s.Path != filepath.Join(dir, "kek.salt") {
					extra = append(extra, s.Path)
				}
			}
			if !slices.Equal(extra, want) {
				t.Fatalf("Registry's optional files = %v, PendingRotationFiles = %v", extra, want)
			}
		})
	}
}

func TestPendingRotationFiles_NilConfig(t *testing.T) {
	found, err := PendingRotationFiles(nil, t.TempDir())
	if err != nil || found != nil {
		t.Fatalf("PendingRotationFiles(nil) = %v, %v; want nil, nil", found, err)
	}
}

// A path that cannot be checked must not read as "no rotation pending".
func TestPendingRotationFiles_UncheckablePathFailsClosed(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	enc := &config.EncryptionConfig{DEKPath: filepath.Join(notADir, "dek.key")}
	if found, err := PendingRotationFiles(enc, dir); err == nil {
		t.Fatalf("PendingRotationFiles = %v, nil; want an error", found)
	}
}

func TestPendingRotationFiles_RejectsUnsafePath(t *testing.T) {
	enc := &config.EncryptionConfig{DEKPath: "../dek.key"}
	if found, err := PendingRotationFiles(enc, t.TempDir()); err == nil {
		t.Fatalf("PendingRotationFiles = %v, nil; want an error", found)
	}
}
