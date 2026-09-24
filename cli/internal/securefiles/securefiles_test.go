package securefiles

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSecureCreateFileHandle_RefusesPreExistingPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := SecureCreateFileHandle(dir, "existing.txt", 0o600); err == nil {
		t.Fatal("expected an error when creating over a pre-existing path")
	}
}

// TestSecureCreateFileHandle_RefusesSymlinkAtLeaf is the security-critical case this
// package exists for: a symlink planted at the target path must never be followed
// (which would write through it to wherever it points), regardless of whether the
// symlink's target itself exists.
func TestSecureCreateFileHandle_RefusesSymlinkAtLeaf(t *testing.T) {
	dir := t.TempDir()
	outsideTarget := filepath.Join(t.TempDir(), "outside.txt")
	linkPath := filepath.Join(dir, "link.txt")
	if err := os.Symlink(outsideTarget, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := SecureCreateFileHandle(dir, "link.txt", 0o600); err == nil {
		t.Fatal("expected an error when the target path is a symlink")
	}
	if _, statErr := os.Stat(outsideTarget); statErr == nil {
		t.Fatal("SecureCreateFileHandle must never have written through the symlink")
	}
}

func TestSecureCreateFileHandle_CreatesNewFileWithRequestedPerm(t *testing.T) {
	dir := t.TempDir()
	f, err := SecureCreateFileHandle(dir, "fresh.txt", 0o600)
	if err != nil {
		t.Fatalf("SecureCreateFileHandle: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
	}
}

func TestSecureCreateFileHandle_RejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	if _, err := SecureCreateFileHandle(dir, "../escape.txt", 0o600); err == nil {
		t.Fatal("expected an error for a path escaping baseDir")
	}
}

func TestSecureOpenBeneath_RefusesSymlinkAtIntermediateComponent(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkDir := filepath.Join(dir, "linkdir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := SecureOpenBeneath(dir, "linkdir/file.txt", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600); err == nil {
		t.Fatal("expected an error when an intermediate path component is a symlink")
	}
}
