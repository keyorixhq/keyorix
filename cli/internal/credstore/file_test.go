package credstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore_SaveWritesMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "credentials.yaml")
	s := NewFileStore(path)

	if err := s.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o, want 0600", perm)
	}
}

// CLI-CREDSTORE-001 regression guard: os.OpenFile's mode argument is only applied when
// O_CREATE actually creates a new file -- if credentials.yaml already exists (e.g. from
// a misconfigured shared host, or an older CLI version) with wider permissions, O_TRUNC
// reuses it as-is and Save must not silently write the token into it unprotected.
func TestFileStore_SaveFixesPreExistingWidePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")

	if err := os.WriteFile(path, []byte("stale-placeholder"), 0o644); err != nil {
		t.Fatalf("seed a pre-existing 0644 file: %v", err)
	}

	s := NewFileStore(path)
	if err := s.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o after Save on a pre-existing 0644 file, want 0600", perm)
	}

	// Load must succeed too -- the whole point of fixing the mode is that the
	// credentials Save just wrote are actually readable back through Load's own
	// perm-width refusal.
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load after Save-onto-pre-existing-file: %v", err)
	}
	if got.Token != "tok" {
		t.Fatalf("Load().Token = %q, want %q", got.Token, "tok")
	}
}

func TestFileStore_SaveThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	s := NewFileStore(path)

	want := Credentials{ServerURL: "https://example.test", Token: "tok-abc"}
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("Load() = %+v, want %+v", got, want)
	}
}

func TestFileStore_LoadRefusesWiderPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	s := NewFileStore(path)

	if err := s.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := s.Load(); err == nil {
		t.Fatal("Load succeeded on a 0644 credentials file, want a refusal")
	}
}

func TestFileStore_LoadRefusesGroupReadablePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	s := NewFileStore(path)

	if err := s.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := s.Load(); err == nil {
		t.Fatal("Load succeeded on a 0640 (group-readable) credentials file, want a refusal")
	}
}

func TestFileStore_LoadWithoutSaveFails(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(filepath.Join(dir, "does-not-exist.yaml"))

	if _, err := s.Load(); err == nil {
		t.Fatal("Load succeeded with no stored credentials, want an error")
	}
}

func TestFileStore_ClearRemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	s := NewFileStore(path)

	if err := s.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after Clear: err=%v", err)
	}
}

func TestFileStore_ClearWithoutSaveIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(filepath.Join(dir, "does-not-exist.yaml"))

	if err := s.Clear(); err != nil {
		t.Fatalf("Clear on a never-saved store: %v", err)
	}
}

func TestFileStore_LoadRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-credentials.yaml")
	link := filepath.Join(dir, "credentials.yaml")

	realStore := NewFileStore(real)
	if err := realStore.Save(Credentials{ServerURL: "https://example.test", Token: "tok"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	s := NewFileStore(link)
	if _, err := s.Load(); err == nil {
		t.Fatal("Load succeeded through a symlink, want a refusal")
	}
}
