package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption"
)

// CONFIG-TRUTH-1 item 2 (#3742): `admin encryption init` blamed a live server for
// every exclusive-lock failure, including a key directory that does not exist.

func TestInitLocalKeyOpService_MissingKeyDirNamesTheDirNotAServer(t *testing.T) {
	base := t.TempDir()
	cfg := testConfig(true)
	cfg.Storage.Encryption.DEKPath = "keys/dek.key"
	cfg.Storage.Encryption.SaltPath = "keys/kek.salt"

	_, err := InitLocalKeyOpService(cfg, base, "pw-for-the-test-0123456789", true)
	if err == nil {
		t.Fatal("init with a missing key directory must fail")
	}
	want := "key directory " + filepath.Join(base, "keys") + " does not exist: run `keyorix-server admin init` (or create it with mode 0700)"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
	if strings.Contains(err.Error(), "live server") {
		t.Errorf("a missing directory must not blame a live server: %q", err)
	}
}

func TestInitLocalKeyOpService_LockContentionKeepsTheLiveServerHint(t *testing.T) {
	base := t.TempDir()
	cfg := testConfig(true)

	holder := encryption.NewService(&cfg.Storage.Encryption, base)
	if err := holder.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("holder lock: %v", err)
	}
	defer holder.Shutdown()

	_, err := InitLocalKeyOpService(cfg, base, "pw-for-the-test-0123456789", true)
	if err == nil {
		t.Fatal("init must be refused while the key directory is locked")
	}
	if !strings.Contains(err.Error(), "a live server or an in-progress key operation is using this key directory") {
		t.Errorf("lock contention must keep the live-server hint: %q", err)
	}
	if strings.Contains(err.Error(), "does not exist") {
		t.Errorf("contention is not a missing directory: %q", err)
	}
}

// An unwritable key directory is neither contention nor missing: the message
// names the directory and says what to fix, and does not blame a live server.
func TestInitLocalKeyOpService_UnwritableKeyDirNamesTheDirNotAServer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	base := t.TempDir()
	keys := filepath.Join(base, "keys")
	if err := os.Mkdir(keys, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keys, 0o700) })
	cfg := testConfig(true)
	cfg.Storage.Encryption.DEKPath = "keys/dek.key"
	cfg.Storage.Encryption.SaltPath = "keys/kek.salt"

	_, err := InitLocalKeyOpService(cfg, base, "pw-for-the-test-0123456789", true)
	if err == nil {
		t.Fatal("init with an unwritable key directory must fail")
	}
	if !strings.Contains(err.Error(), "key directory "+keys) || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %q, want the key directory path and the permission cause", err)
	}
	if strings.Contains(err.Error(), "live server") {
		t.Errorf("an unwritable directory must not blame a live server: %q", err)
	}
}
