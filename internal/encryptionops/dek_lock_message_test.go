package encryptionops

import (
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
