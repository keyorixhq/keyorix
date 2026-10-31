package encryptionops

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

// PILOT-FIRSTRUN-FIXES-1 (#3742): `admin encryption init` blamed "a live server or an
// in-progress key operation" for every failure to open the DEK lock file, including a key
// directory that does not exist. The hint belongs to lock contention only.

const liveServerHint = "live server"

func keysSubdirConfig() *config.Config {
	cfg := testConfig(true)
	cfg.Storage.Encryption.DEKPath = "keys/dek.key"
	cfg.Storage.Encryption.SaltPath = "keys/kek.salt"
	return cfg
}

func TestInitLocalKeyOpService_MissingKeyDirectoryIsNotBlamedOnALiveServer(t *testing.T) {
	baseDir := chdirTemp(t)
	cfg := keysSubdirConfig()

	_, err := InitLocalKeyOpService(cfg, baseDir, testBaselinePassphrase, true)
	if err == nil {
		t.Fatal("init succeeded with a missing key directory")
	}
	msg := err.Error()
	if strings.Contains(msg, liveServerHint) || strings.Contains(msg, "in-progress key operation") {
		t.Fatalf("a missing key directory was blamed on a live server: %v", err)
	}
	for _, want := range []string{"key directory", "keys", "does not exist", "keyorix-server admin init", "0700"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message lacks %q: %v", want, err)
		}
	}
}

func TestInitLocalKeyOpService_HeldLockStillSaysLiveServer(t *testing.T) {
	baseDir := chdirTemp(t)
	cfg := keysSubdirConfig()
	if err := os.Mkdir("keys", 0o700); err != nil {
		t.Fatal(err)
	}

	holder := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := holder.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("holder.Initialize: %v", err)
	}
	if err := holder.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("holder.AcquireExclusiveKeyLock: %v", err)
	}
	defer holder.Shutdown()

	_, err := InitLocalKeyOpService(cfg, baseDir, testBaselinePassphrase, true)
	if err == nil {
		t.Fatal("init succeeded while another process holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), liveServerHint) {
		t.Fatalf("lock contention lost its live-server hint: %v", err)
	}
	if strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("lock contention reported as a missing directory: %v", err)
	}
}

func TestInitLocalKeyOpService_PermissionDeniedIsNeitherHint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	baseDir := chdirTemp(t)
	cfg := keysSubdirConfig()
	if err := os.Mkdir("keys", 0o500); err != nil { // no write: the lock file cannot be created
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod("keys", 0o700) })

	_, err := InitLocalKeyOpService(cfg, baseDir, testBaselinePassphrase, true)
	if err == nil {
		t.Fatal("init succeeded in a read-only key directory")
	}
	msg := err.Error()
	if strings.Contains(msg, liveServerHint) || strings.Contains(msg, "does not exist") {
		t.Fatalf("permission denied got a misleading hint: %v", err)
	}
	if !strings.Contains(msg, "permission denied") {
		t.Fatalf("the real cause (permission denied) is missing: %v", err)
	}
}
