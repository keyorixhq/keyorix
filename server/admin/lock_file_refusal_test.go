package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestAcquireDatabaseLock_UnopenableLockFileSaysSo: REVIEW-SERVERGUARD-RECOVERYKEY-1
// F7. A .server.lock the admin command cannot open (another user's 0600 file,
// simulated with mode 000) fails closed, and the refusal must name the lock
// file, not claim the database could not be reached.
func TestAcquireDatabaseLock_UnopenableLockFileSaysSo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode 000 file")
	}
	forceFlag = false
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	lockFile := dbPath + ".server.lock"
	if err := os.WriteFile(lockFile, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}}}
	lock, err := acquireDatabaseLock(cfg)
	if err == nil {
		if lock != nil {
			_ = lock.Release()
		}
		t.Fatal("expected acquireDatabaseLock to fail on an unopenable lock file")
	}
	if !strings.Contains(err.Error(), "cannot open the server lock file: ") || !strings.Contains(err.Error(), lockFile) {
		t.Fatalf("expected the lock-file message naming %s, got: %v", lockFile, err)
	}
	for _, wrong := range []string{"cannot connect to the database", "appears to be using this database"} {
		if strings.Contains(err.Error(), wrong) {
			t.Fatalf("a lock-file open error must not say %q, got: %v", wrong, err)
		}
	}
}
