package serverguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func sqliteCfg(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: filepath.Join(dir, "secrets.db")},
		},
	}
}

func TestSQLite_ProbeRunning_FalseWhenNoServer(t *testing.T) {
	cfg := sqliteCfg(t)
	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatalf("expected running=false with no server, got true (detail=%q)", detail)
	}
}

func TestSQLite_ProbeRunning_TrueWhileServerHoldsPresence(t *testing.T) {
	cfg := sqliteCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer presence.Release() //nolint:errcheck

	running, detail, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !running {
		t.Fatal("expected running=true while a server holds the presence lock")
	}
	if detail == "" {
		t.Fatal("expected a non-empty detail message")
	}
}

func TestSQLite_ProbeRunning_FalseAfterServerReleases(t *testing.T) {
	cfg := sqliteCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if err := presence.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	running, _, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if running {
		t.Fatal("expected running=false after the server released its presence lock")
	}
}

func TestSQLite_MultipleServerReplicas_ShareCoexist(t *testing.T) {
	// Two "server replicas" against the same local file both holding the
	// SHARED presence lock must not conflict with each other -- only the
	// EXCLUSIVE probe used by admin commands treats that as contention.
	cfg := sqliteCfg(t)
	p1, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("first AcquirePresence: %v", err)
	}
	defer p1.Release() //nolint:errcheck

	p2, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("second AcquirePresence (concurrent shared holder) unexpectedly failed: %v", err)
	}
	defer p2.Release() //nolint:errcheck
}

func TestSQLite_InMemoryDatabase_NoOp(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: ":memory:"},
		},
	}
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if presence.release != nil {
		t.Fatal("expected a no-op Presence for an in-memory database")
	}
	running, _, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("ProbeRunning: %v", err)
	}
	if running {
		t.Fatal("expected running=false for an in-memory database (nothing to guard)")
	}
}

func TestRemoteStorage_NoOp(t *testing.T) {
	cfg := &config.Config{Storage: config.StorageConfig{Type: "remote"}}
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if err := presence.Release(); err != nil {
		t.Fatalf("Release on no-op Presence: %v", err)
	}
	running, _, err := ProbeRunning(cfg)
	if err != nil {
		t.Fatalf("ProbeRunning: %v", err)
	}
	if running {
		t.Fatal("expected running=false for remote storage (no local database to guard)")
	}
}

func TestSQLite_LockFileCreatedAlongsideDatabase(t *testing.T) {
	cfg := sqliteCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer presence.Release() //nolint:errcheck

	lockPath := cfg.Storage.Database.Path + serverLockSuffix
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("expected server lock sidecar file at %s: %v", lockPath, err)
	}
}
