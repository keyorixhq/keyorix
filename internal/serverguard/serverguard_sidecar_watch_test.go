package serverguard

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1 F4: the SQLite presence lock is an flock on
// the sidecar's inode, not on its name. An operator who deletes (or replaces)
// <db>.server.lock while a server runs, taking it for a stale lock file, leaves
// the server holding a lock on a file nobody else can open, and the next admin
// command creates a new file and gets the exclusive lock beside the server.
// The server must notice within one watch interval: take the lock again on
// the file the path now names, or, when an admin command got there first,
// close Lost so it stops serving (the PostgreSQL lost-lock contract).

func sqliteGuardCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "secrets.db")
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}}}
	return cfg, dbPath + serverLockSuffix
}

// fastSidecarWatch shortens the watch interval the SQLite presence watcher
// shares with the PostgreSQL one.
func fastSidecarWatch(t *testing.T) time.Duration {
	t.Helper()
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 20 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
	return config.PinnedLockPingInterval
}

// syncBuffer is a log output the watcher goroutine writes while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog sends the standard logger to a buffer for the test's duration.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return buf
}

// waitRelocked waits for the watcher's "took the presence lock again" line,
// so a loaded machine cannot make the admin probe below win the race the
// next test is about. On the unfixed code nothing is logged and the probe
// runs after the deadline.
func waitRelocked(logs *syncBuffer, interval time.Duration) {
	deadline := time.Now().Add(100 * interval)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "took the presence lock again") {
		time.Sleep(interval)
	}
}

// TestSQLitePresence_DeletedSidecarIsTakenAgain: after the sidecar is deleted
// under a running server, the server re-creates it and holds it SHARED again
// within one interval, so an admin command arriving afterwards is refused, and
// the server keeps running (Lost stays open).
func TestSQLitePresence_DeletedSidecarIsTakenAgain(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, lockPath := sqliteGuardCfg(t)
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer func() { _ = p.Release() }()

	logs := captureLog(t)
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	waitRelocked(logs, interval)

	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("the deleted sidecar was not re-created by the watcher: %v", err)
	}
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("an admin command got the exclusive lock beside a running server after the sidecar was deleted and the server had one interval to take it again")
	} else if !IsLockHeld(err) {
		t.Fatalf("want a lock-held refusal, got %v", err)
	}
	select {
	case <-p.Lost():
		t.Fatal("Lost closed although the server took the lock back")
	default:
	}
}

// TestSQLitePresence_ReplacedSidecarIsTakenAgain: the same when the file is
// replaced (a new inode under the same name: an editor, a restore of the data
// directory, `mv x .server.lock`) rather than deleted.
func TestSQLitePresence_ReplacedSidecarIsTakenAgain(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, lockPath := sqliteGuardCfg(t)
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer func() { _ = p.Release() }()

	logs := captureLog(t)
	tmp := lockPath + ".new"
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, lockPath); err != nil {
		t.Fatal(err)
	}
	waitRelocked(logs, interval)

	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("an admin command got the exclusive lock beside a running server after the sidecar was replaced")
	} else if !IsLockHeld(err) {
		t.Fatalf("want a lock-held refusal, got %v", err)
	}
	select {
	case <-p.Lost():
		t.Fatal("Lost closed although the server took the lock back")
	default:
	}
}

// TestSQLitePresence_DeletedSidecarTakenByAdminFirst_ClosesLost: when an admin
// command creates the new sidecar and takes it exclusively before the watcher's
// next tick, the server cannot take it back. It must close Lost (the server
// then shuts down through awaitShutdown, as on a lost PostgreSQL presence lock)
// instead of serving beside the admin command.
func TestSQLitePresence_DeletedSidecarTakenByAdminFirst_ClosesLost(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, lockPath := sqliteGuardCfg(t)
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer func() { _ = p.Release() }()

	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	x, err := AcquireExclusive(cfg) // the hole F4 describes: this succeeds
	if err != nil {
		t.Fatalf("precondition: an admin command takes the re-created sidecar: %v", err)
	}
	defer func() { _ = x.Release() }()

	select {
	case <-p.Lost():
	case <-time.After(50 * interval):
		t.Fatal("Lost did not close although an admin command holds the sidecar's new file exclusively beside the running server")
	}
	// Release after a loss still works and does not touch the admin's lock.
	if err := p.Release(); err != nil {
		t.Fatalf("Release after a loss: %v", err)
	}
	if x2, err := AcquireExclusive(cfg); err == nil {
		_ = x2.Release()
		t.Fatal("the server's Release dropped the admin command's exclusive lock")
	}
}

// TestSQLitePresence_HealthySidecarNeverReportsLost: the control. While the
// sidecar is left alone, many ticks pass without a loss, and Release ends the
// watch: an admin command then gets the lock, and Lost is never closed after
// Release.
func TestSQLitePresence_HealthySidecarNeverReportsLost(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, _ := sqliteGuardCfg(t)
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	select {
	case <-p.Lost():
		t.Fatal("Lost closed on an untouched sidecar")
	case <-time.After(10 * interval):
	}
	lost := p.Lost()
	if err := p.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive after Release: %v", err)
	}
	defer func() { _ = x.Release() }()
	select {
	case <-lost:
		t.Fatal("Lost closed after Release")
	case <-time.After(5 * interval):
	}
}
