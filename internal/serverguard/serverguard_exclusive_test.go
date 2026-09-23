package serverguard

// serverguard_exclusive_test.go covers AcquireExclusive directly (the
// hold-for-the-whole-operation API admin commands must use) and both
// directions of contention with AcquirePresence: a server refusing to boot
// while an admin operation holds the exclusive lock (non-blocking, fails
// fast with a specific message -- the review-requested fix), and an admin
// command refusing to proceed while a server holds the shared lock.

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestSQLite_AcquireExclusive_SucceedsWhenFree(t *testing.T) {
	cfg := sqliteCfg(t)
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	defer lock.Release() //nolint:errcheck
}

func TestSQLite_AcquireExclusive_ConflictsWithAnotherExclusive(t *testing.T) {
	cfg := sqliteCfg(t)
	first, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("first AcquireExclusive: %v", err)
	}
	defer first.Release() //nolint:errcheck

	if _, err := AcquireExclusive(cfg); err == nil {
		t.Fatal("expected a second concurrent AcquireExclusive to fail")
	}
}

func TestSQLite_AcquireExclusive_ConflictsWithPresence(t *testing.T) {
	cfg := sqliteCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	defer presence.Release() //nolint:errcheck

	if _, err := AcquireExclusive(cfg); err == nil {
		t.Fatal("expected AcquireExclusive to fail while a server holds the presence lock")
	}
}

// TestSQLite_AcquirePresence_FailsFastWhileExclusiveHeld is the direct
// regression test for the review finding: a server must refuse to start
// (non-blocking, with a specific message) while an admin operation holds
// the exclusive lock -- not hang, and not get a generic error.
func TestSQLite_AcquirePresence_FailsFastWhileExclusiveHeld(t *testing.T) {
	cfg := sqliteCfg(t)
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	defer lock.Release() //nolint:errcheck

	done := make(chan error, 1)
	go func() {
		_, err := AcquirePresence(cfg)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected AcquirePresence to fail while the exclusive lock is held")
		}
		if !strings.Contains(err.Error(), "admin operation is running") {
			t.Errorf("expected a specific admin-operation-in-progress message, got: %v", err)
		}
		if !strings.Contains(err.Error(), "retry when it finishes") {
			t.Errorf("expected the message to tell the operator to retry, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcquirePresence blocked instead of failing fast -- non-blocking guarantee violated")
	}
}

func TestSQLite_AcquireExclusive_SucceedsAfterPresenceReleases(t *testing.T) {
	cfg := sqliteCfg(t)
	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("AcquirePresence: %v", err)
	}
	if err := presence.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("expected AcquireExclusive to succeed once the server released presence: %v", err)
	}
	_ = lock.Release()
}

func TestSQLite_AcquirePresence_SucceedsAfterExclusiveReleases(t *testing.T) {
	cfg := sqliteCfg(t)
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	presence, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("expected AcquirePresence to succeed once the admin operation released: %v", err)
	}
	_ = presence.Release()
}

func TestRemoteStorage_AcquireExclusive_NoOp(t *testing.T) {
	cfg := &config.Config{Storage: config.StorageConfig{Type: "remote"}}
	lock, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release on no-op Exclusive: %v", err)
	}
}
