package serverguard

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// SERVERGUARD-LOCK-TAILS-1 item 1: the admin side of the SQLite sidecar watch.
// An admin command's exclusive lock is an flock on <db>.server.lock's inode.
// If the sidecar is deleted or replaced while the command runs, a server
// arriving afterwards creates a new file and starts beside the command, and
// both write. The command must notice within the same interval the server's
// watch uses, close Exclusive.Lost (server/admin stops the command), and keep
// every second acquisition out until it has released.

// waitExclusiveLost waits for x.Lost, failing the test after a generous bound.
func waitExclusiveLost(t *testing.T, x *Exclusive, interval time.Duration, why string) {
	t.Helper()
	select {
	case <-x.Lost():
	case <-time.After(200 * interval):
		t.Fatalf("Exclusive.Lost did not close although %s", why)
	}
}

// assertSecondAcquisitionRefused checks that neither a server nor another
// admin command can attach while the stopped command still holds its lock.
func assertSecondAcquisitionRefused(t *testing.T, lockPath string, cfg *config.Config) {
	t.Helper()
	if p, err := AcquirePresence(cfg); err == nil {
		_ = p.Release()
		t.Fatalf("a server attached beside an admin command whose sidecar %s was deleted or replaced, before the command stopped", lockPath)
	}
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatalf("a second admin command attached beside one whose sidecar %s was deleted or replaced, before the first stopped", lockPath)
	} else if !IsLockHeld(err) {
		t.Fatalf("want a lock-held refusal for the second admin command, got %v", err)
	}
}

// TestSQLiteExclusive_DeletedSidecarClosesLost: the sidecar is deleted while
// an admin command holds it. Lost closes within the watch interval, a second
// acquisition (server or admin) is refused until the command releases, and
// one succeeds after that.
func TestSQLiteExclusive_DeletedSidecarClosesLost(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, lockPath := sqliteGuardCfg(t)
	logs := captureLog(t)
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = x.Release()
		}
	}()

	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	waitExclusiveLost(t, x, interval, "the sidecar was deleted under the admin command")
	if !strings.Contains(logs.String(), "serverguard admin exclusive lock:") {
		t.Errorf("the loss was not logged with its cause; log:\n%s", logs.String())
	}
	assertSecondAcquisitionRefused(t, lockPath, cfg)

	if err := x.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	released = true
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("a server could not attach after the stopped admin command released: %v", err)
	}
	_ = p.Release()
}

// TestSQLiteExclusive_ReplacedSidecarClosesLost: the same when the file is
// replaced by a new inode under the same name.
func TestSQLiteExclusive_ReplacedSidecarClosesLost(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, lockPath := sqliteGuardCfg(t)
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	defer func() { _ = x.Release() }()

	tmp := lockPath + ".new"
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, lockPath); err != nil {
		t.Fatal(err)
	}
	waitExclusiveLost(t, x, interval, "the sidecar was replaced under the admin command")
	assertSecondAcquisitionRefused(t, lockPath, cfg)
}

// TestSQLiteExclusive_ServerGotInFirst_ClosesLost: a server attaches to the
// re-created sidecar before the admin command's watch runs (the window this
// watch cannot close). The command cannot take the new file, and Lost still
// closes, naming the cause.
func TestSQLiteExclusive_ServerGotInFirst_ClosesLost(t *testing.T) {
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 300 * time.Millisecond // the server below attaches well inside one interval
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
	cfg, lockPath := sqliteGuardCfg(t)
	logs := captureLog(t)
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	defer func() { _ = x.Release() }()
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatalf("precondition: a server attaches to the re-created sidecar inside the watch interval: %v", err)
	}
	defer func() { _ = p.Release() }()

	waitExclusiveLost(t, x, config.PinnedLockPingInterval, "a server attached to the replaced sidecar beside the admin command")
	if !strings.Contains(logs.String(), "a server or another admin command now holds the new file") {
		t.Errorf("the loss was not logged with its cause; log:\n%s", logs.String())
	}
}

// TestSQLiteExclusive_HealthySidecarNeverReportsLost is the control: an
// untouched sidecar never closes Lost, during the hold or after Release.
func TestSQLiteExclusive_HealthySidecarNeverReportsLost(t *testing.T) {
	interval := fastSidecarWatch(t)
	cfg, _ := sqliteGuardCfg(t)
	x, err := AcquireExclusive(cfg)
	if err != nil {
		t.Fatalf("AcquireExclusive: %v", err)
	}
	select {
	case <-x.Lost():
		t.Fatal("Lost closed for an untouched sidecar")
	case <-time.After(20 * interval):
	}
	if err := x.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case <-x.Lost():
		t.Fatal("Lost closed after Release")
	case <-time.After(10 * interval):
	}
}
