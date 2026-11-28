package encryption

// dek_epoch_test.go: the cross-replica DEK epoch (dek_epoch.go) parts that need
// no PostgreSQL: SQLite stays untouched, the write gate's staleness rule, and
// the swept-table list staying in step with the sweep. The PostgreSQL behaviour
// is in dek_epoch_postgres_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"gorm.io/gorm"
)

// The package's tests do not need production fence timing; tests that check a
// bound set their own values.
func init() {
	dekEpochPollInterval = 50 * time.Millisecond
	dekEpochMaxStaleness = 300 * time.Millisecond
	dekEpochFenceWait = 400 * time.Millisecond
}

func newEpochTestService(t *testing.T, dir string) *Service {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	svc := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize("epoch-test-passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return svc
}

func copyKeyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(to, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"dek.key", "kek.salt"} {
		b, err := os.ReadFile(filepath.Join(from, "keys", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, "keys", f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func epochValue(t *testing.T, db *gorm.DB) (string, bool) {
	t.Helper()
	v, found, err := readDEKEpoch(db)
	if err != nil {
		t.Fatalf("read epoch: %v", err)
	}
	return v, found
}

// SQLite is single-node: no watcher and no fence, but since SQLITE-DEK-EPOCH-1
// the boot guard seeds the epoch and a rotation keeps it consistent (atomically,
// in the sweep transaction, with no "rotating:<old>" fenced state).
func TestDEKEpoch_SQLiteBootSeedsAndRotationKeepsEpoch(t *testing.T) {
	db := fuzzworld.OpenSQLite(t, "file:"+filepath.Join(t.TempDir(), "e.db"), 1)
	fuzzworld.Bootstrap(t, db)
	svc := newEpochTestService(t, t.TempDir())
	defer svc.Shutdown()

	released := false
	if err := svc.StartDEKEpochGuard(db, func() { released = true }); err != nil {
		t.Fatalf("StartDEKEpochGuard on SQLite: %v", err)
	}
	// Single node: boot verifies at boot only — no watcher goroutine, and the
	// handle is not kept (release is never called).
	if svc.DEKEpochGuardRunning() || released {
		t.Fatalf("guard running=%v released=%v on SQLite, want neither (boot-time check only)", svc.DEKEpochGuardRunning(), released)
	}
	// A fresh database seeds the epoch to this DEK's fingerprint.
	fp, err := svc.DEKFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if v, found := epochValue(t, db); !found || v != fp {
		t.Fatalf("after a SQLite boot, epoch = %q (found=%v), want this DEK's fingerprint %q", v, found, fp)
	}

	// Rotation moves the epoch to the new DEK in the same transaction as the sweep
	// — never a "rotating:<old>" fenced value — so the next boot still matches.
	if _, err := svc.RotateDEKWithSweep("epoch-test-passphrase", db); err != nil {
		t.Fatalf("rotate on SQLite: %v", err)
	}
	newFP, err := svc.DEKFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if newFP == fp {
		t.Fatalf("rotation did not change the DEK fingerprint (%q)", fp)
	}
	if v, found := epochValue(t, db); !found || v != newFP {
		t.Fatalf("after a SQLite rotation, epoch = %q (found=%v), want the new DEK's fingerprint %q", v, found, newFP)
	}
	if _, _, err := svc.EncryptSecretWithAAD([]byte("x"), []byte("aad")); err != nil {
		t.Fatalf("encrypt after SQLite rotation: %v", err)
	}

	// A second boot under the rotated DEK must be accepted (epoch matches), and a
	// repeat start must stay idempotent (no mismatch, no watcher).
	if err := svc.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("second StartDEKEpochGuard on SQLite after rotation: %v", err)
	}
	if svc.DEKEpochGuardRunning() {
		t.Fatal("a watcher started on SQLite; single-node SQLite must verify at boot only")
	}
}

// The write gate fences when no poll confirmed the epoch within
// dekEpochMaxStaleness (database unreachable), and immediately on a mismatch.
func TestDEKEpochWatch_AllowWrite(t *testing.T) {
	w := &dekEpochWatch{own: "own", base: time.Now()}
	if err := w.allowWrite(); !errors.Is(err, ErrDEKWriteFenced) {
		t.Fatalf("never confirmed: got %v, want ErrDEKWriteFenced", err)
	}
	w.markMatch(time.Since(w.base))
	if err := w.allowWrite(); err != nil {
		t.Fatalf("just confirmed: %v", err)
	}
	w.base = w.base.Add(-2 * dekEpochMaxStaleness) // the confirmation is now older than the bound
	if err := w.allowWrite(); !errors.Is(err, ErrDEKWriteFenced) {
		t.Fatalf("stale confirmation: got %v, want ErrDEKWriteFenced", err)
	}
	w.markMatch(time.Since(w.base))
	obs := "rotating:own"
	w.observed.Store(&obs)
	w.lastMatch.Store(0)
	if err := w.allowWrite(); !errors.Is(err, ErrDEKWriteFenced) || !strings.Contains(err.Error(), "rotating:own") {
		t.Fatalf("mismatch: got %v, want ErrDEKWriteFenced naming the observed epoch", err)
	}
}

// The rotation locks exactly the tables SweepAllTables re-encrypts.
func TestSweptModels_MatchSweptFields(t *testing.T) {
	var got []string
	for _, m := range sweptModels() {
		got = append(got, reflect.TypeOf(m).Elem().Name())
	}
	seen := map[string]bool{}
	var want []string
	for f := range expectedSweptFields {
		if !seen[f.Struct] {
			seen[f.Struct] = true
			want = append(want, f.Struct)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sweptModels() = %v, SweepAllTables sweeps %v: the rotation must lock every swept table", got, want)
	}
}
