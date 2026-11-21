//go:build !windows

package encryption

// resguard_keylifecycle_pg_test.go -- the PostgreSQL (and SQLite) leg of the
// KL1 key-material leak oracle (task KL1). FuzzKeyLifecycleCrashKeyLeak
// (resguard_keylifecycle_crash_test.go) carries the real-SIGKILL fuzzing on
// SQLite; the leak oracle itself is database-INDEPENDENT (it scans the LOCAL key
// directory, written by the same internal/encryption KeyManager code in either
// deployment), so this white-box test proves it once on BOTH backends at every
// rotation crash checkpoint, reusing FuzzDEKSweepCrashConsistency's fuzzworld
// setup.
//
// K1: after a true DEK rotation with sweep (RotateDEKWithSweep) is crashed at
// each durability checkpoint and then recovered (RecoverInterruptedRotation +
// Initialize), no file in the key directory may contain, byte-for-byte, the raw
// DEK or any KEK-derived key-material value (evidence-sign, audit-checkpoint,
// backup-manifest) — pre-rotation or post-recovery. All are held only in memory
// and are never persisted, so any on-disk occurrence is a leak.
//
// PostgreSQL uses a fuzzworld SCHEMA named kl1_keyleak_<pid>_<seq> (dropped on
// cleanup) inside the KEYORIX_TEST_PG_DSN database — no database is created, and
// the schema is kl1_-prefixed, per the KL1 runtime rules.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

const (
	kleakPGPass   = "kl1-keyleak-passphrase-0001"
	kleakPGPrefix = "kl1_keyleak"
)

// kleakNeedlesFromService returns the key-material values readable from an
// initialized Service: the raw DEK plus the three derived keys. Each is memory-
// only and must never appear in any file.
func kleakNeedlesFromService(svc *Service) [][]byte {
	var ns [][]byte
	add := func(b []byte) {
		if len(b) >= 16 {
			ns = append(ns, append([]byte(nil), b...))
		}
	}
	add(svc.keyManager.GetDEK())
	if k, _, ok := svc.EvidenceSignKey(); ok {
		add(k)
	}
	if k, _, ok := svc.AuditCheckpointKey(); ok {
		add(k)
	}
	if k, _, ok := svc.BackupManifestKey(); ok {
		add(k)
	}
	return ns
}

// kleakScanDir returns a description of any regular file under root whose bytes
// contain any needle.
func kleakScanDir(root string, needles [][]byte) []string {
	var hits []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		data, rerr := os.ReadFile(p) //nolint:gosec // test-generated key dir
		if rerr != nil {
			return nil
		}
		for i, n := range needles {
			if bytes.Contains(data, n) {
				rel, _ := filepath.Rel(root, p)
				hits = append(hits, fmt.Sprintf("needle#%d in %s", i, rel))
			}
		}
		return nil
	})
	return hits
}

// runKeyLeakSweepCase seeds an install, crashes a DEK sweep at target, recovers,
// and returns any key-material leak hits under the key directory. plant, when
// set, runs after recovery (red-proof only).
func runKeyLeakSweepCase(t *testing.T, w *fuzzworld.World, dir, target string, plant func(dir string, needles [][]byte)) []string {
	t.Helper()
	if err := w.Reset(sweepDBTables); err != nil {
		t.Fatalf("[%s] reset: %v", w.Backend, err)
	}
	db := w.DB

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	svc.keyManager.SetKeyProvider(staticKEKProvider{})
	if e := svc.Initialize(kleakPGPass); e != nil {
		t.Fatalf("[%s] seed Initialize: %v", w.Backend, e)
	}
	preNeedles := kleakNeedlesFromService(svc)
	if len(preNeedles) == 0 {
		t.Fatalf("[%s] no pre-rotation key material readable", w.Backend)
	}

	for i := range 3 {
		projID := uint(i + 1)
		node := &models.SecretNode{ProjectID: projID, Name: fmt.Sprintf("kl1-node-%d", i), IsSecret: true}
		if e := db.Create(node).Error; e != nil {
			t.Fatalf("[%s] seed node: %v", w.Backend, e)
		}
		aad := SecretAAD(node.ID, projID, 1)
		enc, meta, e := svc.EncryptSecretWithAAD([]byte(fmt.Sprintf("kl1-secret-%d", i)), aad)
		if e != nil {
			t.Fatalf("[%s] seed encrypt: %v", w.Backend, e)
		}
		if e := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; e != nil {
			t.Fatalf("[%s] seed version: %v", w.Backend, e)
		}
	}

	runSweepWithCrash(svc, kleakPGPass, db, target)
	svc.Shutdown()

	rec := NewService(cfg, dir)
	rec.keyManager.SetKeyProvider(staticKEKProvider{})
	if e := rec.RecoverInterruptedRotation(db); e != nil {
		t.Fatalf("[%s] RecoverInterruptedRotation(%q): %v", w.Backend, target, e)
	}
	if e := rec.Initialize(kleakPGPass); e != nil {
		t.Fatalf("[%s] recovery Initialize(%q): %v", w.Backend, target, e)
	}
	needles := append(append([][]byte(nil), preNeedles...), kleakNeedlesFromService(rec)...)
	rec.Shutdown()

	if plant != nil {
		plant(dir, needles)
	}
	return kleakScanDir(dir, needles)
}

// TestKeyLifecycleKeyLeakBackends proves K1 on SQLite and (when
// KEYORIX_TEST_PG_DSN is set) PostgreSQL, at every DEK-sweep crash checkpoint.
func TestKeyLifecycleKeyLeakBackends(t *testing.T) {
	if testing.Short() {
		t.Skip("key-lifecycle leak oracle: migrates a DB per world")
	}
	worlds := fuzzworld.Worlds(t, kleakPGPrefix, ":memory:", 0)
	for _, w := range worlds {
		for _, target := range sweepCrashLabels {
			label := target
			if label == "" {
				label = "no-crash"
			}
			t.Run(w.Backend+"/"+label, func(t *testing.T) {
				dir := t.TempDir()
				if hits := runKeyLeakSweepCase(t, w, dir, target, nil); len(hits) > 0 {
					t.Fatalf("[%s] K1 PLAINTEXT KEY MATERIAL after crash %q: %v", w.Backend, target, hits)
				}
			})
		}
	}
}

// TestKeyLifecycleKeyLeakRedProof confirms the scan actually fires: a scratch
// file holding the real key material makes it red; the same run without the
// plant (TestKeyLifecycleKeyLeakBackends) is green.
func TestKeyLifecycleKeyLeakRedProof(t *testing.T) {
	if testing.Short() {
		t.Skip("key-lifecycle leak oracle red-proof: migrates a DB")
	}
	worlds := fuzzworld.Worlds(t, kleakPGPrefix, ":memory:", 0)
	plant := func(dir string, needles [][]byte) {
		if err := os.WriteFile(filepath.Join(dir, "LEAKED.scratch"), needles[0], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// SQLite world is always present (index 0).
	hits := runKeyLeakSweepCase(t, worlds[0], t.TempDir(), "sweep:after-sweep-commit", plant)
	if len(hits) == 0 {
		t.Fatalf("red-proof: planted key material was not detected by the scan")
	}
}
