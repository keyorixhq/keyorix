// key_commitment_epoch_db_test.go -- KEYCOMMIT-2 item 4: the DEK epoch check
// (dek_epoch.go) against a real database, for a key file that two KEKs both open.
//
// KEYCOMMIT-1 showed that wrapKey is not key-committing: one dek.key can open under
// two KEKs to two different DEKs, and named the DEK epoch fingerprint as the stand-in
// check. This file runs that check for real: a dek.key GHASH-partitioned across the
// KEKs derived from two passphrases (same kek.salt), loaded by the real Service
// (Initialize, the boot path of server/key_dir_lock.go) under each, against a
// database whose rows and epoch belong to the first.
//
// What this verifies:
//   - control: both Services boot (the documented wrapKey gap), hold DEKs with
//     different fingerprints, and the second cannot decrypt the first's row;
//   - PostgreSQL (KEYORIX_TEST_PG_DSN; otherwise a SKIP line, never a pass): the first
//     Service's StartDEKEpochGuard seeds the epoch, the second's is refused with
//     ErrDEKEpochMismatch and leaves the stored epoch unchanged (oracle
//     kcWrongKeyDEKViolation);
//   - SQLite (no DSN needed, so never SKIPs — SQLITE-DEK-EPOCH-1): the same
//     seed-then-refuse at boot, boot-time only (no watcher), via the same oracle;
//   - red-proof: the oracle reports a guard that returns nil, and one that refuses
//     for another reason, and stays quiet on the real refusal;
//   - an ordinary (non-partitioned) dek.key under the wrong passphrase is refused by
//     Initialize itself, so it is the partition that lets the second KEK in.
//
// What this does NOT verify: reachability beyond the two callers that load a
// dek.key (server boot via initializeKeysAndStartEpochGuard, restore via
// stageKeyFilesForKEKUnwrap), which this test does not drive; a database already
// holding rows under an epoch written by a different release; the PostgreSQL
// watcher/fence runtime behaviour (dek_epoch_postgres_test.go); concurrent boots.
package encryption

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	"gorm.io/gorm"
)

// kcWrongKeyDEKViolation is the oracle: loading a wrong-key DEK against a database
// recorded under another DEK must be refused as a DEK epoch mismatch.
func kcWrongKeyDEKViolation(guardErr error) string {
	switch {
	case guardErr == nil:
		return "WRONG-KEY DEK ACCEPTED: the epoch guard let a DEK that is not the database's DEK start"
	case !errors.Is(guardErr, ErrDEKEpochMismatch):
		return "refused for the wrong reason (not ErrDEKEpochMismatch): " + guardErr.Error()
	}
	return ""
}

func kcEpochService(t *testing.T, dir, pass string) *Service {
	t.Helper()
	svc := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := svc.Initialize(pass); err != nil {
		t.Fatalf("Initialize(%s): %v", pass, err)
	}
	t.Cleanup(svc.Shutdown)
	return svc
}

// kcKeyDir writes keys/kek.salt and keys/dek.key into a fresh directory.
func kcKeyDir(t *testing.T, salt, dekKey []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"kek.salt": salt, "dek.key": dekKey} {
		if err := os.WriteFile(filepath.Join(dir, "keys", name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const kcPassA, kcPassB = "kc2-pass-A", "kc2-pass-B"

func kcSalt(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, 32)
	if _, err := rand.Read(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// kcPartitionedDEKKey returns a wrapKey-layout dek.key (nonce||ct||tag, AAD nil)
// that opens under the KEKs of both passphrases (checked by stock GCM in partitioned).
func kcPartitionedDEKKey(t *testing.T, salt []byte) []byte {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct, tag, ok := partitioned(t, GenerateKEK(kcPassA, salt, 0), GenerateKEK(kcPassB, salt, 0), nonce, nil, make([]byte, 16))
	if !ok {
		t.Fatal("construction degenerate")
	}
	return append(append(append([]byte(nil), nonce...), ct...), tag...)
}

// kcEpochWorld boots two Services on one partitioned dek.key (A under the first
// passphrase, B under the second), checks the controls and writes one secret
// version under A's DEK.
func kcEpochWorld(t *testing.T, db *gorm.DB) (a, b *Service, node *models.SecretNode) {
	t.Helper()
	salt := kcSalt(t)
	dek := kcPartitionedDEKKey(t, salt)
	a = kcEpochService(t, kcKeyDir(t, salt, dek), kcPassA)
	b = kcEpochService(t, kcKeyDir(t, salt, dek), kcPassB) // boots: the documented wrapKey gap
	if fa, fb := fingerprintOf(t, a), fingerprintOf(t, b); fa == fb {
		t.Fatalf("control failed: both Services hold the same DEK (fingerprint %s), the key file was not partitioned", fa)
	}
	node = &models.SecretNode{ProjectID: 1, Name: "kc2-node", IsSecret: true}
	if err := db.Create(node).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := epochWrite(t, a, db, node, 1); err != nil {
		t.Fatalf("write under A's DEK: %v", err)
	}
	if bad := epochUndecryptable(t, a, db, node); len(bad) != 0 {
		t.Fatalf("control failed: A cannot decrypt its own row (versions %v)", bad)
	}
	if bad := epochUndecryptable(t, b, db, node); len(bad) != 1 {
		t.Fatalf("control failed: B decrypts the row written under A's DEK (undecryptable %v), so B's DEK is not a wrong-key DEK", bad)
	}
	return a, b, node
}

func TestKeyCommitment_EpochGuard_Postgres(t *testing.T) {
	db := fuzzworld.OpenPostgres(t, "kcepoch")
	if db == nil {
		t.Skip("SKIP: KEYORIX_TEST_PG_DSN not set: the DEK epoch check against a real PostgreSQL was NOT run")
	}
	fuzzworld.Bootstrap(t, db)
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	a, b, _ := kcEpochWorld(t, db)

	if err := a.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("control failed: the Service whose DEK the database is under was refused: %v", err)
	}
	fa := fingerprintOf(t, a)
	if v, found := epochValue(t, db); !found || v != fa {
		t.Fatalf("control failed: epoch = %q (found=%v), want A's fingerprint %q", v, found, fa)
	}

	err := b.StartDEKEpochGuard(db, nil)
	if v := kcWrongKeyDEKViolation(err); v != "" {
		t.Fatalf("%s", v)
	}
	if v, _ := epochValue(t, db); v != fa {
		t.Fatalf("refusing B changed the stored epoch to %q, want it to stay %q", v, fa)
	}
}

// The SQLite run: the same world, controls only (see the header).
func TestKeyCommitment_EpochGuard_SQLiteControls(t *testing.T) {
	db := fuzzworld.OpenSQLite(t, "file:"+filepath.Join(t.TempDir(), "kc.db"), 1)
	fuzzworld.Bootstrap(t, db)
	kcEpochWorld(t, db)
}

// TestKeyCommitment_EpochGuard_SQLite is the SQLite analogue of
// TestKeyCommitment_EpochGuard_Postgres (SQLITE-DEK-EPOCH-1, fuzz-corpus#195 /
// KEYCOMMIT-2 item 4): on SQLite, as on PostgreSQL, the Service whose DEK the
// database is under must start and seed the epoch, and a wrong-key DEK (the
// partition's second DEK) must be refused at boot with a wrapped
// ErrDEKEpochMismatch, leaving the stored epoch unchanged. No PostgreSQL DSN is
// needed — SQLite is the default backend — so this never SKIPs.
//
// RED on code without the SQLite boot guard: dekEpochApplies is false for
// SQLite, so StartDEKEpochGuard takes the record-protocol-only branch and
// returns nil for B → the oracle fires "WRONG-KEY DEK ACCEPTED".
func TestKeyCommitment_EpochGuard_SQLite(t *testing.T) {
	db := fuzzworld.OpenSQLite(t, "file:"+filepath.Join(t.TempDir(), "kc.db"), 1)
	fuzzworld.Bootstrap(t, db)
	a, b, _ := kcEpochWorld(t, db)

	// Positive control: the Service whose DEK the database's row is under must
	// start (and, with the fix, seed the epoch).
	if err := a.StartDEKEpochGuard(db, nil); err != nil {
		t.Fatalf("control failed: the Service whose DEK the database is under was refused: %v", err)
	}
	fa := fingerprintOf(t, a)

	// The wrong-key DEK must be refused at boot as a DEK epoch mismatch. On
	// current code (no SQLite guard) this returns nil and the oracle fires.
	err := b.StartDEKEpochGuard(db, nil)
	if v := kcWrongKeyDEKViolation(err); v != "" {
		t.Fatalf("%s", v)
	}

	// A seeded the epoch to its own fingerprint, and refusing B did not change it.
	if v, found := epochValue(t, db); !found || v != fa {
		t.Fatalf("epoch = %q (found=%v), want A's fingerprint %q (seeded by A, unchanged by refusing B)", v, found, fa)
	}

	// No watcher on single-node SQLite, and no handle kept.
	if a.DEKEpochGuardRunning() || b.DEKEpochGuardRunning() {
		t.Fatalf("a watcher started on SQLite (running a=%v b=%v); single-node SQLite must verify at boot only",
			a.DEKEpochGuardRunning(), b.DEKEpochGuardRunning())
	}
}

// TestKeyCommitment_EpochGuard_RedProof shows the oracle fires on a guard that lets
// the wrong-key DEK start and on one that refuses for another reason, and is quiet
// on the real refusal.
func TestKeyCommitment_EpochGuard_RedProof(t *testing.T) {
	for _, c := range []struct {
		name    string
		guarded error
		fires   bool
	}{
		{"planted guard that returns nil", nil, true},
		{"planted guard that fails for another reason", errors.New("read DEK epoch: connection refused"), true},
		{"real refusal (wrapped ErrDEKEpochMismatch)", errors.Join(ErrDEKEpochMismatch, errors.New("detail")), false},
	} {
		v := kcWrongKeyDEKViolation(c.guarded)
		t.Logf("%-46s fires=%v verdict=%q", c.name, v != "", v)
		if (v != "") != c.fires {
			t.Errorf("%s: oracle fired=%v, want %v", c.name, v != "", c.fires)
		}
	}
}

// TestKeyCommitment_EpochGuard_OrdinaryKeyFileWrongPassphrase: without the partition
// the wrong passphrase never gets as far as the epoch guard.
func TestKeyCommitment_EpochGuard_OrdinaryKeyFileWrongPassphrase(t *testing.T) {
	salt := kcSalt(t)
	dir := kcKeyDir(t, salt, nil)
	if err := os.Remove(filepath.Join(dir, "keys", "dek.key")); err != nil {
		t.Fatal(err)
	}
	a := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := a.Initialize(kcPassA); err != nil { // first boot generates and wraps a DEK
		t.Fatalf("control failed: first boot under passphrase A: %v", err)
	}
	a.Shutdown()
	b := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}, dir)
	if err := b.Initialize(kcPassB); err == nil {
		b.Shutdown()
		t.Fatal("an ordinary dek.key opened under the wrong passphrase")
	}
}
