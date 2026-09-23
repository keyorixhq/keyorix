//go:build !windows

package encryption

// fault_injected_operations_fuzz_test.go — FuzzFaultInjectedOperations.
//
// Crash-consistency fuzzing (the existing FuzzKEKRotationCrashConsistency /
// FuzzDEKRewrapCrashConsistency / FuzzDEKSweepCrashConsistency trilogy) models a
// process crash BETWEEN two fully-completed durability steps — the write, the
// rename, and the fsync each always run to completion; only the gap between them
// is interrupted. That leaves an uncovered fault class: the ENVIRONMENT failing
// WHILE the process keeps running — ENOSPC/EIO/a short write on the write itself,
// an fsync that reports failure after the data already landed, a SQL statement
// that never executes because the connection/transaction failed. This fuzzer
// targets exactly that class, reusing the trilogy's own recovery-model helpers
// (recoverDEK, recoverRewrap, tryOpen, tryOpenProvider) so the oracle logic for
// "is the DEK still recoverable and uncorrupted" is identical, not reimplemented.
//
// ── Fault model ──────────────────────────────────────────────────────────────
//
// One fuzz input drives ONE operation (of six, below) with ONE injected fault at
// ONE seam within it. Every seam in this catalog is called at most once per
// operation invocation, so "the Nth call to seam S" (STEP 2's stated schedule
// shape) is always N=1 here — there is no loop that calls the same seam twice
// within a single operation. This is a narrower scope than a multi-operation
// fault SEQUENCE would be; see the report accompanying this change for why that
// was the deliberate v1 cut. The fault (operation + seam + kind + byte count) is
// fully encoded in the fuzz input, so every failure reproduces from the corpus
// file alone, matching the multi-fault design's own reproducibility property.
//
// Three fault kinds (fileFaultKind, fault_hooks.go) apply to file seams:
//
//	faultCleanError:      zero bytes reach the real file / the rename never runs.
//	faultShortWrite:      the real file gets exactly K of the real bytes, no fsync.
//	faultRealEffectThenError: the real write/rename DOES happen, error reported anyway.
//
// SQL seams use a fourth, GORM-callback-based mechanism (armSQLFault) requiring
// no production code change at all — a Before-hook's AddError stops GORM's
// default Create/Delete callback chain before it issues the real statement,
// exactly as local_pat_expiry_test.go's existing BulkRevokeExpiredPATsByUser
// fault-injection test already does. Every SQL seam here is a "clean" fault
// (the statement either fully runs or does not — no equivalent of a short write
// at the SQL layer).
//
// ── Ambiguity classification (oracle a) ──────────────────────────────────────
//
// Directive: faults AT OR AFTER the commit/durability point must accept EITHER
// the pre- or post-change state (never a mix); faults BEFORE it must leave the
// model unchanged. Per seam type:
//
//	write seam, ANY kind          → deterministic OLD. Every write seam here
//	    targets a *.pending file; the function that calls it unconditionally
//	    aborts (returns the error without renaming) on ANY write failure — so a
//	    faultRealEffectThenError on a write seam populates the .pending file
//	    correctly but the ACTIVE file is untouched regardless. Given this, the
//	    fuzz decoder never selects faultRealEffectThenError for a write seam
//	    (see seamSpec.kinds below) — it would be a real capability of
//	    fault_hooks.go's applyWriteFault, just not an interesting one here.
//	rename seam, faultCleanError   → deterministic OLD (the rename never ran).
//	rename seam, faultRealEffectThenError → AMBIGUOUS: durableRename performs
//	    the real os.Rename and only returns the injected error if that real
//	    rename succeeded — so the active file IS the post-rename one, even
//	    though the function reports failure. The oracle accepts either via.
//	sync seam (rewrap:syncdir)    → the preceding rename has, by construction,
//	    ALREADY happened for real by the time this seam fires (durableSyncDir is
//	    only ever reached after a successful durableRename) — so any fault here
//	    is inherently post-commit; the oracle accepts either via but in
//	    practice will always observe the post-rename state.
//	SQL seam                       → deterministic OLD for every seam in this
//	    catalog: GORM's Before-hook AddError stops the INSERT/DELETE from ever
//	    running, and none of the six operations retries or partially commits
//	    around a single faulted statement (the multi-statement DELETE is wrapped
//	    in a real db.Transaction, which GORM rolls back whole on any error).
//
// ── Operations (6 of the original 7-item catalog; PAT deferred) ─────────────
//
// secret create / secret update (version rollover) / secret delete are driven at
// the storage+encryption layer directly (raw GORM model calls + Service.
// EncryptSecretWithAAD), NOT through internal/core — core already imports
// encryption, so encryption importing core to call KeyorixCore.CreateSecret
// would be a cycle. This mirrors the EXISTING FuzzDEKSweepCrashConsistency's own
// seeding code, which already creates secret rows this same way. The call
// sequence and transaction boundaries are copied from the real production code
// they model (internal/core/secrets.go CreateSecret/storeSecretVersion,
// internal/storage/store/local_secrets.go DeleteSecret) — CREATE'S two writes
// (node, then version) are genuinely NOT wrapped in one transaction in
// production (storeSecretVersion is a bare CreateSecretVersion call after a
// separate CreateSecret call), so this harness does not invent a stronger
// atomicity guarantee than production actually has for that operation; DELETE's
// three writes ARE wrapped in one real db.Transaction in production
// (LocalStorage.DeleteSecret), reproduced here identically.
//
// DEK rewrap / KEK rotation reuse the crash-consistency trilogy's own
// standalone-KeyManager harness style and recovery-model helpers directly
// (recoverDEK/recoverRewrap/tryOpen/tryOpenProvider, rewrapDEKFile/
// rewrapSaltOld/rewrapSaltNew) — no new recovery logic, only a new way to reach
// the same crash points (a real fault instead of a real crash).
//
// backup/export models core.ExportComplianceEvidence's file-durability
// primitive — a single securefiles.SecureWriteFileSync to a final path with NO
// separate rename (unlike the DEK/KEK operations) — without invoking
// core.ExportComplianceEvidence itself, for the same import-cycle reason as
// secret CRUD above. The oracle (directive 4) is specific to this no-rename
// shape: after a faulted export, the final path must have either no file, or a
// file byte-identical to the intended content (the ambiguous "it actually
// wrote through despite the reported error" case), or a file that fails to
// parse as JSON (a short/garbled write that would be visibly rejected by any
// consumer) — never a THIRD state: a truncated file that happens to still
// parse.
//
// PAT create/revoke is deferred per the approved scope (no durability path
// beyond the generic SQL layer already covered by secret create/update/delete —
// see the investigation report).
//
// ── After every faulted operation ────────────────────────────────────────────
//
// The harness runs the REAL production startup/recovery step for that
// operation's family before checking any oracle:
//   - DEK rewrap / KEK rotation: km.CleanPendingDEK() (production's own startup
//     cleanup for a leftover dek.key.pending). KEK rotation's kek.salt.pending
//     hazard window has no automated recovery in production at all — the
//     existing trilogy's own recoverDEK models the documented MANUAL operator
//     step, reused here unchanged, not reinvented.
//   - secret create/update/delete/backup: no key-material recovery applies (no
//     .pending file is involved); the oracle reads storage/disk state directly.
//
// Then oracles (b)-(e) are checked (oracle (a) atomicity is folded into each
// operation's own state check above, per the ambiguity classification).
//
// ── FIXED: kek:rename-dek's ambiguous fault ──────────────────────────────────
//
// kek:rename-dek's faultRealEffectThenError case WAS a confirmed, filed
// data-loss bug (commitNewKEKFiles' error-cleanup deleted kek.salt.pending
// even when the rename it was cleaning up after had actually succeeded) — see
// docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md
// for the reachability conditions (NFS/network-filesystem rename
// retransmission semantics, NOT a directory-fsync error — that WAS, at the
// time of that finding, a separate, disconnected, silently-discarded call in
// the same function; also since fixed — see "kek:syncdir-dek/-salt" below,
// both now checked seams, not a stale claim about current behavior) and the
// fix (dekRenameActuallySucceeded, keymanager_kek_rotation.go): on a
// rename-dek error, verify the actual on-disk DEK content before any
// cleanup; only clean up when the rename provably did not happen. This is
// now DETERMINISTIC, not ambiguous — see expectedKEKVia and
// runKEKRotateFaultCase's transparentRecovery handling. Red-proofed by
// reverting the fix (fuzzer fails again at this exact seam) and restoring it
// (green again); not committed as a permanent toggle.
//
// ── Known limitation: the hang-guard is not yet load-tolerant ───────────────
//
// faultOpGuardDeadline (30s) is a fixed wall-clock deadline, same as the
// crash-consistency trilogy's own per-target deadlines. Under real system
// contention (verified directly: a `-race` fuzz burst hit this deadline once
// on a 10-core/5-user shared machine with a 15-min load average of 10.66;
// re-running the SAME case in isolation immediately after passed in ~5.6s) a
// deadline trip is NOT on its own evidence of a hang in the code under test —
// it currently conflates "the operation is stuck" with "the machine is busy."
// Treat a rig timeout here as inconclusive, not as a finding, until a
// load-tolerant guard (e.g. adaptive to measured baseline latency, or a
// deadline-miss retry-once-in-isolation check) lands — tracked informally as
// "speed-fix-2," not yet a filed issue.
//
// ── v2 candidates (not implemented here) ─────────────────────────────────────
//
//   - Fault during RECOVERY itself: every case above injects one fault into the
//     original operation, then runs the REAL (unfaulted) recovery/startup step.
//     A second fault dimension — the recovery path itself failing (e.g.
//     CleanPendingDEK's os.Remove erroring, or a second crash during a manual
//     apply-pending-salt recovery) — is not modeled.
//   - A Postgres-gated regression test for the abort-after-constraint-violation
//     trap (CLAUDE.md's documented Postgres hazard: a caught violation that
//     returns nil is dead code there) — SQLite-only today; oracle (c)'s
//     fail-closed check is sound against SQLite, not yet demonstrated against
//     real Postgres transaction-abort semantics specifically.
//   - KMS-provider dependency-error/timeout faults for rewrap (rewrap here only
//     exercises the password-provider path). crypto.KMSClient is already an
//     interface with test fakes (internal/crypto/kms_provider_test.go), so this
//     needs no new production seam — just a fault-injecting fake wired through
//     crypto.NewKMSKeyProvider.
//   - The SAME verify-before-cleanup treatment for kek:rename-salt's own
//     ambiguous case (still genuinely ambiguous after this fix — see
//     expectedKEKVia) and, for defense-in-depth, RewrapDEK's rewrap:rename-dek
//     cleanup (not currently exploitable there — no second coupled file — but
//     the same discipline would prevent the bug class re-appearing if that
//     changes).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// faultOpGuardDeadline is a HANG backstop, matching the trilogy's own
// per-target deadlines (kekRotationGuardDeadline / rewrapGuardDeadline) rather
// than fuzzutil.Guard's shared 3s (tuned for fast file/parse targets). The
// rewrap/kek-rotate operations run real PBKDF2 KEK derivation, same as their
// crash-consistency counterparts.
const faultOpGuardDeadline = 30 * time.Second

// errInjectedFault is the sentinel error every fault kind returns, so a test
// failure message is unambiguous about its source.
var errInjectedFault = fmt.Errorf("fault-injected-operations: simulated environment failure (ENOSPC/EIO/short-write/SQL-fault)")

// ── seam catalog ──────────────────────────────────────────────────────────

type seamKind int

const (
	seamWrite    seamKind = iota // file write seam: faultCleanError or faultShortWrite
	seamRename                   // file rename seam: faultCleanError or faultRealEffectThenError
	seamSync                     // file sync seam: faultCleanError only (always post-commit)
	seamSQL                      // GORM callback seam: faultCleanError only
	seamCombined                 // two seams faulted simultaneously — see runKEKRotateFaultCase
)

type seamSpec struct {
	label string
	kind  seamKind
}

type opID int

const (
	opCreate opID = iota
	opUpdate
	opDelete
	opRewrap
	opKEKRotate
	opBackup
	numOps
)

var opSeams = map[opID][]seamSpec{
	opCreate:    {{"sql:create-node", seamSQL}, {"sql:create-version", seamSQL}},
	opUpdate:    {{"sql:update-version", seamSQL}},
	opDelete:    {{"sql:delete-node", seamSQL}, {"sql:delete-shares", seamSQL}, {"sql:delete-acls", seamSQL}},
	opRewrap:    {{"rewrap:write-dek-pending", seamWrite}, {"rewrap:rename-dek", seamRename}, {"rewrap:syncdir", seamSync}},
	opKEKRotate: {{"kek:write-salt-pending", seamWrite}, {"kek:write-dek-pending", seamWrite}, {"kek:rename-dek", seamRename}, {"kek:rename-salt", seamRename}, {"kek:syncdir-dek", seamSync}, {"kek:syncdir-salt", seamSync}, {"kek:rename-dek-verify-unknown", seamCombined}},
	opBackup:    {{"backup:write", seamWrite}},
}

// decodeFault picks the operation, seam, and fault kind from the fuzz-chosen
// selector bytes, and returns the concrete *fileFault (nil for a seamSQL seam,
// which uses armSQLFault instead).
func decodeFault(opSel, seamSel, kindSel, shortWriteK byte) (op opID, seam string, sk seamKind, ff *fileFault) {
	op = opID(int(opSel) % int(numOps))
	seams := opSeams[op]
	s := seams[int(seamSel)%len(seams)]

	switch s.kind {
	case seamSQL:
		return op, s.label, s.kind, nil
	case seamWrite:
		// faultRealEffectThenError is deliberately excluded here — see the
		// package doc comment's ambiguity classification: it is not
		// distinguishable from faultCleanError at the active-file level for a
		// write seam, so offering it would just be redundant fuzzing surface.
		if kindSel%2 == 0 {
			return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
		}
		return op, s.label, s.kind, &fileFault{kind: faultShortWrite, k: int(shortWriteK), err: errInjectedFault}
	case seamRename:
		// kek:rename-dek's faultRealEffectThenError combination WAS a confirmed
		// production bug (commitNewKEKFiles' error-cleanup on a rename-dek
		// failure unconditionally deleted kek.salt.pending, destroying the only
		// recovery path when the rename actually succeeded and merely reported
		// failure) — now fixed (classifyDEKRename, keymanager_kek_rotation.go);
		// see docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md
		// for the reachability analysis, reproduction, and fix description. This
		// case is deterministic post-fix — see expectedKEKVia and
		// runKEKRotateFaultCase's transparentRecovery handling.
		if kindSel%2 == 0 {
			return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
		}
		return op, s.label, s.kind, &fileFault{kind: faultRealEffectThenError, err: errInjectedFault}
	case seamSync:
		return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
	case seamCombined:
		// The returned *fileFault is unused for this seam — runKEKRotateFaultCase
		// special-cases s.label and arms its own pair of faults via
		// armMultiFileFault. See its doc comment.
		return op, s.label, s.kind, nil
	}
	return op, s.label, s.kind, &fileFault{kind: faultCleanError, err: errInjectedFault}
}

// armFileFault installs ff at seam via fileFaultHook and returns a restore func.
func armFileFault(seam string, ff *fileFault) (restore func()) {
	prev := fileFaultHook
	fileFaultHook = func(s string) *fileFault {
		if s == seam {
			return ff
		}
		return nil
	}
	return func() { fileFaultHook = prev }
}

// armMultiFileFault installs a distinct fault per seam simultaneously — used
// only by the combined rename-dek+verification-failure case below, where a
// single armFileFault can't express "two seams fail in the same call."
func armMultiFileFault(faults map[string]*fileFault) (restore func()) {
	prev := fileFaultHook
	fileFaultHook = func(s string) *fileFault {
		if f, ok := faults[s]; ok {
			return f
		}
		return nil
	}
	return func() { fileFaultHook = prev }
}

// armSQLFault registers a GORM Before-hook on db that fails the FIRST matching
// statement for seam, then never runs the real INSERT/DELETE for it — the same
// mechanism (and the same "gorm:before_create"/"gorm:before_delete" hook
// points) local_pat_expiry_test.go's existing
// TestLocalStorage_BulkRevokeExpiredPATsByUser_UpdateFails_ReturnsError uses.
// No production code is touched: GORM's Callback registry is a public API.
func armSQLFault(db *gorm.DB, seam string) (restore func()) {
	name := "fault:" + seam
	match := func(dest any, want string) bool {
		switch want {
		case "sql:create-node", "sql:delete-node":
			_, ok := dest.(*models.SecretNode)
			return ok
		case "sql:create-version", "sql:update-version":
			_, ok := dest.(*models.SecretVersion)
			return ok
		case "sql:delete-shares":
			_, ok := dest.(*models.ShareRecord)
			return ok
		case "sql:delete-acls":
			_, ok := dest.(*models.SecretACL)
			return ok
		}
		return false
	}
	switch seam {
	case "sql:create-node", "sql:create-version", "sql:update-version":
		_ = db.Callback().Create().Before("gorm:before_create").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Create().Remove(name) }
	case "sql:delete-node", "sql:delete-shares", "sql:delete-acls":
		_ = db.Callback().Delete().Before("gorm:before_delete").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Delete().Remove(name) }
	}
	return func() {}
}

// ── secret-CRUD world (create/update/delete/backup) ─────────────────────────

// secretWorldDBTables is the explicit, hand-named set of tables fuzzworld.World.Reset
// clears between fuzz iterations that reuse the same per-worker DB world (see World.Reset's
// doc for why this is a named list, not derived from the migrated model set).
// Dependent-first order: secret_versions/secret_acls/share_records before secret_nodes.
var secretWorldDBTables = []string{"secret_versions", "secret_acls", "share_records", "secret_nodes"}

// secretWorld is a cheap-static-KEK harness for the four operations that don't need a real
// password-derived KEK (their durability seams are the SQL layer or a plain file write, not
// KEK derivation) — mirrors FuzzDEKSweepCrashConsistency's own staticKEKProvider reasoning:
// the KDF is not what's under test here. Its DB comes from a per-worker fuzzworld.World (SQLite
// always, PostgreSQL too when KEYORIX_TEST_PG_DSN is set) reset fresh on every call to
// newSecretWorld — only the key/file directory (dir) is still allocated per call.
type secretWorld struct {
	t         *testing.T
	backend   string
	dir       string
	db        *gorm.DB
	svc       *Service
	seedNode  uint
	seedValue []byte
	canary    string
}

func newSecretWorld(t *testing.T, dbw *fuzzworld.World, canary string) *secretWorld {
	t.Helper()
	if err := dbw.Reset(secretWorldDBTables); err != nil {
		t.Fatalf("[%s] reset: %v", dbw.Backend, err)
	}
	db := dbw.DB
	dir := t.TempDir()

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	svc.keyManager.SetKeyProvider(staticKEKProvider{})
	if e := svc.Initialize("seed-passphrase"); e != nil {
		t.Fatalf("seed Initialize: %v", e)
	}

	seedVal := []byte("seed-value-" + canary)
	node := &models.SecretNode{ProjectID: 1, Name: "seed", IsSecret: true}
	if e := db.Create(node).Error; e != nil {
		t.Fatalf("[%s] seed node: %v", dbw.Backend, e)
	}
	aad := SecretAAD(node.ID, 1, 1)
	enc, meta, e := svc.EncryptSecretWithAAD(seedVal, aad)
	if e != nil {
		t.Fatalf("seed encrypt: %v", e)
	}
	if e := db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; e != nil {
		t.Fatalf("[%s] seed version: %v", dbw.Backend, e)
	}
	return &secretWorld{t: t, backend: dbw.Backend, dir: dir, db: db, svc: svc, seedNode: node.ID, seedValue: seedVal, canary: canary}
}

// decryptLatest returns the decrypted plaintext of the latest version row for
// nodeID, or ok=false if none exists / decryption fails.
func (w *secretWorld) decryptLatest(nodeID uint) (plaintext []byte, versionNumber int, ok bool) {
	var v models.SecretVersion
	if e := w.db.Where("secret_node_id = ?", nodeID).Order("version_number DESC").First(&v).Error; e != nil {
		return nil, 0, false
	}
	aad := SecretAAD(nodeID, 1, v.VersionNumber)
	pt, e := w.svc.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if e != nil {
		return nil, 0, false
	}
	return pt, v.VersionNumber, true
}

func (w *secretWorld) nodeExists(nodeID uint) bool {
	var n models.SecretNode
	return w.db.First(&n, nodeID).Error == nil
}

// ── plaintext-spill scan (oracle d) ──────────────────────────────────────────

// scanForPlaintext walks every regular file under root and returns the paths
// of any that contain canary verbatim — the DB is in-memory, so this only
// needs to cover the key-directory / backup-directory files, but walks
// everything under root defensively.
func scanForPlaintext(root string, canary []byte) []string {
	var hits []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- test-only scan of a harness temp dir
		if rerr != nil {
			return nil
		}
		if bytes.Contains(data, canary) {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

// ── the fuzz target ───────────────────────────────────────────────────────

func FuzzFaultInjectedOperations(f *testing.F) {
	// Built ONCE per testing.F, before f.Fuzz (internal/testutil/fuzzworld) — reopening and
	// migrating a DB per iteration was the dominant per-input cost.
	// SQLite always; PostgreSQL too when KEYORIX_TEST_PG_DSN is set. Only
	// opCreate/opUpdate/opDelete/opBackup (via newSecretWorld) touch this DB at all —
	// opRewrap/opKEKRotate never receive it (see runFaultInjectedCase below); they are pure
	// file/PBKDF2 operations with zero database interaction, so they run once, not once per
	// world.
	dbWorlds := fuzzworld.Worlds(f, "faultopsfuzz", ":memory:", 0) // full production schema (#1947)

	// Seed one case per (operation, seam, kind) combination decodeFault can
	// produce, including kek:rename-dek's ambiguous kind — see decodeFault's
	// comment: that case is deterministic post-fix (transparent recovery), not
	// a tolerated finding anymore.
	for opSel := 0; opSel < int(numOps); opSel++ {
		seams := opSeams[opID(opSel)]
		for seamSel := range seams {
			for kindSel := 0; kindSel < 2; kindSel++ {
				f.Add(byte(opSel), byte(seamSel), byte(kindSel), byte(3), "old-pass", "new-pass", "secret-val")
			}
		}
	}
	f.Add(byte(0), byte(0), byte(0), byte(0), "", "", "")

	f.Fuzz(func(t *testing.T, opSel, seamSel, kindSel, shortWriteK byte, oldPassIn, newPassIn, secretVal string) {
		// Prefixed, never just the raw fuzzed string: oracle (e) below checks
		// these passphrases for leakage via strings.Contains against error text
		// that legitimately contains vocabulary like "ENOSPC" — a short or
		// single-character fuzzed passphrase (e.g. "C") coincidentally collides
		// with that vocabulary and false-positives the leak check on pure
		// chance, not an actual leak (confirmed via a -race fuzz run: oldPass=
		// newPass="C" tripped "ERROR HYGIENE" purely because "ENOSPC" contains a
		// "C"). A long, distinctive prefix makes coincidental substring
		// collision with ordinary error vocabulary vanishingly unlikely while
		// still varying meaningfully with the fuzzer's chosen suffix.
		oldPass := "PASSCANARY-old-" + oldPassIn
		newPass := "PASSCANARY-new-" + newPassIn
		canary := "FAULTCANARY-" + secretVal

		done := make(chan struct{})
		go func() {
			defer close(done)
			runFaultInjectedCase(t, dbWorlds, opSel, seamSel, kindSel, shortWriteK, oldPass, newPass, canary)
		}()
		select {
		case <-done:
		case <-time.After(faultOpGuardDeadline):
			t.Fatalf("fault-injected-operations exceeded %s — possible hang", faultOpGuardDeadline)
		}
	})
}

func runFaultInjectedCase(t *testing.T, dbWorlds []*fuzzworld.World, opSel, seamSel, kindSel, shortWriteK byte, oldPass, newPass, canary string) {
	op, seam, sk, ff := decodeFault(opSel, seamSel, kindSel, shortWriteK)

	switch op {
	case opCreate, opUpdate, opDelete, opBackup:
		for _, dbw := range dbWorlds {
			runSecretWorldCase(t, dbw, op, seam, sk, ff, canary)
		}
	case opRewrap:
		runRewrapFaultCase(t, seam, ff, oldPass, newPass)
	case opKEKRotate:
		runKEKRotateFaultCase(t, seam, ff, oldPass, newPass)
	}
}

// ── create / update / delete / backup ────────────────────────────────────

func runSecretWorldCase(t *testing.T, dbw *fuzzworld.World, op opID, seam string, sk seamKind, ff *fileFault, canary string) {
	w := newSecretWorld(t, dbw, canary)

	var restore func()
	switch sk {
	case seamSQL:
		restore = armSQLFault(w.db, seam)
	default:
		restore = armFileFault(seam, ff)
	}

	var callErr error
	var newNodeID uint
	var backupPath string
	var backupWant []byte

	switch op {
	case opCreate:
		val := []byte(canary)
		node := &models.SecretNode{ProjectID: 1, Name: "created", IsSecret: true}
		if e := w.db.Create(node).Error; e != nil {
			callErr = e
		} else {
			newNodeID = node.ID
			aad := SecretAAD(node.ID, 1, 1)
			enc, meta, eerr := w.svc.EncryptSecretWithAAD(val, aad)
			if eerr != nil {
				callErr = eerr
			} else if e := w.db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error; e != nil {
				callErr = e
			}
		}
	case opUpdate:
		val := []byte(canary)
		aad := SecretAAD(w.seedNode, 1, 2)
		enc, meta, eerr := w.svc.EncryptSecretWithAAD(val, aad)
		if eerr != nil {
			callErr = eerr
		} else {
			callErr = w.db.Create(&models.SecretVersion{SecretNodeID: w.seedNode, VersionNumber: 2, EncryptedValue: enc, EncryptionMetadata: models.JSON(meta)}).Error
		}
	case opDelete:
		callErr = w.db.Transaction(func(tx *gorm.DB) error {
			res := tx.Delete(&models.SecretNode{}, w.seedNode)
			if res.Error != nil {
				return res.Error
			}
			if e := tx.Where("secret_id = ?", w.seedNode).Delete(&models.ShareRecord{}).Error; e != nil {
				return e
			}
			return tx.Where("secret_id = ?", w.seedNode).Delete(&models.SecretACL{}).Error
		})
	case opBackup:
		// "note" is deliberately NOT the canary: this evidence-pack payload is
		// non-secret metadata by design (core.ExportComplianceEvidence's real
		// export is a plaintext JSON compliance record, never a secret VALUE),
		// so it legitimately belongs in plaintext on disk. Embedding the canary
		// here would make oracle (d)'s plaintext-spill scan below fire on the
		// backup's own intended content — a harness false positive, not a
		// finding (confirmed via a 90s -fuzz burst during verification).
		payload := map[string]any{"generated_at": "2026-09-19T00:00:00Z", "note": "fault-injected-operations-backup-marker", "campaigns": []any{}}
		data, merr := json.MarshalIndent(payload, "", "  ")
		if merr != nil {
			t.Fatalf("marshal backup payload: %v", merr)
		}
		// A dedicated subdir, distinct from w.dir (which holds dek.key/kek.salt) —
		// core.ExportComplianceEvidence's real outputDir is likewise never the key
		// directory, and checkBackupOracle's "no stray file" check would otherwise
		// misreport the key files themselves as unexpected leftovers.
		backupDir := filepath.Join(w.dir, "backup-out")
		if e := os.MkdirAll(backupDir, 0o700); e != nil {
			t.Fatalf("mkdir backup dir: %v", e)
		}
		name := "keyorix-evidence-fault-test.json"
		backupPath = filepath.Join(backupDir, name)
		backupWant = data
		callErr = durableWriteSync(backupDir, name, data, 0o600, seam)
	}
	restore()

	// oracle (c): a faulted operation must report failure, never silent success.
	if callErr == nil {
		t.Fatalf("HARNESS/oracle-c: op=%v seam=%q fault did not fire — the operation returned nil error", op, seam)
	}
	// oracle (e): the error must not leak the plaintext canary.
	if strings.Contains(callErr.Error(), canary) {
		t.Fatalf("ERROR HYGIENE: op=%v seam=%q error leaks plaintext canary: %v", op, seam, callErr)
	}

	switch op {
	case opCreate:
		checkCreateOracle(t, w, seam, newNodeID)
	case opUpdate:
		checkUpdateOracle(t, w)
	case opDelete:
		checkDeleteOracle(t, w)
	case opBackup:
		checkBackupOracle(t, backupPath, backupWant)
	}

	// oracle (d): no plaintext spill anywhere under the harness's own dirs.
	if hits := scanForPlaintext(w.dir, []byte(canary)); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: op=%v seam=%q canary found in: %v", op, seam, hits)
	}
}

func checkCreateOracle(t *testing.T, w *secretWorld, seam string, newNodeID uint) {
	switch seam {
	case "sql:create-node":
		var count int64
		w.db.Model(&models.SecretNode{}).Where("name = ?", "created").Count(&count)
		if count != 0 {
			t.Fatalf("ATOMICITY: sql:create-node fault fired but a node row exists anyway")
		}
	case "sql:create-version":
		if !w.nodeExists(newNodeID) {
			t.Fatalf("ATOMICITY: sql:create-version fault also lost the already-committed node row (id=%d)", newNodeID)
		}
		var vcount int64
		w.db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", newNodeID).Count(&vcount)
		if vcount != 0 {
			t.Fatalf("FAIL-CLOSED VIOLATION: sql:create-version fault fired but a version row exists anyway — the injected fault did not actually prevent the write")
		}
	}
}

func checkUpdateOracle(t *testing.T, w *secretWorld) {
	pt, ver, ok := w.decryptLatest(w.seedNode)
	if !ok {
		t.Fatalf("DATA LOSS: sql:update-version fault also made the seed version unreadable")
	}
	if ver != 1 {
		t.Fatalf("ATOMICITY: sql:update-version fault fired but the latest version is v%d, not the original v1", ver)
	}
	if !bytes.Equal(pt, w.seedValue) {
		t.Fatalf("DATA CORRUPTION: sql:update-version fault fired but the seed version's plaintext changed: got %q want %q", pt, w.seedValue)
	}
}

func checkDeleteOracle(t *testing.T, w *secretWorld) {
	if !w.nodeExists(w.seedNode) {
		t.Fatalf("ATOMICITY: a faulted delete step still removed the secret node — the wrapping transaction did not roll back")
	}
	pt, ver, ok := w.decryptLatest(w.seedNode)
	if !ok {
		t.Fatalf("DATA LOSS: a faulted delete left the node but its version is unreadable")
	}
	if ver != 1 || !bytes.Equal(pt, w.seedValue) {
		t.Fatalf("DATA CORRUPTION: a faulted delete left the seed version altered: v%d %q want v1 %q", ver, pt, w.seedValue)
	}
}

func checkBackupOracle(t *testing.T, path string, wantData []byte) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed harness temp-dir path
	if os.IsNotExist(err) {
		return // no file at the final path — acceptable
	}
	if err != nil {
		t.Fatalf("BACKUP: unexpected stat error on final path: %v", err)
	}
	if bytes.Equal(data, wantData) {
		return // the write actually completed durably despite the injected error
	}
	if json.Valid(data) {
		t.Fatalf("BACKUP CORRUPTION: a non-matching file at the final path parses as valid JSON — a restore step would silently accept truncated/garbled data: %q", data)
	}
	// invalid JSON — a restore step would reject it. Acceptable.

	dir := filepath.Dir(path)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Fatalf("BACKUP: unexpected stray file left in backup dir: %s", e.Name())
		}
	}
}

// ── DEK rewrap ────────────────────────────────────────────────────────────

func runRewrapFaultCase(t *testing.T, seam string, ff *fileFault, oldPass, newPass string) {
	dir := t.TempDir()
	kmSeed := NewKeyManager(dir, rewrapDEKFile, rewrapSaltOld)
	kmSeed.SetKeyProvider(crypto.NewPasswordKeyProvider(oldPass, dir, rewrapSaltOld))
	if err := kmSeed.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(old=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), kmSeed.GetDEK()...)
	newProvider := crypto.NewPasswordKeyProvider(newPass, dir, rewrapSaltNew)

	restore := armFileFault(seam, ff)
	err := kmSeed.RewrapDEK(newProvider)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: rewrap seam=%q fault did not fire — RewrapDEK returned nil error", seam)
	}
	if strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass) {
		t.Fatalf("ERROR HYGIENE: rewrap seam=%q error leaks a passphrase: %v", seam, err)
	}

	// Real production startup step: clean a leftover dek.key.pending.
	kmSeed.CleanPendingDEK()

	rec, via, ok := recoverRewrap(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no provider recovers the DEK after rewrap fault %q", seam)
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after rewrap fault %q via %s: recovered key != original", seam, via)
	}

	// Ambiguity classification (see package doc comment): rewrap:syncdir is
	// always post-rename by construction (durableSyncDir only fires after a
	// real durableRename already succeeded), so it always expects "new-provider"
	// regardless of kind; a write-seam or clean rename-seam fault on the other
	// two seams must leave the OLD provider still valid — the operation must not
	// have silently gone through despite reporting failure.
	want, skip := expectedRewrapVia(seam, ff)
	if !skip && !containsString(want, via) {
		t.Fatalf("FAIL-CLOSED VIOLATION: rewrap fault %q (kind=%v) reported failure but the active DEK recovered via %q, want one of %v — the state moved despite the reported error", seam, ff.kind, via, want)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: rewrap fault %q left the raw DEK bytes on disk outside key files: %v", seam, hits)
	}
}

// expectedRewrapVia returns the recoverRewrap "via" value(s) a DETERMINISTIC
// (non-ambiguous) fault at seam must produce, or skip=true when the fault is
// the AMBIGUOUS faultRealEffectThenError kind (only availability/integrity are
// checked then — see the package doc comment's ambiguity classification).
// rewrap:syncdir is always post-rename by construction, so it expects
// "new-provider" unconditionally rather than following the kind-based rule.
func expectedRewrapVia(seam string, ff *fileFault) (want []string, skip bool) {
	if seam == "rewrap:syncdir" {
		return []string{"new-provider"}, false
	}
	if ff.kind == faultRealEffectThenError {
		return nil, true
	}
	return []string{"old-provider"}, false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ── KEK rotation ──────────────────────────────────────────────────────────

// kekRenameDekVerifyUnknownSeam is the combined-fault seam label: rename-dek
// applies for real but reports an error (faultRealEffectThenError) AND the
// classifyDEKRename verification that would otherwise detect that gets its
// own simulated stat/read failure — the exact "same blip disrupts both"
// scenario the tri-state fix (classifyDEKRename returning dekRenameUnknown)
// exists to fail safe against. Handled entirely separately from the generic
// single-fault seams below: ff is unused (always nil, see decodeFault) since
// this needs two simultaneous faults, not one.
const kekRenameDekVerifyUnknownSeam = "kek:rename-dek-verify-unknown"

func runKEKRotateFaultCase(t *testing.T, seam string, ff *fileFault, oldPass, newPass string) {
	if seam == kekRenameDekVerifyUnknownSeam {
		runKEKRotateCombinedVerifyUnknownCase(t, oldPass, newPass)
		return
	}
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(oldPass=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), km.GetDEK()...)

	restore := armFileFault(seam, ff)
	err := km.RotateKEKPassphrase(oldPass, newPass)
	restore()

	// FIXED behavior (docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md):
	// kek:rename-dek's ambiguous fault (the rename actually applied despite the
	// reported error) is now transparently absorbed by dekRenameActuallySucceeded
	// — commitNewKEKFiles falls through and completes the rotation normally, so
	// RotateKEKPassphrase returns nil here. This is the intended, fixed outcome,
	// not a gap: every other (seam, kind) combination must still report an error.
	transparentRecovery := seam == "kek:rename-dek" && ff.kind == faultRealEffectThenError
	switch {
	case transparentRecovery && err != nil:
		t.Fatalf("REGRESSION: kek-rotate fault %q (kind=%v) should be transparently absorbed by the verify-before-cleanup fix (RotateKEKPassphrase should return nil), but got: %v", seam, ff.kind, err)
	case !transparentRecovery && err == nil:
		t.Fatalf("HARNESS/oracle-c: kek-rotate seam=%q fault did not fire — RotateKEKPassphrase returned nil error", seam)
	}
	if err != nil && (strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass)) {
		t.Fatalf("ERROR HYGIENE: kek-rotate seam=%q error leaks a passphrase: %v", seam, err)
	}

	// Real production startup step: clean a leftover dek.key.pending. Note (per
	// the package doc comment): kek.salt.pending has NO automated startup
	// recovery in production — recoverDEK below models the documented manual
	// operator step, unchanged from the existing crash-consistency fuzzer.
	km.CleanPendingDEK()

	rec, via, ok := recoverDEK(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no recovery yields the DEK after kek-rotate fault %q (kind=%v)", seam, ff.kind)
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after kek-rotate fault %q via %s: recovered key != original", seam, via)
	}

	want, skip := expectedKEKVia(seam, ff)
	if !skip && !containsString(want, via) {
		t.Fatalf("FAIL-CLOSED VIOLATION: kek-rotate fault %q (kind=%v) reported failure but recovery went via %q, want one of %v — the state moved despite the reported error", seam, ff.kind, via, want)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: kek-rotate fault %q left the raw DEK bytes on disk outside key files: %v", seam, hits)
	}
}

// runKEKRotateCombinedVerifyUnknownCase drives the combined rename-dek
// fault: the rename applies for real but reports an error, AND the
// verification that would otherwise detect that (classifyDEKRename) gets its
// own simulated failure — dekRenameUnknown, not dekRenameNotApplied. Asserts
// the fail-safe direction directly: no .pending material is removed (the
// concrete fail-open-under-uncertainty gap this case exists to catch — a
// prior version of the fix treated ANY verification failure as "not
// applied," which still permitted deleting kek.salt.pending here) and the
// DEK remains fully recoverable regardless.
func runKEKRotateCombinedVerifyUnknownCase(t *testing.T, oldPass, newPass string) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(oldPass); err != nil {
		t.Fatalf("seed Initialize(oldPass=%q): %v", oldPass, err)
	}
	dek0 := append([]byte(nil), km.GetDEK()...)

	restore := armMultiFileFault(map[string]*fileFault{
		"kek:rename-dek":        {kind: faultRealEffectThenError, err: errInjectedFault},
		"kek:verify-rename-dek": {kind: faultCleanError, err: errInjectedFault},
	})
	err := km.RotateKEKPassphrase(oldPass, newPass)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: kek-rotate seam=%q fault did not fire — RotateKEKPassphrase returned nil error", kekRenameDekVerifyUnknownSeam)
	}
	if strings.Contains(err.Error(), oldPass) || strings.Contains(err.Error(), newPass) {
		t.Fatalf("ERROR HYGIENE: kek-rotate seam=%q error leaks a passphrase: %v", kekRenameDekVerifyUnknownSeam, err)
	}

	// The core assertion: kek.salt.pending must survive an UNKNOWN outcome —
	// deleting it here, on mere uncertainty, is exactly the fail-open gap
	// this case exists to catch.
	if _, statErr := os.Stat(filepath.Join(dir, "kek.salt.pending")); statErr != nil {
		t.Fatalf("FAIL-SAFE VIOLATION: kek.salt.pending was removed despite an UNKNOWN rename-dek outcome (the rename applied for real, but its verification ALSO failed) — this is exactly the fail-open-under-uncertainty gap the tri-state classification exists to close: %v", statErr)
	}

	km.CleanPendingDEK()

	rec, via, ok := recoverDEK(dir, oldPass, newPass)
	if !ok {
		t.Fatalf("DATA LOSS: no recovery yields the DEK after the combined rename-dek+verification-failure fault")
	}
	if !bytes.Equal(rec, dek0) {
		t.Fatalf("DEK CORRUPTION after the combined fault via %s: recovered key != original", via)
	}
	// via is expected to be the hazard-window recovery (apply-pending-salt+*),
	// since the rotation stopped at the Unknown branch without attempting the
	// salt rename — same deterministic state as kek:rename-salt's own case.
	if via != "apply-pending-salt+new-passphrase" && via != "apply-pending-salt+old-passphrase" {
		t.Fatalf("unexpected recovery path after the combined fault: via=%q, want apply-pending-salt+*", via)
	}

	if hits := scanForPlaintext(dir, dek0); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: combined rename-dek+verification-failure fault left the raw DEK bytes on disk outside key files: %v", hits)
	}
}

// expectedKEKVia returns the recoverDEK "via" value(s) a DETERMINISTIC fault
// at seam must produce. "old-passphrase" covers every seam before the DEK
// rename commits (nothing has moved yet); "apply-pending-salt+*" is the
// expected recovery for a deterministic fault at kek:rename-salt, because by
// the time that seam runs, kek:rename-dek has ALREADY unconditionally
// succeeded for real — the correct "unchanged" state for THIS seam is the
// hazard window (dek.key new, kek.salt old, kek.salt.pending still present),
// not plain old-passphrase.
//
// kek:rename-dek's ambiguous (faultRealEffectThenError) case is no longer
// ambiguous after the verify-before-cleanup fix: it is now DETERMINISTIC and
// expects "new-passphrase" (the rotation completes fully, transparently —
// see runKEKRotateFaultCase's transparentRecovery handling). kek:rename-salt's
// ambiguous case remains genuinely ambiguous (skip=true) — no equivalent
// verify-before-cleanup fix exists for it in this commit; a fault there can
// still leave either the hazard window or a fully-completed rotation.
//
// kek:syncdir-dek/-salt (seamSync, always faultCleanError — see decodeFault)
// are DETERMINISTIC, matching the rename step immediately preceding each:
// syncdir-dek fires right after the DEK rename already succeeded for real but
// before the salt rename is attempted (the fix now returns an error there
// instead of proceeding), so the state is the same hazard window
// kek:rename-salt's own deterministic case reaches; syncdir-salt fires after
// BOTH renames already succeeded for real, so the rotation is already fully
// applied on disk regardless of this last fsync's outcome.
func expectedKEKVia(seam string, ff *fileFault) (want []string, skip bool) {
	if seam == "kek:rename-dek" && ff.kind == faultRealEffectThenError {
		return []string{"new-passphrase"}, false
	}
	if ff.kind == faultRealEffectThenError {
		return nil, true
	}
	switch seam {
	case "kek:write-salt-pending", "kek:write-dek-pending", "kek:rename-dek":
		return []string{"old-passphrase"}, false
	case "kek:rename-salt", "kek:syncdir-dek":
		return []string{"apply-pending-salt+new-passphrase", "apply-pending-salt+old-passphrase"}, false
	case "kek:syncdir-salt":
		return []string{"new-passphrase", "old-passphrase"}, false
	}
	return nil, true
}
