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
	"sync"
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
	// opInit, opUpgradeAAD, opMigrateAuthData added for the admin-CLI encryption
	// family's remaining uncovered ops (`encryption init`, `encryption
	// upgrade-aad`, `encryption auth-encryption migrate` — see this file's
	// header comment's "PR A scope" section for what's covered here vs. why
	// fix-perms/migrate-provider's rewrap step/auth-encryption
	// enable+rotate are NOT new seams).
	opInit
	opUpgradeAAD
	opMigrateAuthData
	numOps
)

var opSeams = map[opID][]seamSpec{
	opCreate:    {{"sql:create-node", seamSQL}, {"sql:create-version", seamSQL}},
	opUpdate:    {{"sql:update-version", seamSQL}},
	opDelete:    {{"sql:delete-node", seamSQL}, {"sql:delete-shares", seamSQL}, {"sql:delete-acls", seamSQL}},
	opRewrap:    {{"rewrap:write-dek-pending", seamWrite}, {"rewrap:rename-dek", seamRename}, {"rewrap:syncdir", seamSync}},
	opKEKRotate: {{"kek:write-salt-pending", seamWrite}, {"kek:write-dek-pending", seamWrite}, {"kek:rename-dek", seamRename}, {"kek:rename-salt", seamRename}, {"kek:syncdir-dek", seamSync}, {"kek:syncdir-salt", seamSync}, {"kek:rename-dek-verify-unknown", seamCombined}},
	opBackup:    {{"backup:write", seamWrite}},
	// init:* seams are `KeyManager.Initialize`'s FIRST-RUN key-generation path
	// (ensureSaltExists/ensureWrappedDEKExists, keymanager_lifecycle.go) — NOT
	// wired through fileFaultHook at all before this PR, and found (via this
	// exact opInit case) to write DIRECTLY to the final salt/DEK path with no
	// pending+rename stage, meaning a short write left a CORRUPTED active file
	// that permanently blocked every future Initialize ("re-run does not
	// converge" — the finding this PR's directive was written to catch).
	// Fixed alongside adding this coverage: both now use the same
	// write-pending/rename/syncdir shape as commitNewKEKFiles (KEK rotation).
	// See runInitFaultCase's "re-run converges" check, which is what actually
	// caught this before the fix and confirms it after.
	opInit: {
		{"init:write-salt-pending", seamWrite}, {"init:rename-salt", seamRename}, {"init:syncdir-salt", seamSync},
		{"init:write-dek-pending", seamWrite}, {"init:rename-dek", seamRename}, {"init:syncdir-dek", seamSync},
	},
	// sql:upgrade-aad-* are Service.UpgradeAuthAAD's three per-table sweeps
	// (sweepMFASecrets/sweepDynamicSecretConfigs/sweepDynamicSecretLeases,
	// sweep_auth.go), all inside the ONE transaction UpgradeAuthAAD itself
	// owns — a fault at any one seam rolls back all three tables together,
	// not just the table the fault targeted. Called directly (Service is in
	// this same package) rather than replicated, unlike opRewrap/opKEKRotate.
	opUpgradeAAD: {{"sql:upgrade-aad-mfa", seamSQL}, {"sql:upgrade-aad-dynconfig", seamSQL}, {"sql:upgrade-aad-dynlease", seamSQL}},
	// sql:migrate-password-reset is `encryption auth-encryption migrate`'s
	// per-row update (MigratePasswordResetTokens, internal/encryptionops) —
	// replicated here (not called directly: encryptionops imports encryption,
	// so a direct call would be an import cycle from this package's test),
	// matching the SAME single-row, single-UPDATE-statement shape as the real
	// code (see runAuthWorldCase's migratePasswordResetTokenForFuzz).
	opMigrateAuthData: {{"sql:migrate-password-reset", seamSQL}},
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
			recordSeamHit(seam)
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
			recordSeamHit(s)
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
	// matchUpdate checks Statement.MODEL, not Statement.Dest: every seam here
	// is a `.Model(x).Updates(map[string]interface{}{...})` call (sweep_auth.go
	// / migratePasswordResetTokenForFuzz below), and for that call shape GORM
	// sets Statement.Dest to the map argument itself (useless for a type
	// switch) while Statement.Model carries the typed pointer passed to
	// .Model(). Registered on a SEPARATE callback chain (Update, not
	// Create/Delete) from match/matchCreateOrDelete above.
	matchUpdate := func(model any, want string) bool {
		switch want {
		case "sql:upgrade-aad-mfa":
			_, ok := model.(*models.MFASecret)
			return ok
		case "sql:upgrade-aad-dynconfig":
			_, ok := model.(*models.DynamicSecretConfig)
			return ok
		case "sql:upgrade-aad-dynlease":
			_, ok := model.(*models.DynamicSecretLease)
			return ok
		case "sql:migrate-password-reset":
			_, ok := model.(*models.PasswordReset)
			return ok
		}
		return false
	}
	switch seam {
	case "sql:create-node", "sql:create-version", "sql:update-version":
		_ = db.Callback().Create().Before("gorm:before_create").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				recordSeamHit(seam)
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Create().Remove(name) }
	case "sql:delete-node", "sql:delete-shares", "sql:delete-acls":
		_ = db.Callback().Delete().Before("gorm:before_delete").Register(name, func(d *gorm.DB) {
			if match(d.Statement.Dest, seam) {
				recordSeamHit(seam)
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Delete().Remove(name) }
	case "sql:upgrade-aad-mfa", "sql:upgrade-aad-dynconfig", "sql:upgrade-aad-dynlease", "sql:migrate-password-reset":
		_ = db.Callback().Update().Before("gorm:before_update").Register(name, func(d *gorm.DB) {
			if matchUpdate(d.Statement.Model, seam) {
				recordSeamHit(seam)
				_ = d.AddError(errInjectedFault)
			}
		})
		return func() { _ = db.Callback().Update().Remove(name) }
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
	// a tolerated finding anymore. Shared with
	// TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam below, which
	// replays this EXACT set outside `go test -fuzz` and asserts every
	// declared (op, seam) pair was actually reached — not just that
	// decodeFault's arithmetic selects it, matching PR #2047's lesson that a
	// seed can look like it covers something it never actually reaches.
	for _, s := range allFaultInjectedSeedTriples() {
		f.Add(s.opSel, s.seamSel, s.kindSel, byte(3), "old-pass", "new-pass", "secret-val")
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
	case opInit:
		runInitFaultCase(t, seam, ff, oldPass)
	case opUpgradeAAD, opMigrateAuthData:
		for _, dbw := range dbWorlds {
			runAuthWorldCase(t, dbw, op, seam, sk, canary)
		}
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

// ── init (first-run key generation) ──────────────────────────────────────

// runInitFaultCase drives KeyManager.Initialize's FIRST-RUN key-generation
// path on a completely fresh directory (no existing salt.dat/dek.key) —
// genuinely distinct from every other case in this catalog. init:write-salt
// and init:write-dek write DIRECTLY to the real, final path
// (securefiles.SecureWriteFileSync has no .pending+rename stage of its own),
// so unlike a rotation seam, a short write here can leave a CORRUPTED file at
// the path every future Initialize call on this directory will try to load —
// not an inert .pending file nobody reads until a rename commits it.
//
// The core check is "re-run converges" (this PR's explicit directive): after
// a faulted first-run Initialize, a SECOND, fresh KeyManager against the SAME
// (possibly now-corrupted) directory, with the SAME passphrase, must be able
// to complete Initialize successfully and yield a working 32-byte DEK — not
// stay permanently stuck on a leftover corrupted file requiring manual
// operator cleanup.
func runInitFaultCase(t *testing.T, seam string, ff *fileFault, pass string) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")

	restore := armFileFault(seam, ff)
	err := km.Initialize(pass)
	restore()

	if err == nil {
		t.Fatalf("HARNESS/oracle-c: init seam=%q fault did not fire — Initialize returned nil error", seam)
	}
	if strings.Contains(err.Error(), pass) {
		t.Fatalf("ERROR HYGIENE: init seam=%q error leaks the passphrase: %v", seam, err)
	}

	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	if err2 := km2.Initialize(pass); err2 != nil {
		t.Fatalf("RE-RUN DOES NOT CONVERGE: init seam=%q (kind=%v) left the key directory permanently broken — a second Initialize (same passphrase, same dir) failed: %v (first attempt's error: %v)", seam, ff.kind, err2, err)
	}
	dek := km2.GetDEK()
	if len(dek) != 32 {
		t.Fatalf("init seam=%q: the converged Initialize produced a DEK of length %d, want 32", seam, len(dek))
	}

	if hits := scanForPlaintext(dir, dek); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: init seam=%q left the raw DEK bytes on disk outside key files: %v", seam, hits)
	}
}

// ── upgrade-aad / auth-encryption migrate ────────────────────────────────

// authWorldDBTables mirrors secretWorldDBTables for the four tables
// opUpgradeAAD/opMigrateAuthData touch.
var authWorldDBTables = []string{"mfa_secrets", "dynamic_secret_configs", "dynamic_secret_leases", "password_resets"}

// authWorld seeds one row in each of the four tables opUpgradeAAD/
// opMigrateAuthData read, all encrypted under the SAME real (cheap, static-
// KEK) Service — mirroring secretWorld's own reasoning. The seed plaintext/
// ciphertext pairs are retained so each oracle can independently re-derive
// "was this row actually left unchanged" without re-deriving sweep_auth.go's
// own logic.
type authWorld struct {
	t       *testing.T
	backend string
	dir     string
	db      *gorm.DB
	svc     *Service

	mfaID        uint
	mfaSeedEnc   []byte
	dynConfigID  uint
	dynConfigEnc []byte
	dynLeaseID   string
	dynLeaseEnc  []byte
	pwResetID    uint
	pwResetToken string
}

func newAuthWorld(t *testing.T, dbw *fuzzworld.World, canary string) *authWorld {
	t.Helper()
	if err := dbw.Reset(authWorldDBTables); err != nil {
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
	keyVersion := svc.GetKeyVersion()
	esvc := svc.encryptionService

	w := &authWorld{t: t, backend: dbw.Backend, dir: dir, db: db, svc: svc}

	mfaEnc, err := esvc.EncryptWithAAD([]byte("mfa-"+canary), keyVersion, MFASecretAAD(1))
	if err != nil {
		t.Fatalf("seed mfa encrypt: %v", err)
	}
	mfaBytes, err := SerializeEncryptedData(mfaEnc)
	if err != nil {
		t.Fatalf("seed mfa serialize: %v", err)
	}
	mfaMeta, err := json.Marshal(mfaEnc.Metadata)
	if err != nil {
		t.Fatalf("seed mfa meta: %v", err)
	}
	mfa := &models.MFASecret{UserID: 1, SecretEnc: mfaBytes, SecretMeta: mfaMeta}
	if e := db.Create(mfa).Error; e != nil {
		t.Fatalf("[%s] seed mfa row: %v", dbw.Backend, e)
	}
	w.mfaID, w.mfaSeedEnc = mfa.ID, mfaBytes

	// dynamic_secret_configs: the real AAD binds the row's own ID
	// (DynamicSecretConfigAAD), so the row is created first with a placeholder,
	// then encrypted keyed to the real ID, then filled in — the same two-phase
	// shape production's own writer must use for the same reason.
	dc := &models.DynamicSecretConfig{Name: "seed-config", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres"}
	if e := db.Create(dc).Error; e != nil {
		t.Fatalf("[%s] seed dynconfig row: %v", dbw.Backend, e)
	}
	dcEnc, err := esvc.EncryptWithAAD([]byte("dsn-"+canary), keyVersion, DynamicSecretConfigAAD(dc.ID, 1, 1))
	if err != nil {
		t.Fatalf("seed dynconfig encrypt: %v", err)
	}
	dcBytes, err := SerializeEncryptedData(dcEnc)
	if err != nil {
		t.Fatalf("seed dynconfig serialize: %v", err)
	}
	dcMeta, err := json.Marshal(dcEnc.Metadata)
	if err != nil {
		t.Fatalf("seed dynconfig meta: %v", err)
	}
	if e := db.Model(dc).Updates(map[string]interface{}{"admin_dsn_enc": dcBytes, "admin_dsn_meta": dcMeta}).Error; e != nil {
		t.Fatalf("[%s] seed dynconfig fill: %v", dbw.Backend, e)
	}
	w.dynConfigID, w.dynConfigEnc = dc.ID, dcBytes

	leaseID := "seed-lease-" + canary
	dlEnc, err := esvc.EncryptWithAAD([]byte("cred-"+canary), keyVersion, DynamicSecretLeaseAAD(leaseID, dc.ID))
	if err != nil {
		t.Fatalf("seed lease encrypt: %v", err)
	}
	dlBytes, err := SerializeEncryptedData(dlEnc)
	if err != nil {
		t.Fatalf("seed lease serialize: %v", err)
	}
	dlMeta, err := json.Marshal(dlEnc.Metadata)
	if err != nil {
		t.Fatalf("seed lease meta: %v", err)
	}
	dl := &models.DynamicSecretLease{
		ConfigID: dc.ID, LeaseID: leaseID, ProjectID: 1, EnvironmentID: 1,
		CredentialEnc: dlBytes, CredentialMeta: dlMeta, Status: "active",
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if e := db.Create(dl).Error; e != nil {
		t.Fatalf("[%s] seed lease row: %v", dbw.Backend, e)
	}
	w.dynLeaseID, w.dynLeaseEnc = leaseID, dlBytes

	// password_resets: a plaintext, not-yet-migrated row — matches
	// MigratePasswordResetTokens' own selection query (token != '' AND
	// encrypted_token IS NULL).
	pwToken := "reset-token-" + canary
	pr := &models.PasswordReset{UserID: 1, Token: pwToken}
	if e := db.Create(pr).Error; e != nil {
		t.Fatalf("[%s] seed password_reset row: %v", dbw.Backend, e)
	}
	w.pwResetID, w.pwResetToken = pr.ID, pwToken

	return w
}

// migratePasswordResetTokenForFuzz replicates MigratePasswordResetTokens'
// (internal/encryptionops/auth_encryption.go) single-row body exactly — same
// single-statement UPDATE shape (encrypted_token/token_metadata set, token
// cleared, all in ONE map-based Updates call). Not called directly:
// encryptionops imports encryption, so a direct call from this package's test
// would be an import cycle.
func (w *authWorld) migratePasswordResetTokenForFuzz() error {
	var reset models.PasswordReset
	if err := w.db.First(&reset, w.pwResetID).Error; err != nil {
		return err
	}
	enc, meta, err := w.svc.EncryptSecretWithAAD([]byte(reset.Token), PasswordResetTokenAAD(reset.UserID))
	if err != nil {
		return fmt.Errorf("failed to encrypt password reset token %d: %w", reset.ID, err)
	}
	return w.db.Model(&reset).Updates(map[string]interface{}{
		"encrypted_token": enc,
		"token_metadata":  models.JSON(meta),
		"token":           nil,
	}).Error
}

func runAuthWorldCase(t *testing.T, dbw *fuzzworld.World, op opID, seam string, sk seamKind, canary string) {
	w := newAuthWorld(t, dbw, canary)

	restore := armSQLFault(w.db, seam) // both opUpgradeAAD and opMigrateAuthData are seamSQL-only (see opSeams)
	_ = sk

	var callErr error
	switch op {
	case opUpgradeAAD:
		_, callErr = w.svc.UpgradeAuthAAD(w.db)
	case opMigrateAuthData:
		callErr = w.migratePasswordResetTokenForFuzz()
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
	case opUpgradeAAD:
		w.checkUpgradeAADOracle(t, seam)
	case opMigrateAuthData:
		w.checkMigrateAuthDataOracle(t)
	}

	// oracle (d): no plaintext spill anywhere under the harness's own dirs.
	if hits := scanForPlaintext(w.dir, []byte(canary)); len(hits) > 0 {
		t.Fatalf("PLAINTEXT SPILL: op=%v seam=%q canary found in: %v", op, seam, hits)
	}
}

// checkUpgradeAADOracle asserts every table's row is BYTE-IDENTICAL to its
// seeded ciphertext — UpgradeAuthAAD wraps all three sweeps in ONE
// transaction, so a fault at any single seam must roll back ALL three tables,
// not just the one the fault targeted. Still decryptable under the ORIGINAL
// (pre-upgrade) AAD proves "decryptable with the old key" — this operation
// never changes the DEK, only the AAD-binding metadata, so there is no "new
// key" leg to this oracle, unlike rewrap/KEK-rotate/DEK-sweep.
func (w *authWorld) checkUpgradeAADOracle(t *testing.T, seam string) {
	var mfa models.MFASecret
	if err := w.db.First(&mfa, w.mfaID).Error; err != nil {
		t.Fatalf("DATA LOSS: mfa_secrets row missing after upgrade-aad fault %q: %v", seam, err)
	}
	if !bytes.Equal(mfa.SecretEnc, w.mfaSeedEnc) {
		t.Fatalf("ATOMICITY: upgrade-aad fault %q changed mfa_secrets despite the wrapping transaction — rollback did not cover this table", seam)
	}
	if _, err := decryptAuthRow(w.svc, mfa.SecretEnc, MFASecretAAD(1)); err != nil {
		t.Fatalf("DATA LOSS: mfa_secrets row no longer decrypts under its original AAD after upgrade-aad fault %q: %v", seam, err)
	}

	var dc models.DynamicSecretConfig
	if err := w.db.First(&dc, w.dynConfigID).Error; err != nil {
		t.Fatalf("DATA LOSS: dynamic_secret_configs row missing after upgrade-aad fault %q: %v", seam, err)
	}
	if !bytes.Equal(dc.AdminDSNEnc, w.dynConfigEnc) {
		t.Fatalf("ATOMICITY: upgrade-aad fault %q changed dynamic_secret_configs despite the wrapping transaction — rollback did not cover this table", seam)
	}
	if _, err := decryptAuthRow(w.svc, dc.AdminDSNEnc, DynamicSecretConfigAAD(dc.ID, 1, 1)); err != nil {
		t.Fatalf("DATA LOSS: dynamic_secret_configs row no longer decrypts under its original AAD after upgrade-aad fault %q: %v", seam, err)
	}

	var dl models.DynamicSecretLease
	if err := w.db.Where("lease_id = ?", w.dynLeaseID).First(&dl).Error; err != nil {
		t.Fatalf("DATA LOSS: dynamic_secret_leases row missing after upgrade-aad fault %q: %v", seam, err)
	}
	if !bytes.Equal(dl.CredentialEnc, w.dynLeaseEnc) {
		t.Fatalf("ATOMICITY: upgrade-aad fault %q changed dynamic_secret_leases despite the wrapping transaction — rollback did not cover this table", seam)
	}
	if _, err := decryptAuthRow(w.svc, dl.CredentialEnc, DynamicSecretLeaseAAD(w.dynLeaseID, dc.ID)); err != nil {
		t.Fatalf("DATA LOSS: dynamic_secret_leases row no longer decrypts under its original AAD after upgrade-aad fault %q: %v", seam, err)
	}
}

// checkMigrateAuthDataOracle asserts the password_reset row is left EXACTLY
// as seeded: sql:migrate-password-reset's GORM Before-hook stops the UPDATE
// from running at all (the same deterministic-OLD SQL-seam semantics as
// every other SQL seam in this catalog), so the row must be unchanged, never
// a mix of "token cleared" and "encrypted_token unset."
func (w *authWorld) checkMigrateAuthDataOracle(t *testing.T) {
	var pr models.PasswordReset
	if err := w.db.First(&pr, w.pwResetID).Error; err != nil {
		t.Fatalf("DATA LOSS: password_resets row missing after migrate-auth-data fault: %v", err)
	}
	if pr.Token != w.pwResetToken {
		t.Fatalf("ATOMICITY: migrate-auth-data fault changed password_resets' plaintext token despite the fault preventing the UPDATE: got %q want %q", pr.Token, w.pwResetToken)
	}
	if pr.EncryptedToken != nil {
		t.Fatalf("FAIL-CLOSED VIOLATION: migrate-auth-data fault fired but encrypted_token is set anyway — the injected fault did not actually prevent the write")
	}
}

// decryptAuthRow deserializes and decrypts one auth-table row's ciphertext
// under svc's CURRENT encryption service and aad — shared by
// checkUpgradeAADOracle's three per-table checks.
func decryptAuthRow(svc *Service, ciphertext []byte, aad []byte) ([]byte, error) {
	enc, err := DeserializeEncryptedData(ciphertext)
	if err != nil {
		return nil, err
	}
	return svc.encryptionService.DecryptWithAAD(enc, aad)
}

// ── seed-corpus reachability guard ───────────────────────────────────────
//
// PR #2047's lesson: a seed can look like it covers a code path (its bytes
// decode, via this file's own decodeFault, to a specific op/seam) without
// that path ever actually being exercised at runtime — #2047's FuzzAdminDispatch
// seeds all silently took a "not admin, nothing to check" early-return because
// of an unrelated argv-construction bug, and nothing failed. decodeFault here
// is simpler (pure, already covered by every oracle-c check demanding the
// fault actually fired), but "the decode function selects seam X" and "seam X's
// hook was actually consulted by the real production code" are still two
// different claims — this guard checks the second one directly, independent
// of oracle (c), so a future refactor that silently stops calling a seam
// (e.g. a code path rerouted around durableWriteSync) fails CI here even if
// every existing oracle happened to still pass some other way.

var (
	seamHitMu    sync.Mutex
	seamHitCount = map[string]int{}
)

// recordSeamHit is called by armFileFault/armMultiFileFault/armSQLFault's
// installed hooks ONLY when the seam label they were armed for is actually
// consulted by real production code — never merely when a case is selected.
func recordSeamHit(seam string) {
	seamHitMu.Lock()
	seamHitCount[seam]++
	seamHitMu.Unlock()
}

func resetSeamHitCounts() {
	seamHitMu.Lock()
	seamHitCount = map[string]int{}
	seamHitMu.Unlock()
}

func seamHits(seam string) int {
	seamHitMu.Lock()
	defer seamHitMu.Unlock()
	return seamHitCount[seam]
}

type faultSeedTriple struct {
	opSel, seamSel, kindSel byte
}

// allFaultInjectedSeedTriples enumerates one (op, seam, kind) triple per
// combination decodeFault can produce — the same set FuzzFaultInjectedOperations
// seeds itself with (via f.Add) and TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam
// replays directly, so the two can never silently drift apart.
func allFaultInjectedSeedTriples() []faultSeedTriple {
	var triples []faultSeedTriple
	for opSel := 0; opSel < int(numOps); opSel++ {
		seams := opSeams[opID(opSel)]
		for seamSel := range seams {
			for kindSel := 0; kindSel < 2; kindSel++ {
				triples = append(triples, faultSeedTriple{byte(opSel), byte(seamSel), byte(kindSel)})
			}
		}
	}
	return triples
}

// TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam replays this
// fuzzer's own committed seed set (allFaultInjectedSeedTriples, the exact
// triples FuzzFaultInjectedOperations' f.Add loop uses) through the SAME
// case runner the real fuzz target uses, and asserts every seam declared in
// opSeams was actually consulted by real production code at least once — a
// dead seed (one that decodes to a seam the runner never really reaches)
// fails this test, not just silently contributes zero coverage. Plain `go
// test`, not `-fuzz`: this runs on every CI invocation of this package's test
// suite, same as any other Test function.
func TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam(t *testing.T) {
	resetSeamHitCounts()

	dbWorlds := fuzzworld.Worlds(t, "faultopsfuzzreachguard", ":memory:", 0)
	for _, s := range allFaultInjectedSeedTriples() {
		runFaultInjectedCase(t, dbWorlds, s.opSel, s.seamSel, s.kindSel, 3, "old-pass", "new-pass", "secret-val")
	}

	for op, seams := range opSeams {
		for _, s := range seams {
			if s.kind == seamCombined {
				// The combined case (kek:rename-dek-verify-unknown) fires two
				// DIFFERENT sub-seam labels via armMultiFileFault, never its
				// own label — checked directly, not via s.label.
				for _, sub := range []string{"kek:rename-dek", "kek:verify-rename-dek"} {
					if seamHits(sub) == 0 {
						t.Errorf("DEAD SEED: op=%v combined seam %q's sub-seam %q was never actually consulted by production code", op, s.label, sub)
					}
				}
				continue
			}
			if seamHits(s.label) == 0 {
				t.Errorf("DEAD SEED: op=%v seam %q was never actually consulted by production code — a committed seed exists for it, but nothing reached it", op, s.label)
			}
		}
	}
}
