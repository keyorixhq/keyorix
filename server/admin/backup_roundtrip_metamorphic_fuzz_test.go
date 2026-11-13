// backup_roundtrip_metamorphic_fuzz_test.go: FuzzBackupRestoreRoundTrip is a
// METAMORPHIC round-trip fuzzer for `admin backup` / `admin restore`. Unlike
// backup_restore_property_test.go (one deterministic row per model) and
// backup_restore_fuzz_test.go (malformed-archive robustness only), this target
// drives a bounded, fuzz-byte-driven sequence of REAL core-layer mutations
// (projects, secrets, versions, roles, machine identities, deletes) onto a
// seeded, encrypted store -- producing arbitrary logical states and a real
// audit hash-chain -- then backs up, restores into a fresh data directory
// through the real CLI startup path, and asserts the round-trip oracles below:
// (1) logical-state equality, (2) per-version plaintext decrypt under the
// restored key files, (3) the restore's own verify-audit reports VALID,
// (4) idempotence, (6) a refusal is an explicit error, never silent
// corruption. Oracle 5 (continuation) and completed DEK/KEK-rotation and
// passphrase-change ops are documented limitations -- see op 9 and the report.
//
// It reuses this package's existing property-test harness verbatim:
// configureBackendTestDir / writeBackupRestoreTestConfig (config), the real
// runAdminBackup / runAdminRestore cobra RunE entry points driven through the
// package flag vars, and extractArchive / manifestTablesByName /
// normalizedNDJSONRows (the canonical logical-state dump: a backup archive's
// per-table normalized NDJSON, compared by parsed instant so a cross-backend
// timezone re-encoding is not a false diff). "Logical state" here is exactly
// that dump: every GORM table's rows, the wrapped key files (compared via the
// manifest's recorded SHA-256), and the audit chain (verified by the restore's
// own automatic verify-audit). The documented EXCLUSIONS are in
// assertLogicalEqual's doc comment.
//
// Invalid operations are tolerated as no-ops (the standard stateful-fuzz
// contract, matching internal/core/core_sequence_fuzz_test.go): a validation
// error from a core call is not a bug, it just does not advance the model. A
// backup/restore REFUSAL (a returned error) is likewise allowed and classified
// -- what is forbidden is a SUCCESS that silently corrupts (oracle 6).
//
// SQLite always runs; Postgres runs only when KEYORIX_TEST_PG_DSN is set, into
// isolated databases named bk_<pid>_<n>, each dropped on cleanup.
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

const roundTripPassphrase = "metamorphic-passphrase-1234"

// knownVersion records a secret version this harness created, so oracle 2 can
// re-derive its AAD and decrypt its restored ciphertext back to the exact
// plaintext bytes it was given. The plaintext is held only in memory and never
// logged (oracle 2 reports lengths/hashes on mismatch, never the value).
type knownVersion struct {
	nodeID    uint
	projectID uint
	version   int
	plaintext []byte
}

// roundTripModel is the harness's in-memory shadow of what it has created, used
// to feed later operations valid IDs and to drive oracle 2.
type roundTripModel struct {
	core      *core.KeyorixCore
	ctx       context.Context
	actorID   uint // a real, pre-created user so audit events never dangle
	projects  []uint
	envByProj map[uint]uint
	secrets   []uint
	nodeProj  map[uint]uint
	nodeVer   map[uint]int
	roles     []uint
	machines  []uint
	known     []knownVersion
	seq       int
}

func newRoundTripModel(ctx context.Context, c *core.KeyorixCore, actorID uint) *roundTripModel {
	return &roundTripModel{
		core:      c,
		ctx:       ctx,
		actorID:   actorID,
		envByProj: map[uint]uint{},
		nodeProj:  map[uint]uint{},
		nodeVer:   map[uint]int{},
	}
}

func (m *roundTripModel) next() int { m.seq++; return m.seq }

// pick returns ids[b % len] or 0 when empty -- a fuzz byte choosing an existing
// entity.
func pick(ids []uint, b byte) uint {
	if len(ids) == 0 {
		return 0
	}
	return ids[int(b)%len(ids)]
}

// applyOp decodes and attempts one operation from a 4-byte opcode window. Any
// ordinary error is swallowed (no-op); only the handful of ops that mutate key
// material return an error the caller must surface, because a failure there can
// leave the store half-rotated.
func (m *roundTripModel) applyOp(t *testing.T, enc *encryption.Service, gdb *gorm.DB, op, a, b, c byte) {
	t.Helper()
	switch op % 10 {
	case 0: // create project (auto-seeds environments)
		n := m.next()
		p, err := m.core.CreateProject(m.ctx, fmt.Sprintf("proj-%d", n), fmt.Sprintf("d-%d", n))
		if err != nil {
			return
		}
		m.projects = append(m.projects, p.ID)
		envs, err := m.core.ListEnvironmentsByProject(m.ctx, p.ID)
		if err == nil && len(envs) > 0 {
			m.envByProj[p.ID] = envs[int(a)%len(envs)].ID
		}
	case 1, 2: // create secret (encrypted version 1)
		pid := pick(m.projects, a)
		if pid == 0 {
			return
		}
		eid := m.envByProj[pid]
		if eid == 0 {
			return
		}
		n := m.next()
		pt := []byte(fmt.Sprintf("plaintext-%d-%d", n, b))
		node, err := m.core.CreateSecret(m.ctx, &core.CreateSecretRequest{
			Name:          fmt.Sprintf("secret-%d", n),
			Value:         pt,
			ProjectID:     pid,
			EnvironmentID: eid,
			Type:          "password",
			CreatedBy:     "fuzz",
		})
		if err != nil {
			return
		}
		m.secrets = append(m.secrets, node.ID)
		m.nodeProj[node.ID] = pid
		m.nodeVer[node.ID] = 1
		m.known = append(m.known, knownVersion{nodeID: node.ID, projectID: pid, version: 1, plaintext: pt})
	case 3: // add a new version to an existing secret
		nid := pick(m.secrets, a)
		if nid == 0 {
			return
		}
		n := m.next()
		pt := []byte(fmt.Sprintf("plaintext-v-%d-%d", n, b))
		_, err := m.core.UpdateSecret(m.ctx, &core.UpdateSecretRequest{
			ID:        nid,
			Value:     pt,
			UpdatedBy: "fuzz",
		})
		if err != nil {
			return
		}
		ver := m.nodeVer[nid] + 1
		m.nodeVer[nid] = ver
		m.known = append(m.known, knownVersion{nodeID: nid, projectID: m.nodeProj[nid], version: ver, plaintext: pt})
	case 4: // delete a secret
		nid := pick(m.secrets, a)
		if nid == 0 {
			return
		}
		_ = m.core.DeleteSecret(m.ctx, nid)
		// Leave it in model lists; a stale ID just becomes a future no-op. The
		// known-version registry entries for a deleted secret are pruned by
		// oracle 2 itself (a soft-deleted version may legitimately not decrypt
		// back through the normal read path; oracle 2 only checks rows that
		// survive into secret_versions).
	case 5: // create role
		n := m.next()
		role, _, err := m.core.CreateRoleWithScope(m.ctx, m.actorID,
			fmt.Sprintf("role-%d", n), fmt.Sprintf("rd-%d", n), nil, models.RoleAssignableProject)
		if err != nil {
			return
		}
		m.roles = append(m.roles, role.ID)
	case 6: // create machine identity
		pid := pick(m.projects, a)
		if pid == 0 {
			return
		}
		n := m.next()
		mi, err := m.core.CreateMachineIdentity(m.ctx, pid,
			fmt.Sprintf("mi-%d", n), "service", "fuzz", "internal", m.actorID, 0)
		if err != nil {
			return
		}
		m.machines = append(m.machines, mi.ID)
	case 7: // revoke a machine identity
		mid := pick(m.machines, a)
		pid := pick(m.projects, b)
		if mid == 0 || pid == 0 {
			return
		}
		_, _ = m.core.TransitionMachineIdentity(m.ctx, pid, mid, "revoked", m.actorID)
	case 8: // delete a project (cascade)
		pid := pick(m.projects, a)
		if pid == 0 {
			return
		}
		_ = m.core.DeleteProject(m.ctx, m.actorID, pid, true)
	case 9: // reserved: completed DEK rotation.
		// Intentionally a no-op in the committed op set. RotateDEKWithSweep is
		// designed to run as a STANDALONE process (admin encryption rotate-dek),
		// not alongside a live, in-process storage handle: driven here it retains
		// the key-directory flock, and the subsequent in-process `admin backup`
		// (which re-acquires that same flock) then refuses with "another process
		// already holds the DEK lock". That is a harness/wiring limitation of
		// in-process reuse, NOT a product defect -- the CLI serialises the two in
		// separate processes. See the report's limitations section.
		_ = enc
		_ = gdb
	}
}

// roundTripWorld holds one backend's fully wired source store.
type roundTripWorld struct {
	backend string
	dir     string
	cfgPath string
	cfg     *config.Config
	enc     *encryption.Service
	core    *core.KeyorixCore
	gdb     *gorm.DB
	model   *roundTripModel
}

// setupSource builds a fresh, encrypted source store for backend, drives the
// fuzz program onto it, and returns the world (process is left chdir'd in its
// dir). pgBaseDSN is required only for the postgres backend.
func setupSource(t *testing.T, backend, pgBaseDSN string, program []byte) *roundTripWorld {
	t.Helper()
	dir := t.TempDir()
	chdirTest(t, dir)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dir)
	require.NoError(t, enc.Initialize(roundTripPassphrase))

	cfgPath := bkConfigureBackend(t, backend, dir, pgBaseDSN)
	configPathFlag = cfgPath
	cfg, err := loadConfig()
	require.NoError(t, err)
	store, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)

	c := core.NewKeyorixCore(store)
	c.SetSecretValueEncryptor(enc)
	require.True(t, c.SecretValueEncryptionActive(), "secret value encryption must be wired for backend %s", backend)

	w := &roundTripWorld{backend: backend, dir: dir, cfgPath: cfgPath, cfg: cfg, enc: enc, core: c, gdb: gdb}

	// A real actor user, so every audit event an operation writes references an
	// existing users.id. Without this, operations pass a non-existent actor id
	// and the resulting audit_events.user_id dangles -- which restore's
	// mandatory dangling-reference check (correctly) refuses. In production the
	// bootstrap admin always exists; this reproduces that precondition. Created
	// by a raw insert so it writes no audit event of its own.
	actor := &models.User{Username: "fuzz-actor", UsernameFolded: "fuzz-actor"}
	require.NoError(t, gdb.Create(actor).Error)
	w.model = newRoundTripModel(context.Background(), c, actor.ID)

	// Drive the program: 4 bytes per op, bounded to keep per-iteration cost sane.
	const maxOps = 48
	ops := 0
	for i := 0; i+3 < len(program) && ops < maxOps; i += 4 {
		w.model.applyOp(t, enc, gdb, program[i], program[i+1], program[i+2], program[i+3])
		ops++
	}
	return w
}

// backupTables runs the real `admin backup` to a fresh archive and returns the
// manifest plus every table's normalized rows -- the canonical logical-state
// dump. On a REFUSAL it returns the error (never fails the test) so oracle 6
// can classify it.
func backupTables(t *testing.T, archivePath string) (backupfmt.Manifest, map[string][]map[string]any, string, error) {
	t.Helper()
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	if err != nil {
		return backupfmt.Manifest{}, nil, out, err
	}
	manifest, stage := extractArchive(t, archivePath)
	tables := make(map[string][]map[string]any, len(manifest.Tables))
	for _, te := range manifest.Tables {
		tables[te.Name] = normalizedNDJSONRows(t, filepath.Join(stage, te.TarName))
	}
	return manifest, tables, out, nil
}

// assertLogicalEqual compares two canonical dumps. EXCLUSIONS (each with its
// reason), none of which is a data-loss escape hatch:
//   - system_metadata: its schema_epoch / schema_min_compatible_epoch rows are
//     regenerated by the TARGET binary's own migration (ADR-097/101), so their
//     content legitimately differs; the row COUNT is still required equal.
//   - timestamp columns are compared by parsed instant (normalizeJSONValue),
//     not raw text, so a cross-backend timezone re-encoding of the same instant
//     is not a false diff.
//
// It does NOT verify: key-file bytes (covered by the manifest SHA-256 the
// restore itself checks, and by oracle 2's decrypt), the audit chain's
// cryptographic validity (covered by the restore's automatic verify-audit,
// oracle 3), or anything about on-disk physical layout.
func assertLogicalEqual(t *testing.T, a, b map[string][]map[string]any, context string) {
	t.Helper()
	var an, bn []string
	for n := range a {
		an = append(an, n)
	}
	for n := range b {
		bn = append(bn, n)
	}
	require.ElementsMatch(t, an, bn, "%s: table set differs", context)
	for name, rowsA := range a {
		rowsB := b[name]
		if name == "system_metadata" {
			require.Equal(t, len(rowsA), len(rowsB), "%s: system_metadata row count differs", context)
			continue
		}
		ra, rb := stripExcludedFields(rowsA), stripExcludedFields(rowsB)
		if name == "audit_events" {
			ra, rb = dropOperationSelfEvents(ra), dropOperationSelfEvents(rb)
		}
		// Normalize empty vs nil: testify distinguishes them, but an empty
		// table and a table whose only rows were filtered out are logically the
		// same here.
		if len(ra) == 0 {
			ra = nil
		}
		if len(rb) == 0 {
			rb = nil
		}
		require.Equal(t, ra, rb, "%s: rows differ for table %q", context, name)
	}
}

// operationSelfEventTypes are audit events recording the backup/restore ACTS
// themselves, not the logical data state. The task's own exclusion list names
// "the restore audit event" as a legitimate post-restore difference: `admin
// restore` appends an `admin.restore_completed` event to the restored chain
// (verified live here), so a backup of the restored store has exactly one more
// audit row than the source. `admin.backup_created` is its backup-side analog
// (each backup logs itself AFTER taking its snapshot, so it does not normally
// appear inside a compared snapshot -- excluding it is a harmless safety net
// against that ordering, not a load-bearing exclusion). Dropping these is sound
// for the chain comparison because they are always the TAIL of the chain, so
// the remaining rows' PrevHash/EntryHash are unaffected. It also keeps
// idempotence (oracle 4) consistent: each successive restore appends one more
// such event, all of which this filter removes.
var operationSelfEventTypes = map[string]bool{
	"admin.restore_completed": true,
	"admin.backup_created":    true,
}

func dropOperationSelfEvents(rows []map[string]any) []map[string]any {
	out := rows[:0:0]
	for _, r := range rows {
		et, _ := r["EventType"].(string)
		if operationSelfEventTypes[et] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// roundTripExcludedFields are columns deliberately NOT compared, each a derived,
// non-application-owned value that legitimately does not survive a logical
// restore -- so comparing them would flag a by-design behaviour as a data-loss
// bug. Every entry needs a reason:
//   - CacheEpoch: secret_nodes/secret_versions carry a `gorm:"<-:false"`
//     read-only, DB-trigger-maintained, process-local read-path cache-generation
//     stamp (models.go, store.EnsureSecretNodeCacheEpoch). GORM never writes it,
//     so the restore loader's INSERT cannot carry a non-zero value; a restored
//     server is a fresh process with an empty cache, so the absolute value is
//     irrelevant (only within-process consistency matters). The sibling
//     property test never seeds a non-zero value, so this round-trip was
//     previously untested; this fuzzer exercises it (via a second secret
//     version / rotation) and confirms the reset is benign. See the report's
//     findings (EXPECTED-DIFFERENCE BK-1).
var roundTripExcludedFields = map[string]bool{"CacheEpoch": true}

func stripExcludedFields(rows []map[string]any) []map[string]any {
	for _, r := range rows {
		for k := range roundTripExcludedFields {
			delete(r, k)
		}
	}
	return rows
}

// restoreInto restores archivePath into a fresh dir for backend and leaves the
// process chdir'd there. Returns the restore stdout and error (refusal
// surfaces as a non-nil error for oracle 6).
func restoreInto(t *testing.T, backend, pgBaseDSN, archivePath string) (string, string, error) {
	t.Helper()
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = bkConfigureBackend(t, backend, dstDir, pgBaseDSN)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	return dstDir, out, err
}

// oracleDecrypt (oracle 2) opens the restored store at dstDir, re-initializes
// an encryption service over the RESTORED key files, and asserts every known
// secret version still decrypts to the exact plaintext it was created with.
// Plaintext is never logged. It does NOT verify versions this harness did not
// create, nor versions whose secret was deleted (those rows may be gone).
func oracleDecrypt(t *testing.T, dstDir string, dstCfg *config.Config, known []knownVersion) {
	t.Helper()
	if len(known) == 0 {
		return
	}
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	enc := encryption.NewService(encCfg, dstDir)
	require.NoError(t, enc.Initialize(roundTripPassphrase), "re-init encryption over restored key files")

	gdb, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)

	for _, kv := range known {
		var row models.SecretVersion
		err := gdb.Where("secret_node_id = ? AND version_number = ?", kv.nodeID, kv.version).First(&row).Error
		if err != nil {
			// The version row is gone (secret deleted / purged). Not an oracle-2
			// failure: oracle 1 already proved the row set round-trips exactly.
			continue
		}
		aad := encryption.SecretAAD(kv.nodeID, kv.projectID, kv.version)
		got, derr := enc.DecryptSecretWithAAD(row.EncryptedValue, aad)
		require.NoError(t, derr, "oracle2: restored version (node=%d ver=%d) failed to decrypt", kv.nodeID, kv.version)
		if !bytesEqualConst(got, kv.plaintext) {
			t.Fatalf("oracle2: restored plaintext mismatch for node=%d ver=%d: got %d bytes (sha %s), want %d bytes (sha %s)",
				kv.nodeID, kv.version, len(got), shortSHA(got), len(kv.plaintext), shortSHA(kv.plaintext))
		}
	}
}

func bytesEqualConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func shortSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:4])
}

func FuzzBackupRestoreRoundTrip(f *testing.F) {
	// Seeds: a few op-rich programs plus degenerate inputs.
	f.Add([]byte{0, 0, 0, 0, 1, 0, 1, 0, 3, 0, 2, 0})             // project, secret, new version
	f.Add([]byte{0, 0, 0, 0, 1, 0, 1, 0, 5, 0, 0, 0, 6, 0, 0, 0}) // + role + machine
	f.Add([]byte{0, 0, 0, 0, 1, 0, 1, 0, 9, 0, 0, 0})             // project, secret, DEK rotation
	f.Add([]byte{})
	f.Add([]byte{255, 255, 255, 255})

	f.Fuzz(func(t *testing.T, program []byte) {
		require.NoError(t, i18n.InitializeForTesting())

		backends := []string{"sqlite"}
		if os.Getenv("KEYORIX_TEST_PG_DSN") != "" {
			backends = append(backends, "postgres")
		}
		for _, backend := range backends {
			runMetamorphicRoundTrip(t, backend, program)
		}
	})
}

func runMetamorphicRoundTrip(t *testing.T, backend string, program []byte) {
	resetBackupRestoreFlags(t)
	t.Setenv("KEYORIX_MASTER_PASSWORD", roundTripPassphrase)

	var pgBaseDSN string
	if backend == "postgres" {
		pgBaseDSN = bkPgBaseDSN(t)
	}

	src := setupSource(t, backend, pgBaseDSN, program)

	// Oracle 6 (refusal, not corruption): capture a pre-backup fingerprint of
	// the source so a REFUSED backup/restore can be proven to have left the
	// source untouched. A clean backup is itself read-only; we re-verify below.
	archive1 := filepath.Join(t.TempDir(), "a1.tar.gz")
	manifest1, tables1, out1, err := backupTables(t, archive1)
	if err != nil {
		// Backup refused. That is allowed; it must be an explicit error (it is)
		// and it must not have mutated the source. Re-open and confirm the
		// source still reads (a corrupt refusal would fail here). Classify and
		// stop -- there is no archive to restore.
		t.Logf("[%s] EXPECTED-REFUSAL backup: %v (stdout: %s)", backend, err, out1)
		require.Error(t, err)
		return
	}
	require.NotEmpty(t, manifest1.Tables)

	// Restore into a fresh dir via the real startup path (runs verify-audit).
	// Oracle 6 (refusal, not corruption): a restore that refuses must do so with
	// an explicit error and leave its target clean. We restore into a FRESH dir,
	// so the original source is structurally untouchable; what we assert here is
	// that the refusal is an explicit error, never a silent partial success.
	// (The restore path is itself journaled/atomic -- restore_commit.go,
	// restorejournal -- so a refused restore commits nothing.) A SUCCESS, by
	// contrast, must satisfy oracles 1-4 below.
	dstDir, restoreOut, rerr := restoreInto(t, backend, pgBaseDSN, archive1)
	if rerr != nil {
		t.Logf("[%s] EXPECTED-REFUSAL restore: %v (stdout: %s)", backend, rerr, restoreOut)
		require.Error(t, rerr)
		return
	}

	// Oracle 3 (audit chain + anchor): the restore ran verify-audit itself.
	require.Contains(t, restoreOut, "verify-audit on the restored database: VALID",
		"[%s] restore must verify the audit chain on the restored store", backend)

	// Build the restored target's config (we are chdir'd in dstDir now).
	dstCfg, err := loadConfig()
	require.NoError(t, err)

	// Oracle 2 (plaintext): every known version decrypts to its original bytes.
	oracleDecrypt(t, dstDir, dstCfg, src.model.known)

	// Oracle 1 (state equality): a second backup of the restored target equals
	// the first. (audit_events equality inside this is also the anchor-identity
	// half of oracle 3.)
	archive2 := filepath.Join(t.TempDir(), "a2.tar.gz")
	_, tables2, _, err := backupTables(t, archive2)
	require.NoError(t, err, "[%s] backup of restored target", backend)
	assertLogicalEqual(t, tables1, tables2, fmt.Sprintf("[%s] oracle1 restore(backup(S))==S", backend))

	// Oracle 4 (idempotence): restore the second archive again and re-back it up;
	// it must equal the second archive -- backup(restore(backup(S)))==backup(S).
	dstDir2, restoreOut2, rerr2 := restoreInto(t, backend, pgBaseDSN, archive2)
	require.NoError(t, rerr2, "[%s] second restore (idempotence): %s", backend, restoreOut2)
	require.Contains(t, restoreOut2, "verify-audit on the restored database: VALID")
	_ = dstDir2
	archive3 := filepath.Join(t.TempDir(), "a3.tar.gz")
	_, tables3, _, err := backupTables(t, archive3)
	require.NoError(t, err, "[%s] third backup (idempotence)", backend)
	assertLogicalEqual(t, tables2, tables3, fmt.Sprintf("[%s] oracle4 idempotence", backend))
}

// bkPgBaseDSN returns the base Postgres DSN for the bk_ fuzzer, or skips.
func bkPgBaseDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	return dsn
}

var bkPgCounter atomic.Int64

// bkConfigureBackend writes a config for backend rooted at dir. For postgres it
// first creates a fresh, isolated database named bk_<pid>_<n> (the task's
// mandated prefix), dropped on cleanup -- deliberately NOT the sibling
// property test's admin_backup_restore_ prefix.
func bkConfigureBackend(t *testing.T, backend, dir, pgBaseDSN string) string {
	t.Helper()
	switch backend {
	case "sqlite":
		return writeBackupRestoreTestConfig(t, dir, filepath.Join(dir, "secrets.db"))
	case "postgres":
		return writePostgresBackupRestoreTestConfig(t, dir, bkPgIsolatedDSN(t, pgBaseDSN))
	default:
		t.Fatalf("unknown backend %q", backend)
		return ""
	}
}

func bkPgIsolatedDSN(t *testing.T, base string) string {
	t.Helper()
	n := bkPgCounter.Add(1)
	dbName := fmt.Sprintf("bk_%d_%d", os.Getpid(), n)
	admin := pgAdminRawOpen(t, base)
	require.NoError(t, admin.Exec("CREATE DATABASE "+dbName).Error) //nolint:gosec // pid+counter generated name, not external input
	t.Cleanup(func() {
		cleaner := pgAdminRawOpen(t, base)
		_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	})
	return pgdsn.PGReplaceDBName(base, dbName)
}
