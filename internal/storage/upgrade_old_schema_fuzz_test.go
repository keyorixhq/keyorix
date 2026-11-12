// upgrade_old_schema_fuzz_test.go -- FuzzUpgradeFromOldSchema and
// FuzzUpgradeInterrupted: skip-version upgrades from a database a released binary
// wrote, migrated by this tree's code.
//
// FuzzUpgradeMigration (internal/core) replays three fixed databases. These two
// targets add what that one cannot: generated state on top of a real old
// schema (versions, renames in the folding-backfill shapes, grants, audit rows),
// the releases either side of its three, an idempotence check over the whole
// database, and an interruption at every write statement of the upgrade path
// (the sibling crash-recovery work covers only the fresh-install path).
//
// Each snapshot under testdata/upgrade-snapshots was written by that release's
// own core (see README.md there); no old code runs here. Oracles are one-way and
// report ugFinding values so the red-proof tests can assert which one fired:
//
//	1 every secret version decrypts to the value written (and the latest reads
//	  back through core.GetSecretValue when the secret is live);
//	2 core.Authorize equals the old-version decision: the old binary's recorded
//	  verdict on the snapshot's own users, ugModel on generated state;
//	3 audit rows are not lost, and the chain verifies where the source is on
//	  HEAD's hash encoding (v0.91.0 predates #1452 and needs the operator's
//	  migrate-chain-encoding step, so it gets the row count only);
//	4 a second migration changes nothing, in the schema or in any row;
//	5 (FuzzUpgradeInterrupted) an upgrade stopped after any write statement
//	  completes on restart with oracles 1-4 intact.
//
// What these do NOT check: Postgres (see the README), machine identities, MFA
// and SSO state, intended refusals (two names folding together refuse by
// design, INV-STORAGE-18, so the generator cannot produce them), and pre-v0.91
// sources. Oracle 5 is fail-stop: the first statement to fail and every one after
// it, which is the state a crash leaves, not a torn write inside SQLite.
package storage

import (
	"bytes"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ugSources are the releases with a snapshot, oldest first. ugChainFrom is the
// first index whose audit chain is on HEAD's encoding.
var ugSources = []string{"v0.91.0", "v0.92.1", "v0.93.0", "v0.94.0", "v0.95.3", "v0.96.3"}

const ugChainFrom = 1

// ugSharedKeyDir holds the test key the existing upgrade fixtures use; the
// snapshots were written under it, so they carry no key material of their own.
const ugSharedKeyDir = "../core/testdata/upgrade-fixtures/v095"

type ugManifestVerdict struct {
	User    uint   `json:"user"`
	Perm    string `json:"perm"`
	Project uint   `json:"project"`
	Env     uint   `json:"env"`
	Allow   bool   `json:"allow"`
}

type ugManifestVersion struct {
	Version int    `json:"version"`
	Value   string `json:"value"`
}

type ugManifestSecret struct {
	ID        uint                `json:"id"`
	ProjectID uint                `json:"project_id"`
	Versions  []ugManifestVersion `json:"versions"`
}

type ugManifest struct {
	SourceTag  string              `json:"source_tag"`
	Passphrase string              `json:"passphrase"`
	Secrets    []ugManifestSecret  `json:"secrets"`
	Verdicts   []ugManifestVerdict `json:"verdicts"`
}

// ugTemplate is one source release, loaded once per process: PBKDF2 and the SQL
// replay would otherwise dominate every exec.
type ugTemplate struct {
	once     sync.Once
	err      error
	dbFile   string
	manifest ugManifest
	enc      *encryption.Service
}

var ugTemplates sync.Map

// ugFinding is one oracle failure.
type ugFinding struct {
	Invariant int
	Detail    string
}

func (f ugFinding) String() string { return fmt.Sprintf("invariant %d: %s", f.Invariant, f.Detail) }

func ugEncConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
}

func ugCopyFile(src, dst string) error {
	b, err := os.ReadFile(src) // #nosec G304 -- test fixture path
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

func ugLoadTemplate(tag string) (*ugTemplate, error) {
	v, _ := ugTemplates.LoadOrStore(tag, &ugTemplate{})
	tpl := v.(*ugTemplate)
	tpl.once.Do(func() { tpl.err = tpl.build(tag) })
	return tpl, tpl.err
}

// build replays snapshot.sql into a private file and opens the shared test key.
// Key material is only needed at Initialize, so its directory does not outlive
// this call; the replayed database is copied per exec and lives for the process.
func (tpl *ugTemplate) build(tag string) error {
	dir := filepath.Join("testdata", "upgrade-snapshots", tag)
	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json")) // #nosec G304 -- test fixture path
	if err != nil {
		return err
	}
	if err := json.Unmarshal(mb, &tpl.manifest); err != nil {
		return fmt.Errorf("decoding %s manifest: %w", tag, err)
	}
	script, err := os.ReadFile(filepath.Join(dir, "snapshot.sql")) // #nosec G304 -- test fixture path
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "keyorix-upgrade-tpl-*")
	if err != nil {
		return err
	}
	tpl.dbFile = filepath.Join(tmp, "template.db")
	db, err := sql.Open("sqlite", tpl.dbFile)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(string(script)); err != nil {
		return fmt.Errorf("replaying %s snapshot: %w", tag, err)
	}

	keys, err := os.MkdirTemp("", "keyorix-upgrade-key-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(keys) }()
	for _, f := range []string{"dek.key", "kek.salt"} {
		if err := ugCopyFile(filepath.Join(ugSharedKeyDir, f), filepath.Join(keys, f)); err != nil {
			return err
		}
	}
	tpl.enc = encryption.NewService(ugEncConfig(), keys)
	if err := tpl.enc.Initialize(tpl.manifest.Passphrase); err != nil {
		return fmt.Errorf("opening test key for %s: %w", tag, err)
	}
	return nil
}

func ugFold(name string) string {
	f, err := identity.NewFoldedName(name)
	if err != nil {
		return ""
	}
	return f.Folded()
}

// ugGenConfig is the HEAD side of ugConfig.
func ugGenConfig(enc *encryption.Service, gdb *gorm.DB) ugConfig {
	return ugConfig{
		Encrypt: func(pt, aad []byte) ([]byte, []byte, error) { return enc.EncryptSecretWithAAD(pt, aad) },
		AAD:     func(s, p uint, v int) []byte { return encryption.SecretAAD(s, p, v) },
		Fold:    ugFold,
		SealAudit: func(db *sql.DB, id int64, prev string) (string, error) {
			// Only the columns this old schema has: models.AuditEvent also names ones added since.
			cols, err := ugColumns(db, "audit_events")
			if err != nil {
				return "", err
			}
			var ev models.AuditEvent
			if err := gdb.Table("audit_events").Select(cols).Where("id = ?", id).Take(&ev).Error; err != nil {
				return "", fmt.Errorf("re-reading generated audit row %d: %w", id, err)
			}
			return store.ComputeAuditEntryHash(&ev, prev), nil
		},
	}
}

func ugLocalConfig(dbPath string) *config.Config {
	return &config.Config{Storage: config.StorageConfig{
		Type:       "local",
		Database:   config.DatabaseConfig{Path: dbPath},
		Encryption: *ugEncConfig(),
	}}
}

// ugHooks are the harness-side breaks the red-proof tests use. Production paths
// are never altered; each hook only touches the scratch database file.
type ugHooks struct {
	afterGenerate func(db *sql.DB) error
	afterMigrate  func(db *sql.DB) error
	beforeRerun   func(db *sql.DB) error
	// bareInterrupt interrupts migrateSQLite outside withMigrationLock's
	// BEGIN EXCLUSIVE, a shape no production boot has. Only the red-proof that
	// documents the artefact sets it; the fuzz target never does.
	bareInterrupt bool
}

// ugRun is one exec. stopAfter == 0 runs the real startup path once;
// stopAfter > 0 first fail-stops the upgrade after that many write statements.
func ugRun(t testing.TB, tag string, chainVerifiable bool, data []byte, stopAfter int, hooks ugHooks) []ugFinding {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	tpl, err := ugLoadTemplate(tag)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", tag, err)
	}
	workDir := t.TempDir()
	dbPath := filepath.Join(workDir, "upgrade.db")
	if err := ugCopyFile(tpl.dbFile, dbPath); err != nil {
		t.Fatalf("copying template: %v", err)
	}

	raw, gdb, closeRaw := ugOpenRaw(t, dbPath)
	exp, err := ugApplyState(raw, data, ugGenConfig(tpl.enc, gdb))
	if err != nil {
		closeRaw()
		t.Fatalf("building generated state on %s: %v", tag, err)
	}
	if hooks.afterGenerate != nil {
		if err := hooks.afterGenerate(raw); err != nil {
			closeRaw()
			t.Fatalf("afterGenerate hook: %v", err)
		}
	}
	model, err := ugBuildModel(raw)
	if err != nil {
		closeRaw()
		t.Fatalf("building old-version model: %v", err)
	}
	var preAudit int64
	if err := raw.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&preAudit); err != nil {
		closeRaw()
		t.Fatalf("counting audit rows: %v", err)
	}
	closeRaw()

	var findings []ugFinding
	if stopAfter > 0 {
		if err := ugInterruptedMigrate(t, dbPath, stopAfter, hooks.bareInterrupt); err != nil {
			t.Fatalf("interrupted run: %v", err)
		}
	}

	// The real startup path: the same CreateStorage server boot calls.
	st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
	if err != nil {
		inv := 0
		if stopAfter > 0 {
			inv = 5
		}
		return append(findings, ugFinding{inv, fmt.Sprintf("CreateStorage on a %s database (stopAfter=%d): %v", tag, stopAfter, err)})
	}
	defer func() { _ = ugCloseStorage(st) }()

	// Oracle 4 comes first: the core reads below legitimately write audit and
	// read-count rows.
	before, err := ugDumpDB(dbPath)
	if err != nil {
		t.Fatalf("dumping migrated database: %v", err)
	}
	if hooks.beforeRerun != nil {
		rerunRaw, _, closeRerun := ugOpenRaw(t, dbPath)
		if err := hooks.beforeRerun(rerunRaw); err != nil {
			closeRerun()
			t.Fatalf("beforeRerun hook: %v", err)
		}
		closeRerun()
	}
	again, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
	if err != nil {
		findings = append(findings, ugFinding{4, fmt.Sprintf("second migration failed: %v", err)})
	} else {
		_ = ugCloseStorage(again)
		after, err := ugDumpDB(dbPath)
		if err != nil {
			t.Fatalf("dumping re-migrated database: %v", err)
		}
		if !bytes.Equal(before, after) {
			findings = append(findings, ugFinding{4, "second migration changed the database: " + ugFirstDiff(before, after)})
		}
	}

	if hooks.afterMigrate != nil {
		mutRaw, _, closeMut := ugOpenRaw(t, dbPath)
		if err := hooks.afterMigrate(mutRaw); err != nil {
			closeMut()
			t.Fatalf("afterMigrate hook: %v", err)
		}
		closeMut()
	}

	c := core.NewKeyorixCore(st)
	c.SetAuthEncryptor(tpl.enc)
	c.SetSecretValueEncryptor(tpl.enc)
	return append(findings, ugCheckOracles(t, tag, chainVerifiable, dbPath, c, tpl, exp, model, preAudit, len(data))...)
}

func ugCheckOracles(t testing.TB, tag string, chainVerifiable bool, dbPath string, c *core.KeyorixCore, tpl *ugTemplate, exp *ugExpect, model *ugModel, preAudit int64, probeOffset int) []ugFinding {
	t.Helper()
	var out []ugFinding
	fail := func(inv int, format string, args ...any) {
		out = append(out, ugFinding{inv, fmt.Sprintf(format, args...)})
	}
	ctx := t.Context()
	raw, _, closeRaw := ugOpenRaw(t, dbPath)
	defer closeRaw()

	decryptRow := func(secret uint, project uint, version int) ([]byte, error) {
		var ct []byte
		if err := raw.QueryRow("SELECT encrypted_value FROM secret_versions WHERE secret_node_id = ? AND version_number = ?", secret, version).Scan(&ct); err != nil {
			return nil, fmt.Errorf("reading version row: %w", err)
		}
		return tpl.enc.DecryptSecretWithAAD(ct, encryption.SecretAAD(secret, project, version))
	}

	// Oracle 1, old-code ciphertexts.
	for _, s := range tpl.manifest.Secrets {
		for _, v := range s.Versions {
			got, err := decryptRow(s.ID, s.ProjectID, v.Version)
			switch {
			case err != nil:
				fail(1, "snapshot secret %d v%d no longer decrypts after upgrading from %s: %v", s.ID, v.Version, tag, err)
			case string(got) != v.Value:
				fail(1, "snapshot secret %d v%d decrypted to %q, want %q", s.ID, v.Version, got, v.Value)
			}
		}
		latest := s.Versions[len(s.Versions)-1].Value
		got, err := c.GetSecretValue(ctx, s.ID)
		switch {
		case err != nil:
			fail(1, "GetSecretValue(%d) after upgrading from %s: %v", s.ID, tag, err)
		case string(got) != latest:
			fail(1, "GetSecretValue(%d) = %q, want latest %q", s.ID, got, latest)
		}
	}
	// Oracle 1, generated secrets.
	for _, s := range exp.Secrets {
		for _, v := range s.Versions {
			got, err := decryptRow(s.ID, s.ProjectID, v.Number)
			switch {
			case err != nil:
				fail(1, "generated secret %d v%d no longer decrypts: %v", s.ID, v.Number, err)
			case !bytes.Equal(got, v.Plaintext):
				fail(1, "generated secret %d v%d decrypted to the wrong value", s.ID, v.Number)
			}
		}
		if s.Deleted {
			continue
		}
		got, err := c.GetSecretValue(ctx, s.ID)
		want := s.Versions[len(s.Versions)-1].Plaintext
		switch {
		case err != nil:
			fail(1, "GetSecretValue(%d) on generated secret: %v", s.ID, err)
		case !bytes.Equal(got, want):
			fail(1, "GetSecretValue(%d) on generated secret returned the wrong value", s.ID)
		}
	}

	// Oracle 2: the old binary's own verdicts, then the model on generated state.
	for _, v := range tpl.manifest.Verdicts {
		got, err := c.Authorize(ctx, v.User, v.Perm, core.Scope{ProjectID: v.Project, EnvironmentID: v.Env})
		if err != nil {
			fail(2, "Authorize(u=%d,%s,%d,%d) errored after upgrading from %s: %v", v.User, v.Perm, v.Project, v.Env, tag, err)
			continue
		}
		if got != v.Allow {
			fail(2, "Authorize(u=%d,%s,%d,%d) changed across the upgrade from %s: old binary said %v, now %v", v.User, v.Perm, v.Project, v.Env, tag, v.Allow, got)
		}
	}
	// The model is checked on a stride of the generated probes so one exec stays
	// well under a second; which ones varies with the input, so every probe still
	// gets a turn over a run. The old binary's verdicts above are always all checked.
	total := len(model.Users) * len(ugProbePerms) * len(model.Scopes)
	stride := 1 + total/150
	count := probeOffset
	for _, u := range model.Users {
		for _, perm := range ugProbePerms {
			for _, s := range model.Scopes {
				count++
				if count%stride != 0 {
					continue
				}
				got, err := c.Authorize(ctx, u, perm, core.Scope{ProjectID: s[0], EnvironmentID: s[1]})
				if err != nil {
					fail(2, "Authorize(u=%d,%s,%d,%d) errored on generated state: %v", u, perm, s[0], s[1], err)
					continue
				}
				if want := model.Decide(u, perm, s[0], s[1]); got != want {
					fail(2, "Authorize(u=%d,%s,%d,%d) on generated state: old-version model says %v, now %v (source %s)", u, perm, s[0], s[1], want, got, tag)
				}
			}
		}
	}

	// Oracle 3: audit log intact.
	var n int64
	if err := raw.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&n); err != nil {
		t.Fatalf("counting audit rows: %v", err)
	}
	if n < preAudit {
		fail(3, "audit_events shrank across the upgrade from %s: %d rows before, %d after", tag, preAudit, n)
	}
	if chainVerifiable {
		res, err := c.VerifyAuditChain(ctx)
		switch {
		case err != nil:
			fail(3, "VerifyAuditChain after upgrading from %s: %v", tag, err)
		case !res.Valid:
			fail(3, "audit chain broken after upgrading from %s: first broken id=%v (%d chained, %d unchained, %d generated)", tag, res.FirstBrokenID, res.ChainedEvents, res.UnchainedEvents, exp.AuditAdded)
		}
	}
	return out
}

// ugOpenRaw opens a plain connection for harness-side reads and writes (never
// through the migration lock). The gorm handle shares it.
func ugOpenRaw(t testing.TB, dbPath string) (*sql.DB, *gorm.DB, func()) {
	t.Helper()
	gdb, err := openSQLiteGorm(sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("opening %s: %v", dbPath, err)
	}
	raw, err := gdb.DB()
	if err != nil {
		t.Fatalf("raw handle: %v", err)
	}
	return raw, gdb, func() { _ = raw.Close() }
}

func ugCloseStorage(st corestorage.Storage) error {
	if c, ok := st.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// ugDumpDB renders the schema and every row deterministically. WAL state is
// invisible here by construction, which is why a second migration that only
// checkpoints reads as "no change".
func ugDumpDB(dbPath string) ([]byte, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	var out bytes.Buffer
	rows, err := db.Query("SELECT type, name, COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var typ, name, text string
		if err := rows.Scan(&typ, &name, &text); err != nil {
			_ = rows.Close()
			return nil, err
		}
		fmt.Fprintf(&out, "schema %s %s %s\n", typ, name, text)
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	slices.Sort(tables)
	for _, tbl := range tables {
		cols, err := ugColumns(db, tbl)
		if err != nil {
			return nil, err
		}
		exprs := make([]string, len(cols))
		for i, c := range cols {
			exprs[i] = `quote("` + c + `")`
		}
		rs, err := db.Query(`SELECT ` + strings.Join(exprs, ",") + ` FROM "` + tbl + `" ORDER BY rowid`)
		if err != nil {
			return nil, fmt.Errorf("dumping %s: %w", tbl, err)
		}
		for rs.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rs.Scan(ptrs...); err != nil {
				_ = rs.Close()
				return nil, err
			}
			fmt.Fprintf(&out, "row %s", tbl)
			for i, v := range vals {
				fmt.Fprintf(&out, "|%s=%s", cols[i], v.String)
			}
			out.WriteByte('\n')
		}
		if err := rs.Close(); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func ugFirstDiff(a, b []byte) string {
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	for i := range max(len(al), len(bl)) {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d: %.200q != %.200q", i, x, y)
		}
	}
	return "same lines, different framing"
}

// errUgInterrupted is the fail-stop error the interruption seam injects.
var errUgInterrupted = errors.New("upgrade-fuzz: simulated crash")

// ugInterruptedMigrate runs the real boot migration (migrateSQLite inside
// withMigrationLock, the call createLocalStorage makes) with every write-class
// gorm statement counted, failing the stopAfter'th and every later one -- the
// persisted state a crash at that statement leaves. The lock's BEGIN EXCLUSIVE
// transaction is open at the stop and rolls back when the connection closes.
//
// bare skips the lock and calls migrateDatabase on an autocommit connection:
// statements that already reached SQLite then stay durable. No production boot
// does that (see docs/findings/2026-11-09-FINDING-v091-interrupted-upgrade-artifact.md);
// it exists only so a red-proof can show what the lock buys.
func ugInterruptedMigrate(t testing.TB, dbPath string, stopAfter int, bare bool) error {
	t.Helper()
	gdb, err := openSQLiteGorm(sqliteDSN(dbPath))
	if err != nil {
		return err
	}
	raw, err := gdb.DB()
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	var seen atomic.Int64
	stop := func(db *gorm.DB) {
		if seen.Add(1) >= int64(stopAfter) {
			_ = db.AddError(errUgInterrupted)
		}
	}
	for _, reg := range []error{
		gdb.Callback().Raw().Before("gorm:raw").Register("ug:stop_raw", stop),
		gdb.Callback().Create().Before("gorm:create").Register("ug:stop_create", stop),
		gdb.Callback().Update().Before("gorm:update").Register("ug:stop_update", stop),
		gdb.Callback().Delete().Before("gorm:delete").Register("ug:stop_delete", stop),
	} {
		if reg != nil {
			return reg
		}
	}
	f := &DefaultStorageFactory{}
	var mErr error
	if bare {
		mErr = f.migrateDatabase(gdb)
	} else {
		mErr = withMigrationLock(gdb, false, dbPath, f.migrateSQLite)
	}
	// A stop that was reached surfaces as errUgInterrupted. A stop beyond the
	// migration's last write statement is not reached and the migration simply
	// completes; the restart that follows is then a plain second boot. Any other
	// error is a harness or migration failure, not an interruption.
	if mErr != nil && !errors.Is(mErr, errUgInterrupted) {
		return fmt.Errorf("interrupted migration failed for a reason other than the injected stop: %w", mErr)
	}
	return nil
}

func ugSeeds() [][]byte {
	seeds := [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 64)}
	for i := range 6 {
		b := make([]byte, 96)
		for j := range b {
			b[j] = byte((i+1)*31 + j*(i+3))
		}
		seeds = append(seeds, b)
	}
	return seeds
}

// FuzzUpgradeFromOldSchema upgrades generated state on a real old schema with
// the real startup path. See the file comment for the oracles.
func FuzzUpgradeFromOldSchema(f *testing.F) {
	for i := range ugSources {
		for _, s := range ugSeeds() {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		if len(data) > 400 {
			t.Skip("over the generator's useful input size")
		}
		idx := int(sel) % len(ugSources)
		for _, fnd := range ugRun(t, ugSources[idx], idx >= ugChainFrom, data, 0, ugHooks{}) {
			t.Error(fnd)
		}
	})
}

// FuzzUpgradeInterrupted stops the upgrade after a fuzz-chosen write statement
// and asserts the restart completes it, with every other oracle intact. The
// interruption goes through the real boot path (withMigrationLock), so every
// source is covered, v0.91.0 included: its apparent "column never added" defect
// only exists outside that lock (TestUpgradeInterrupted_V091_BarePathArtefact).
func FuzzUpgradeInterrupted(f *testing.F) {
	for i := range ugSources {
		for _, stop := range []uint16{1, 2, 3, 7, 19, 41, 83, 150} {
			f.Add(uint8(i), stop, []byte{byte(i), byte(stop)})
		}
	}
	f.Fuzz(func(t *testing.T, sel uint8, stop uint16, data []byte) {
		if len(data) > 400 {
			t.Skip("over the generator's useful input size")
		}
		idx := int(sel) % len(ugSources)
		for _, fnd := range ugRun(t, ugSources[idx], idx >= ugChainFrom, data, int(stop%240)+1, ugHooks{}) {
			t.Error(fnd)
		}
	})
}
