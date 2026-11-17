// upgrade_pg_fuzz_test.go -- the PostgreSQL leg of the skip-version upgrade
// fuzzers: FuzzUpgradePGFromOldSchema and FuzzUpgradePGInterrupted.
//
// Each source database under testdata/upgrade-snapshots-pg is written by that
// release's own core running against PostgreSQL (see README.md there, including
// its status line: until a snapshot exists these targets skip). Oracles
// 1-5 are the ones in upgrade_old_schema_fuzz_test.go, and three more exist only
// on this leg:
//
//	6 an interrupted migration leaves the database exactly as it found it. The
//	  whole migration runs in one transaction (withMigrationLockPooled), so a
//	  statement failing part way must roll everything back, including the DDL;
//	7 column types, nullability and defaults equal those of a fresh install of
//	  this tree (information_schema), apart from pgSchemaIgnored;
//	8 the constraint and index sets equal those of a fresh install, apart from
//	  pgSchemaIgnored.
//
// Interruption is fail-stop at the gorm layer through the real locked path; see
// pgInterruptedMigrate for what that does and does not cover. Each exec gets its
// own database named w6_ug_*, dropped when the test ends.
//
// What these do NOT check: machine identities, MFA and SSO state (not generated,
// like the SQLite leg), pre-v0.91 sources, a torn write inside PostgreSQL itself
// (only the client-visible failure of a statement is injected), and the
// post-commit CONCURRENTLY audit index build, which is outside the migration
// transaction and not interrupted here.
package storage

import (
	"bytes"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

const pgSnapshotDir = "testdata/upgrade-snapshots-pg"

// pgTemplate is one source release, loaded once per process: PBKDF2 would
// otherwise dominate every exec.
type pgTemplate struct {
	once     sync.Once
	err      error
	script   string
	manifest ugManifest
	enc      *encryption.Service
}

var (
	pgTemplates    sync.Map
	pgRunCounter   atomic.Int64
	pgFreshOnce    sync.Once
	pgFreshSchema  *pgSchema
	pgFreshErr     error
	pgRedactDSNErr = regexp.MustCompile(`postgres(ql)?://[^\s]*`)
)

func pgLoadTemplate(tag string) (*pgTemplate, error) {
	v, _ := pgTemplates.LoadOrStore(tag, &pgTemplate{})
	tpl := v.(*pgTemplate)
	tpl.once.Do(func() { tpl.err = tpl.build(tag) })
	return tpl, tpl.err
}

func (tpl *pgTemplate) build(tag string) error {
	dir := filepath.Join(pgSnapshotDir, tag)
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
	tpl.script = string(script)
	keys, err := os.MkdirTemp("", "keyorix-upgrade-pg-key-*")
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

// pgOpenRaw opens a small plain pool on dsn. Statements are sent unprepared so a
// snapshot replays in one round trip and DDL cannot invalidate a cached plan.
func pgOpenRaw(t testing.TB, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgSimpleProtocolDSN(dsn))
	if err != nil {
		t.Fatalf("opening postgres: %v", redactDSN(err))
	}
	db.SetMaxOpenConns(2)
	return db
}

func pgSimpleProtocolDSN(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		return dsn + sep + "default_query_exec_mode=simple_protocol"
	}
	return dsn + " default_query_exec_mode=simple_protocol"
}

func redactDSN(err error) string {
	if err == nil {
		return ""
	}
	return pgRedactDSNErr.ReplaceAllString(err.Error(), "<dsn>")
}

// pgCreateDatabase makes an empty database on the shared server, dropped on
// cleanup. Only names starting w6_ ever reach this function.
func pgCreateDatabase(t testing.TB, base string) (name, dsn string) {
	t.Helper()
	name = fmt.Sprintf("w6_ug_%d_%d", os.Getpid(), pgRunCounter.Add(1))
	admin := pgOpenRaw(t, base)
	defer func() { _ = admin.Close() }()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("creating %s: %v", name, redactDSN(err))
	}
	t.Cleanup(func() {
		cleaner, err := sql.Open("pgx", pgSimpleProtocolDSN(base))
		if err != nil {
			return
		}
		defer func() { _ = cleaner.Close() }()
		_, _ = cleaner.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
	})
	return name, pgdsn.PGReplaceDBName(base, name)
}

func pgLocalConfig(dsn string) *config.Config {
	return &config.Config{Storage: config.StorageConfig{
		Type:       "postgres",
		Database:   config.DatabaseConfig{DSN: dsn},
		Encryption: *ugEncConfig(),
	}}
}

// pgGenConfig is ugGenConfig on Postgres; only the column lookup differs.
func pgGenConfig(enc *encryption.Service, gdb *gorm.DB) ugConfig {
	return ugConfig{
		Encrypt: func(pt, aad []byte) ([]byte, []byte, error) { return enc.EncryptSecretWithAAD(pt, aad) },
		AAD:     func(s, p uint, v int) []byte { return encryption.SecretAAD(s, p, v) },
		Fold:    ugFold,
		SealAudit: func(db *sql.DB, id int64, prev string) (string, error) {
			cols, err := pgColumns(db, "audit_events")
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

// pgHooks are the harness-side breaks of the red-proof tests; none touches
// production paths, only that run's scratch database.
type pgHooks struct {
	afterGenerate func(db *sql.DB) error
	afterMigrate  func(db *sql.DB) error
	beforeRerun   func(db *sql.DB) error
	bareInterrupt bool // stop through migrateDatabase directly, without the transaction
}

// pgRun is one exec. stopAfter == 0 runs the real startup path once; stopAfter > 0
// first fail-stops a migration after that many write statements.
func pgRun(t testing.TB, tag string, chainVerifiable bool, data []byte, stopAfter int, hooks pgHooks) []ugFinding {
	t.Helper()
	base := pgTestDSN(t.(*testing.T))
	if _, err := os.Stat(filepath.Join(pgSnapshotDir, tag, "snapshot.sql")); errors.Is(err, os.ErrNotExist) {
		t.Skipf("no PostgreSQL snapshot for %s yet: run testdata/upgrade-snapshots-pg/generator/regen.sh", tag)
	}
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	tpl, err := pgLoadTemplate(tag)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", tag, err)
	}
	_, dsn := pgCreateDatabase(t, base)

	raw := pgOpenRaw(t, dsn)
	if _, err := raw.Exec(strings.ReplaceAll(tpl.script, pgStmtSep, ";\n")); err != nil {
		_ = raw.Close()
		t.Fatalf("replaying %s snapshot: %v", tag, redactDSN(err))
	}
	gdb := pgOpenGorm(t, dsn)
	exp, err := pgApplyState(raw, data, pgGenConfig(tpl.enc, gdb))
	if err != nil {
		_ = raw.Close()
		t.Fatalf("building generated state on %s: %v", tag, redactDSN(err))
	}
	if hooks.afterGenerate != nil {
		if err := hooks.afterGenerate(raw); err != nil {
			_ = raw.Close()
			t.Fatalf("afterGenerate hook: %v", err)
		}
	}
	model, err := pgBuildModel(raw)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("building old-version model: %v", err)
	}
	var preAudit int64
	if err := raw.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&preAudit); err != nil {
		_ = raw.Close()
		t.Fatalf("counting audit rows: %v", err)
	}
	var preDump []byte
	if stopAfter > 0 {
		if preDump, err = pgDumpDB(raw); err != nil {
			_ = raw.Close()
			t.Fatalf("dumping before interruption: %v", err)
		}
	}
	_ = raw.Close()

	var findings []ugFinding
	if stopAfter > 0 {
		reached, err := pgInterruptedMigrate(t, dsn, stopAfter, hooks.bareInterrupt)
		if err != nil {
			t.Fatalf("interrupted run: %v", err)
		}
		if reached {
			r := pgOpenRaw(t, dsn)
			post, err := pgDumpDB(r)
			_ = r.Close()
			if err != nil {
				t.Fatalf("dumping after interruption: %v", err)
			}
			if !bytes.Equal(preDump, post) {
				findings = append(findings, ugFinding{6, fmt.Sprintf("interrupted migration from %s (stopAfter=%d) changed the database: %s", tag, stopAfter, ugFirstDiff(preDump, post))})
			}
		}
	}

	st, err := NewStorageFactory().CreateStorage(pgLocalConfig(dsn))
	if err != nil {
		inv := 0
		if stopAfter > 0 {
			inv = 5
		}
		return append(findings, ugFinding{inv, fmt.Sprintf("CreateStorage on a %s database (stopAfter=%d): %s", tag, stopAfter, redactDSN(err))})
	}
	defer func() { _ = ugCloseStorage(st) }()

	r2 := pgOpenRaw(t, dsn)
	defer func() { _ = r2.Close() }()
	before, err := pgDumpDB(r2)
	if err != nil {
		t.Fatalf("dumping migrated database: %v", err)
	}
	if hooks.beforeRerun != nil {
		if err := hooks.beforeRerun(r2); err != nil {
			t.Fatalf("beforeRerun hook: %v", err)
		}
	}
	again, err := NewStorageFactory().CreateStorage(pgLocalConfig(dsn))
	if err != nil {
		findings = append(findings, ugFinding{4, fmt.Sprintf("second migration failed: %s", redactDSN(err))})
	} else {
		_ = ugCloseStorage(again)
		after, err := pgDumpDB(r2)
		if err != nil {
			t.Fatalf("dumping re-migrated database: %v", err)
		}
		if !bytes.Equal(before, after) {
			findings = append(findings, ugFinding{4, "second migration changed the database: " + ugFirstDiff(before, after)})
		}
	}

	if hooks.afterMigrate != nil {
		if err := hooks.afterMigrate(r2); err != nil {
			t.Fatalf("afterMigrate hook: %v", err)
		}
	}
	fresh, err := pgFreshInstallSchema(t, base)
	if err != nil {
		t.Fatalf("building fresh-install schema: %v", err)
	}
	got, err := pgReadSchema(r2)
	if err != nil {
		t.Fatalf("reading migrated schema: %v", err)
	}
	for _, d := range pgSchemaDiff(tag, got, fresh) {
		findings = append(findings, ugFinding{d.invariant, fmt.Sprintf("schema differs from a fresh install after upgrading from %s: %s", tag, d.text)})
	}

	c := core.NewKeyorixCore(st)
	c.SetAuthEncryptor(tpl.enc)
	c.SetSecretValueEncryptor(tpl.enc)
	return append(findings, pgCheckOracles(t, tag, chainVerifiable, r2, c, tpl, exp, model, preAudit, len(data))...)
}

func pgOpenGorm(t testing.TB, dsn string) *gorm.DB {
	t.Helper()
	gdb, err := openPostgresGorm(&config.DatabaseConfig{DSN: dsn}, gormConfig())
	if err != nil {
		t.Fatalf("opening gorm: %v", redactDSN(err))
	}
	if raw, derr := gdb.DB(); derr == nil {
		raw.SetMaxOpenConns(2)
		t.Cleanup(func() { _ = raw.Close() })
	}
	return gdb
}

// pgCheckOracles is ugCheckOracles with PostgreSQL placeholders; see there.
func pgCheckOracles(t testing.TB, tag string, chainVerifiable bool, raw *sql.DB, c *core.KeyorixCore, tpl *pgTemplate, exp *ugExpect, model *ugModel, preAudit int64, probeOffset int) []ugFinding {
	t.Helper()
	var out []ugFinding
	fail := func(inv int, format string, args ...any) {
		out = append(out, ugFinding{inv, fmt.Sprintf(format, args...)})
	}
	ctx := t.Context()
	decryptRow := func(secret uint, project uint, version int) ([]byte, error) {
		var ct []byte
		if err := raw.QueryRow("SELECT encrypted_value FROM secret_versions WHERE secret_node_id = $1 AND version_number = $2", secret, version).Scan(&ct); err != nil {
			return nil, fmt.Errorf("reading version row: %w", err)
		}
		return tpl.enc.DecryptSecretWithAAD(ct, encryption.SecretAAD(secret, project, version))
	}
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
	total := len(model.Users) * len(ugProbePerms) * len(model.Scopes)
	stride := 1 + total/60 // round trips over a tunnel are the budget here, not CPU
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

// errPGInterrupted is the fail-stop error the interruption seam injects.
var errPGInterrupted = errors.New("upgrade-pg-fuzz: simulated crash")

// pgInterruptedMigrate fail-stops a migration at the stopAfter'th write-class
// gorm statement and every later one. It reports whether the stop was reached:
// a migration with fewer statements completes, and is not interrupted at all.
//
// bare=false is the path a real boot takes (withMigrationLockPooled's one
// transaction around migratePostgres). bare=true calls migrateDatabase directly,
// with no outer transaction: the shape of the SQLite leg's ugInterruptedMigrate bare option,
// kept to compare the two legs. That shape is not reachable in production: every
// real caller of migrateDatabase on Postgres goes through the lock.
func pgInterruptedMigrate(t testing.TB, dsn string, stopAfter int, bare bool) (bool, error) {
	t.Helper()
	gdb, err := openPostgresGorm(&config.DatabaseConfig{DSN: dsn}, gormConfig())
	if err != nil {
		return false, errors.New(redactDSN(err))
	}
	raw, err := gdb.DB()
	if err != nil {
		return false, err
	}
	defer func() { _ = raw.Close() }()
	seen := pgRegisterStop(t, gdb, stopAfter)
	f := &DefaultStorageFactory{}
	// The migration's own error return is expected; what matters is the state left.
	if bare {
		_ = f.migrateDatabase(gdb)
	} else {
		_ = withMigrationLockPooled(gdb, true, false, "", f.migratePostgres)
	}
	return seen.Load() >= int64(stopAfter), nil
}

// pgRegisterStop arms gdb to fail the stopAfter'th write-class statement and every
// later one, and returns the statement counter.
func pgRegisterStop(t testing.TB, gdb *gorm.DB, stopAfter int) *atomic.Int64 {
	t.Helper()
	var seen atomic.Int64
	stop := func(db *gorm.DB) {
		if seen.Add(1) >= int64(stopAfter) {
			_ = db.AddError(errPGInterrupted)
		}
	}
	for _, reg := range []error{
		gdb.Callback().Raw().Before("gorm:raw").Register("ug:stop_raw", stop),
		gdb.Callback().Create().Before("gorm:create").Register("ug:stop_create", stop),
		gdb.Callback().Update().Before("gorm:update").Register("ug:stop_update", stop),
		gdb.Callback().Delete().Before("gorm:delete").Register("ug:stop_delete", stop),
	} {
		if reg != nil {
			t.Fatalf("registering stop callback: %v", reg)
		}
	}
	return &seen
}

// pgSchema is the comparable shape of a database's schema.
type pgSchema struct {
	columns     map[string]string // "table.column" -> type/nullable/default
	constraints map[string]string // "table.name" -> kind and definition
	indexes     map[string]string // index name -> definition
}

func pgReadSchema(db *sql.DB) (*pgSchema, error) {
	s := &pgSchema{columns: map[string]string{}, constraints: map[string]string{}, indexes: map[string]string{}}
	rows, err := pgQueryRows(db, `SELECT table_name, column_name, data_type, udt_name, COALESCE(character_maximum_length::text,''),
		COALESCE(numeric_precision::text,''), COALESCE(numeric_scale::text,''), COALESCE(datetime_precision::text,''), is_nullable, COALESCE(column_default,'')
		FROM information_schema.columns WHERE table_schema = current_schema()`, 10)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		s.columns[r[0]+"."+r[1]] = strings.Join(r[2:], "|")
	}
	cons, err := pgQueryRows(db, pgConstraintsQ, 4)
	if err != nil {
		return nil, err
	}
	for _, c := range cons {
		s.constraints[c[0]+"."+c[1]] = c[2] + " " + c[3]
	}
	idx, err := pgQueryRows(db, pgIndexesQ, 3)
	if err != nil {
		return nil, err
	}
	for _, i := range idx {
		s.indexes[i[0]] = i[1] + " valid=" + i[2]
	}
	return s, nil
}

// pgSchemaDifference is one schema mismatch against a fresh install.
type pgSchemaDifference struct {
	invariant int
	key       string
	text      string
}

// pgSchemaIgnored is the documented ignore list for oracles 7 and 8, built by
// classifying every difference the first real run reported (W6, 2026-11-10; see
// docs/findings/2026-11-10-FINDING-pg-upgrade-schema-drift.md). A key is either
// global ("columns:table.column", "constraints:table.name", "indexes:name"),
// applied for every source, or scoped to one source tag
// ("v0.91.0|columns:table.column"), applied only when upgrading from that tag.
// The value is why the difference from a fresh install is expected. Anything that
// differs and is not listed is a finding, so a NEW drift (even on a tag that
// already has listed ones) still fires the oracle. Two broad reasons recur:
//
//   - no-column-drop policy: migrations never drop a column (UPGRADING.md 7,
//     rollback is restore), so a since-removed column survives on an upgraded
//     database while a fresh install never creates it ("only on upgraded");
//   - AutoMigrate-only objects: a column or index added to a model after a
//     release is created only by the fresh-install AutoMigrate tail, never by an
//     explicit migrate step, so a database first installed at an older release
//     never gains it on upgrade ("missing on upgraded"). Below the documented
//     v0.93.x upgrade floor this is out of support; within it the break-glass
//     reviewed_by index was this drift (#4091, fixed by #4100, so it is no longer
//     ignored here; schema_parity_guard_test.go guards the class).
var pgSchemaIgnored = map[string]string{
	// Stricter-on-upgrade, harmless, and already recorded for a fresh install in
	// the committed schema-epoch snapshots (epoch-8/9/10 postgres.txt show
	// nullable=YES): migrate_users.go adds the column NOT NULL DEFAULT false with a
	// safe backfill, while the model (models.go MFAEnrolmentRequired, no not-null
	// gorm tag) makes a fresh install nullable. Every row has a value either way.
	"columns:users.mfa_enrolment_required": "EXPECTED: migration adds NOT NULL DEFAULT false; AutoMigrate on a fresh install makes it nullable (see schema_epoch testdata). Stricter on upgrade, every row defaulted.",

	// Since-removed column retained by the no-drop policy; v0.95.x had it, v0.96
	// dropped it from the model, the migration leaves the old column in place.
	"v0.95.3|columns:notification_channels.url": "EXPECTED: column removed from the model after v0.95.x; migrations never drop columns, so it survives on an upgraded database and is absent from a fresh install.",

	// --- v0.91.0 is BELOW the documented v0.93.x upgrade floor (UPGRADING.md). ---
	// The machine-identity actor columns and their composite unique index, the
	// SSO PKCE code_verifier, and the pre-v0.91 session-token columns are all
	// AutoMigrate-only (or since-removed) objects with no backfill migration;
	// upgrading from v0.91.0 is out of support and these are expected there. They
	// are the same class as the SQLite leg's owner_machine_identity_id finding.
	"v0.91.0|columns:access_request_approvals.approver_machine_identity_id":  "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:access_requests.resolved_by_machine_identity_id":        "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:access_review_campaigns.closed_by_machine_identity_id":  "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:access_review_campaigns.created_by_machine_identity_id": "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:break_glass_activations.revoked_by_machine_identity_id": "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:machine_identities.created_by_machine_identity_id":      "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:project_invitations.invited_by_machine_identity_id":     "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:project_memberships.invited_by_machine_identity_id":     "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:secret_dependencies.created_by_machine_identity_id":     "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|columns:setup_tokens.created_by_machine_identity_id":            "below v0.93.x floor: AutoMigrate-only machine-identity actor column, no backfill migration.",
	"v0.91.0|indexes:ux_access_request_approver":                             "below v0.93.x floor: fresh unique index includes approver_machine_identity_id, a column absent on an upgraded v0.91.0 database (see above).",
	"v0.91.0|columns:sessions.encrypted_session_token":                       "below v0.93.x floor: pre-v0.91 session-token column removed from the model later; no-drop policy keeps it on upgrade.",
	"v0.91.0|columns:sessions.session_token_metadata":                        "below v0.93.x floor: pre-v0.91 session-token column removed from the model later; no-drop policy keeps it on upgrade.",
	"v0.91.0|columns:sso_login_states.code_verifier":                         "below v0.93.x floor: AutoMigrate-only SSO PKCE column (added v0.93), no backfill migration.",

	// v0.92.1 is also below the v0.93.x floor; it predates the SSO PKCE column.
	"v0.92.1|columns:sso_login_states.code_verifier": "below v0.93.x floor: AutoMigrate-only SSO PKCE column (added v0.93), no backfill migration.",
}

func pgSchemaDiff(tag string, got, want *pgSchema) []pgSchemaDifference {
	var out []pgSchemaDifference
	ignored := func(fullKey string) bool {
		if _, ok := pgSchemaIgnored[fullKey]; ok {
			return true
		}
		_, ok := pgSchemaIgnored[tag+"|"+fullKey]
		return ok
	}
	add := func(kind string, inv int, gm, wm map[string]string) {
		keys := map[string]bool{}
		for k := range gm {
			keys[k] = true
		}
		for k := range wm {
			keys[k] = true
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			if ignored(kind + ":" + k) {
				continue
			}
			g, gok := gm[k]
			w, wok := wm[k]
			switch {
			case gok && !wok:
				out = append(out, pgSchemaDifference{inv, kind + ":" + k, fmt.Sprintf("%s %s only on the upgraded database: %s", kind, k, g)})
			case wok && !gok:
				out = append(out, pgSchemaDifference{inv, kind + ":" + k, fmt.Sprintf("%s %s missing on the upgraded database (fresh has: %s)", kind, k, w)})
			case g != w:
				out = append(out, pgSchemaDifference{inv, kind + ":" + k, fmt.Sprintf("%s %s differs: upgraded %s, fresh %s", kind, k, g, w)})
			}
		}
	}
	add("columns", 7, got.columns, want.columns)
	add("constraints", 8, got.constraints, want.constraints)
	add("indexes", 8, got.indexes, want.indexes)
	return out
}

// pgFreshInstallSchema reads the schema a fresh install of this tree creates,
// once per process; the database is dropped straight after.
func pgFreshInstallSchema(t testing.TB, base string) (*pgSchema, error) {
	t.Helper()
	pgFreshOnce.Do(func() {
		name := fmt.Sprintf("w6_fresh_%d", os.Getpid())
		admin, err := sql.Open("pgx", pgSimpleProtocolDSN(base))
		if err != nil {
			pgFreshErr = errors.New(redactDSN(err))
			return
		}
		defer func() { _ = admin.Close() }()
		if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
			pgFreshErr = errors.New(redactDSN(err))
			return
		}
		defer func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)") }()
		dsn := pgdsn.PGReplaceDBName(base, name)
		st, err := NewStorageFactory().CreateStorage(pgLocalConfig(dsn))
		if err != nil {
			pgFreshErr = errors.New(redactDSN(err))
			return
		}
		defer func() { _ = ugCloseStorage(st) }()
		raw, err := sql.Open("pgx", pgSimpleProtocolDSN(dsn))
		if err != nil {
			pgFreshErr = errors.New(redactDSN(err))
			return
		}
		defer func() { _ = raw.Close() }()
		pgFreshSchema, pgFreshErr = pgReadSchema(raw)
	})
	return pgFreshSchema, pgFreshErr
}

func pgSeeds() [][]byte { return ugSeeds()[:5] } // fewer than the SQLite leg: each exec is a server round trip budget

// pgInterruptibleFrom is 0: this leg interrupts every source, because on
// PostgreSQL the real path is one transaction (oracle 6). The SQLite leg does the
// same since its interruption also goes through withMigrationLock.
const pgInterruptibleFrom = 0

// FuzzUpgradePGFromOldSchema upgrades generated state on a real old PostgreSQL
// schema with the real startup path. See the file comment for the oracles.
func FuzzUpgradePGFromOldSchema(f *testing.F) {
	for i := range ugSources {
		for _, s := range pgSeeds() {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		if len(data) > 400 {
			t.Skip("over the generator's useful input size")
		}
		idx := int(sel) % len(ugSources)
		for _, fnd := range pgRun(t, ugSources[idx], idx >= ugChainFrom, data, 0, pgHooks{}) {
			t.Error(fnd)
		}
	})
}

// FuzzUpgradePGInterrupted stops the upgrade after a fuzz-chosen write statement
// and asserts the rollback was total and the restart completes it.
func FuzzUpgradePGInterrupted(f *testing.F) {
	sources := ugSources[pgInterruptibleFrom:]
	for i := range sources {
		for _, stop := range []uint16{1, 2, 7, 41, 83, 150} {
			f.Add(uint8(i), stop, []byte{byte(i), byte(stop)})
		}
	}
	f.Fuzz(func(t *testing.T, sel uint8, stop uint16, data []byte) {
		if len(data) > 400 {
			t.Skip("over the generator's useful input size")
		}
		idx := int(sel) % len(sources)
		for _, fnd := range pgRun(t, sources[idx], idx+pgInterruptibleFrom >= ugChainFrom, data, int(stop%240)+1, pgHooks{}) {
			t.Error(fnd)
		}
	})
}
