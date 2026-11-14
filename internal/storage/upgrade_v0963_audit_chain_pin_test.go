package storage

// Pins one upgrade path (UPGRADE-PATH-FIXES-1 item 4): the pristine v0.96.3 snapshot
// (testdata/upgrade-snapshots[-pg]/v0.96.3, written by that release's own core), migrated
// by this tree's real startup path (NewStorageFactory().CreateStorage), has an audit chain
// that VerifyAuditChain accepts.
//
// FuzzUpgradeFromOldSchema and its Postgres twin already check this on top of generated
// state; these two tests state it once, on the snapshot alone, with no generated rows and
// no fuzz seed that could drift away from v0.96.3. They also refuse a vacuous pass: the
// snapshot must hold chained audit rows, and none may be unchained afterwards.
//
// Not covered: the rest of the oracles (secrets, authorization, idempotence, schema
// parity), which the fuzz targets own, and any release other than v0.96.3.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const v0963 = "v0.96.3"

func TestUpgradeV0963_AuditChainVerifiesAfterMigration_SQLite(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	tpl, err := ugLoadTemplate(v0963)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", v0963, err)
	}
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")
	if err := ugCopyFile(tpl.dbFile, dbPath); err != nil {
		t.Fatalf("copying template: %v", err)
	}
	raw, _, closeRaw := ugOpenRaw(t, dbPath)
	var pre int64
	if err := raw.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&pre); err != nil {
		closeRaw()
		t.Fatalf("counting audit rows: %v", err)
	}
	closeRaw()
	if pre == 0 {
		t.Fatalf("the %s snapshot holds no audit rows: the pin would pass vacuously", v0963)
	}

	st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
	if err != nil {
		t.Fatalf("CreateStorage on the %s snapshot: %v", v0963, err)
	}
	defer func() { _ = ugCloseStorage(st) }()

	res, err := core.NewKeyorixCore(st).VerifyAuditChain(t.Context())
	if err != nil {
		t.Fatalf("VerifyAuditChain after migrating the %s snapshot: %v", v0963, err)
	}
	if !res.Valid {
		t.Fatalf("audit chain of the %s snapshot is broken after migration: first broken id=%v (%d chained, %d unchained)",
			v0963, res.FirstBrokenID, res.ChainedEvents, res.UnchainedEvents)
	}
	if int64(res.ChainedEvents) < pre {
		t.Errorf("only %d chained audit events verified, the snapshot had %d rows: rows were lost or left unchained", res.ChainedEvents, pre)
	}
	if res.UnchainedEvents != 0 {
		t.Errorf("%d audit events unchained after migrating the %s snapshot", res.UnchainedEvents, v0963)
	}
}

// Calibration: the same path with one audit row edited in the snapshot copy must NOT
// verify, or a green TestUpgradeV0963_AuditChainVerifiesAfterMigration_SQLite would
// only mean VerifyAuditChain accepts everything.
func TestUpgradeV0963_AuditChainVerifiesAfterMigration_SQLite_CalibrationTamperedRow(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	tpl, err := ugLoadTemplate(v0963)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", v0963, err)
	}
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")
	if err := ugCopyFile(tpl.dbFile, dbPath); err != nil {
		t.Fatalf("copying template: %v", err)
	}
	raw, _, closeRaw := ugOpenRaw(t, dbPath)
	r, err := raw.Exec("UPDATE audit_events SET description = description || ' tampered' WHERE id = (SELECT MIN(id) + 3 FROM audit_events)")
	if err != nil {
		closeRaw()
		t.Fatalf("tampering with an audit row: %v", err)
	}
	if n, _ := r.RowsAffected(); n != 1 {
		closeRaw()
		t.Fatalf("tamper touched %d rows, want 1: the calibration is not exercising a chained row", n)
	}
	closeRaw()

	st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
	if err != nil {
		t.Fatalf("CreateStorage on the tampered %s snapshot: %v", v0963, err)
	}
	defer func() { _ = ugCloseStorage(st) }()
	res, err := core.NewKeyorixCore(st).VerifyAuditChain(t.Context())
	if err == nil && res.Valid {
		t.Fatalf("VerifyAuditChain accepted a chain with an edited row (%d chained, %d unchained): the pin above proves nothing", res.ChainedEvents, res.UnchainedEvents)
	}
}

func TestUpgradeV0963_AuditChainVerifiesAfterMigration_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	if _, err := os.Stat(filepath.Join(pgSnapshotDir, v0963, "snapshot.sql")); err != nil {
		t.Skipf("no PostgreSQL snapshot for %s: %v", v0963, err)
	}
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	tpl, err := pgLoadTemplate(v0963)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", v0963, err)
	}
	_, dsn := pgCreateDatabase(t, base)
	raw := pgOpenRaw(t, dsn)
	if _, err := raw.Exec(strings.ReplaceAll(tpl.script, pgStmtSep, ";\n")); err != nil {
		_ = raw.Close()
		t.Fatalf("replaying %s snapshot: %v", v0963, redactDSN(err))
	}
	var pre int64
	if err := raw.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&pre); err != nil {
		_ = raw.Close()
		t.Fatalf("counting audit rows: %v", err)
	}
	_ = raw.Close()
	if pre == 0 {
		t.Fatalf("the %s snapshot holds no audit rows: the pin would pass vacuously", v0963)
	}

	st, err := NewStorageFactory().CreateStorage(pgLocalConfig(dsn))
	if err != nil {
		t.Fatalf("CreateStorage on the %s snapshot: %s", v0963, redactDSN(err))
	}
	defer func() { _ = ugCloseStorage(st) }()

	res, err := core.NewKeyorixCore(st).VerifyAuditChain(t.Context())
	if err != nil {
		t.Fatalf("VerifyAuditChain after migrating the %s snapshot: %v", v0963, err)
	}
	if !res.Valid {
		t.Fatalf("audit chain of the %s snapshot is broken after migration: first broken id=%v (%d chained, %d unchained)",
			v0963, res.FirstBrokenID, res.ChainedEvents, res.UnchainedEvents)
	}
	if int64(res.ChainedEvents) < pre {
		t.Errorf("only %d chained audit events verified, the snapshot had %d rows: rows were lost or left unchained", res.ChainedEvents, pre)
	}
	if res.UnchainedEvents != 0 {
		t.Errorf("%d audit events unchained after migrating the %s snapshot", res.UnchainedEvents, v0963)
	}
}
