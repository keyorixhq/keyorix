package store_test

// GM1 — tenant-isolation execution oracle (the result side of the gorm-identifier
// campaign; the statement-shape side is FuzzGormListSQLShape in
// gorm_identifier_fuzz_test.go).
//
// Where the shape oracle proves no caller byte reaches the SQL text and the
// project predicate is present+bound, this one executes the real ListSecrets
// against a MIGRATED store seeded with two tenants and asserts the property that
// actually matters to a user: a project-scoped list NEVER returns another
// project's row, no matter what hostile sort/search/classification/type the caller
// supplies. It runs on SQLite always and on PostgreSQL when $KEYORIX_TEST_PG_DSN
// is set, and requires the two backends to agree on the error class (both nil /
// both error) — a differential on the live result, not just the built SQL.
//
// Oracle soundness: the assertion is an independent reference (the seeded
// ground-truth project id of every row), not "did not panic". RED/GREEN:
// TestGormTenantIsolation_RedGreen plants a no-scope query that leaks the
// other tenant's canary row and shows assertOnlyProject fires on it while staying
// green on the real ListSecrets.
//
// What it does NOT verify: authorization above the storage layer (the core
// permission model that decides whether the caller may scope to project 1 at
// all); leakage through read paths other than ListSecrets; and ordering (row
// order without a total order is engine-defined and not asserted).

import (
	"context"
	"os"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	storage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

const (
	isoProject1    uint   = 1
	isoProject2    uint   = 2
	isoEnv1        uint   = 1
	isoEnv2        uint   = 2
	isoTenant2Name string = "TENANT2CANARY"
)

// seedTwoTenants writes two projects' worth of rows: environments 1/2 bound to
// projects 1/2 and three secrets in each. Project 2's secrets carry the canary
// name so a leak is unmistakable. Direct model Create is deliberate — this is a
// storage-layer isolation test, below the business create path.
func seedTwoTenants(t testing.TB, db *gorm.DB) {
	t.Helper()
	envs := []models.Environment{
		{ID: isoEnv1, ProjectID: isoProject1, Name: "env1"},
		{ID: isoEnv2, ProjectID: isoProject2, Name: "env2"},
	}
	if err := db.Create(&envs).Error; err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	secrets := []models.SecretNode{
		{ProjectID: isoProject1, EnvironmentID: isoEnv1, Name: "p1-alpha", IsSecret: true, Type: "password", Classification: "internal"},
		{ProjectID: isoProject1, EnvironmentID: isoEnv1, Name: "p1-beta", IsSecret: true, Type: "token", Classification: "confidential"},
		{ProjectID: isoProject1, EnvironmentID: isoEnv1, Name: "p1-" + isoTenant2Name, IsSecret: true, Type: "password"}, // same canary word, but project 1
		{ProjectID: isoProject2, EnvironmentID: isoEnv2, Name: isoTenant2Name, IsSecret: true, Type: "password", Classification: "restricted"},
		{ProjectID: isoProject2, EnvironmentID: isoEnv2, Name: isoTenant2Name + "-2", IsSecret: true, Type: "token", Classification: "restricted"},
	}
	if err := db.Create(&secrets).Error; err != nil {
		t.Fatalf("seed secrets: %v", err)
	}
}

// assertOnlyProject is the independent reference: every returned row must belong
// to the requested project. Returns an error (testable) rather than failing, so
// the red/green proof can drive it on a leaking query.
func assertOnlyProject(backend string, rows []*models.SecretNode, want uint) error {
	for _, r := range rows {
		if r.ProjectID != want {
			return isoLeak(backend, r, want)
		}
	}
	return nil
}

func isoLeak(backend string, r *models.SecretNode, want uint) error {
	return &isoLeakErr{backend: backend, name: r.Name, got: r.ProjectID, want: want}
}

type isoLeakErr struct {
	backend string
	name    string
	got     uint
	want    uint
}

func (e *isoLeakErr) Error() string {
	return "[" + e.backend + "] TENANT LEAK: row " + e.name + " belongs to another project (got project_id " +
		itoa(e.got) + ", scope was " + itoa(e.want) + ")"
}

// isPGTextEncodingReject reports whether err is PostgreSQL's SQLSTATE 22021
// rejection of a bound string carrying an invalid UTF-8 byte sequence or an
// embedded NUL — the named "pg-text-encoding-reject" EXPECTED-DIFFERENCE class.
// It fails closed, so it is not a tenant-isolation concern.
func isPGTextEncodingReject(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "invalid byte sequence for encoding") || strings.Contains(m, "22021")
}

func itoa(u uint) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// isoHostileFilter builds a project-1-scoped filter whose free-text fields carry
// the fuzz payload, including the other tenant's canary name in Search — the most
// natural "make the query match project 2's rows" attempt.
func isoHostileFilter(payload string) *storage.SecretFilter {
	p1 := isoProject1
	search := payload + isoTenant2Name // bias toward matching the canary
	return &storage.SecretFilter{
		ProjectID:      &p1,
		Type:           ptr(payload),
		Classification: ptr(payload),
		Search:         &search,
		Page:           1,
		PageSize:       100,
	}
}

func FuzzGormListTenantIsolation(f *testing.F) {
	f.Add("")
	f.Add("' OR '1'='1")
	f.Add("%")
	f.Add("restricted")
	f.Add("') UNION SELECT * FROM secret_nodes WHERE ('1'='1")
	f.Add(isoTenant2Name)
	f.Add("\\")

	// --- SQLite backend (migrated through the real production factory) ---
	sqliteDSN := sqlitetest.DSN("gm1iso_")
	if err := createStorageClosedAtCleanup(f, &config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqliteDSN}},
	}); err != nil {
		f.Fatalf("sqlite production migration: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if s, e := sdb.DB(); e == nil {
		s.SetMaxOpenConns(1)
	}
	sls := store.NewLocalStorage(sdb)
	seedOnce(f, sdb)

	// --- PostgreSQL backend, isolated schema, when a DSN is present ---
	var pls *store.LocalStorage
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN != "" {
		schema := "gm1iso_" + itoa(uint(os.Getpid())) + "_" + itoa(uint(pgSchemaSeq.Add(1)))
		admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			f.Fatalf("open pg admin: %v", err)
		}
		if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
			f.Fatalf("pg drop schema: %v", err)
		}
		if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			f.Fatalf("pg create schema: %v", err)
		}
		f.Cleanup(func() {
			if c, e := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
				_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
			}
		})
		pgTargetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)
		if err := createStorageClosedAtCleanup(f, &config.Config{
			Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgTargetDSN}},
		}); err != nil {
			f.Fatalf("pg production migration: %v", err)
		}
		pdb, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			f.Fatalf("open pg: %v", err)
		}
		if p, e := pdb.DB(); e == nil {
			p.SetMaxOpenConns(1)
		}
		pls = store.NewLocalStorage(pdb)
		seedOnce(f, pdb)
	}

	f.Fuzz(func(t *testing.T, payload string) {
		if len(payload) > 2048 {
			payload = payload[:2048]
		}
		ctx := context.Background()
		filter := isoHostileFilter(payload)

		sRows, _, sErr := sls.ListSecrets(ctx, filter)
		must(t, assertOnlyProject("sqlite", sRows, isoProject1))

		if pls != nil {
			pRows, _, pErr := pls.ListSecrets(ctx, filter)
			must(t, assertOnlyProject("pg", pRows, isoProject1))
			// Error-class agreement (both nil / both error) — a live differential —
			// EXCEPT the named EXPECTED-DIFFERENCE class "pg-text-encoding-reject":
			// a UTF8-encoded PostgreSQL server rejects a bound string that carries an
			// invalid byte sequence OR an embedded NUL (0x00) with SQLSTATE 22021,
			// while SQLite tolerates arbitrary bytes and returns a normal (empty)
			// result. NUL is itself valid UTF-8, so the exclusion keys on PG's error
			// class (the 22021 message) rather than guessing from the payload. PG
			// fails CLOSED (errors, returns no rows), so tenant isolation is
			// unaffected — assertOnlyProject ran unconditionally on both backends
			// above. Any OTHER error-class divergence still fails. See
			// gorm_identifier_EXPECTED_DIFFERENCE.md.
			if (sErr == nil) != (pErr == nil) && !isPGTextEncodingReject(pErr) {
				t.Fatalf("DIFF: NEW error-class divergence listing project %d with payload=%q: sqliteErr=%v pgErr=%v",
					isoProject1, payload, sErr, pErr)
			}
		}
	})
}

// seedOnce guards against a double-seed if the harness is re-entered.
func seedOnce(t testing.TB, db *gorm.DB) {
	var n int64
	if err := db.Model(&models.Environment{}).Count(&n).Error; err == nil && n > 0 {
		return
	}
	seedTwoTenants(t, db)
}

// --- RED/GREEN proof ----------------------------------------------------------

// vulnerableNoScopeList is the mistake the isolation oracle guards against: a
// name search with NO project predicate, so it returns every tenant's matching
// rows. Used only to prove assertOnlyProject is non-vacuous.
func vulnerableNoScopeList(ls *store.LocalStorage, name string) []*models.SecretNode {
	var rows []*models.SecretNode
	_ = ls.DB().WithContext(context.Background()).
		Model(&models.SecretNode{}).
		Where("name LIKE ?", "%"+name+"%").
		Find(&rows).Error
	return rows
}

func TestGormTenantIsolation_RedGreen(t *testing.T) {
	dsn := sqlitetest.DSN("gm1isorg_")
	if err := createStorageClosedAtCleanup(t, &config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dsn}},
	}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if s, e := db.DB(); e == nil {
		s.SetMaxOpenConns(1)
	}
	seedTwoTenants(t, db)
	ls := store.NewLocalStorage(db)

	// GREEN: the real, project-1-scoped ListSecrets returns only project-1 rows,
	// even with a search that explicitly targets the other tenant's canary name.
	rows, _, err := ls.ListSecrets(context.Background(), isoHostileFilter(""))
	if err != nil {
		t.Fatalf("real ListSecrets errored: %v", err)
	}
	if e := assertOnlyProject("real", rows, isoProject1); e != nil {
		t.Fatalf("real ListSecrets must be tenant-isolated, got: %v", e)
	}

	// RED: a no-scope query leaks project 2's canary; assertOnlyProject must fire.
	leaked := vulnerableNoScopeList(ls, isoTenant2Name)
	if len(leaked) == 0 {
		t.Fatalf("red-proof setup broken: no-scope query returned nothing")
	}
	if e := assertOnlyProject("vuln", leaked, isoProject1); e == nil {
		t.Fatalf("assertOnlyProject FAILED to fire on a cross-tenant leak of %d rows", len(leaked))
	}
}
