package store

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// AUDIT-SEARCH-PARITY-1 (#4090): the audit search string filters must return the
// same rows on SQLite and PostgreSQL. The resource_type filter was
// "event_type LIKE 'x.%'", case-insensitive on SQLite and case-sensitive on
// PostgreSQL. The single rule is: event types are lower-case constants, so the
// filter is matched case-sensitively (a differently cased value is a caller
// error and matches nothing) on both backends. The same tables run on SQLite
// always and on PostgreSQL when KEYORIX_TEST_PG_DSN is set.

func newAuditParitySQLiteStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "auditparity_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}, &models.MachineIdentity{}))
	return NewLocalStorage(db)
}

func newAuditParityPGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL leg of the audit filter parity test")
	}
	schema := "audit_filter_case_parity_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}, &models.MachineIdentity{}))
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return NewLocalStorage(db)
}

func seedAuditParityRows(t *testing.T, ls *LocalStorage) {
	t.Helper()
	tru := true
	reqID := "Req-ABC"
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, e := range []models.AuditEvent{
		{EventType: "secret.read", IPAddress: "10.0.0.A", RequestID: &reqID},
		{EventType: "secret_backup.read"},
		{EventType: "secretx.read"},
		{EventType: "user.login"},
	} {
		e.ActorType = "user"
		if e.EventType == "secretx.read" {
			e.ActorType = "admin_cli"
		}
		e.Success = &tru
		e.EventTime = base.Add(time.Duration(i) * time.Second)
		require.NoError(t, ls.db.Create(&e).Error)
	}
}

func auditParityEventTypes(t *testing.T, ls *LocalStorage, f storage.AuditFilter) []string {
	t.Helper()
	f.PageSize = 100
	got, _, err := ls.GetAuditLogs(context.Background(), &f)
	require.NoError(t, err)
	var types []string
	for _, e := range got {
		types = append(types, e.EventType)
	}
	sort.Strings(types)
	return types
}

func runAuditResourceTypeParity(t *testing.T, ls *LocalStorage) {
	t.Helper()
	seedAuditParityRows(t, ls)
	cases := []struct {
		name, rt string
		want     []string
	}{
		{"lower case matches the prefix", "secret", []string{"secret.read"}},
		{"upper case is a caller error", "SECRET", nil},
		{"mixed case is a caller error", "Secret", nil},
		{"underscore is literal", "secret_backup", []string{"secret_backup.read"}},
		{"underscore is not a wildcard", "secret_b_ckup", nil},
		{"percent is literal", "sec%", nil},
		{"star is literal", "secret*", nil},
		{"question mark is literal", "s?cret", nil},
		{"bracket class is literal", "[s]ecret", nil},
		{"prefix without the dot boundary", "secre", nil},
		{"other resource", "user", []string{"user.login"}},
	}
	for _, c := range cases {
		rt := c.rt
		got := auditParityEventTypes(t, ls, storage.AuditFilter{ResourceType: &rt})
		assert.Equal(t, c.want, got, "%s (resource_type %q)", c.name, c.rt)
	}
}

func TestAuditResourceTypeCaseParity_SQLite(t *testing.T) {
	runAuditResourceTypeParity(t, newAuditParitySQLiteStore(t))
}

func TestAuditResourceTypeCaseParity_Postgres(t *testing.T) {
	runAuditResourceTypeParity(t, newAuditParityPGStore(t))
}
