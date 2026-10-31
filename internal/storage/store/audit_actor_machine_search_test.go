package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// #3736: the actor search must find a machine identity by the name the ACTOR
// column shows, not only users.username.

func newActorMachineSQLiteStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "auditactormachine_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MachineIdentity{}, &models.AuditEvent{}))
	return NewLocalStorage(db)
}

func newActorMachinePGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL-only test")
	}
	schema := "audit_actor_machine_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.MachineIdentity{}, &models.AuditEvent{}))
	return NewLocalStorage(db)
}

func runActorMachineSearch(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	ci := &models.MachineIdentity{Name: "payments-ci", State: "active", ProjectID: 1}
	other := &models.MachineIdentity{Name: "billing-bot", State: "active", ProjectID: 1}
	require.NoError(t, ls.db.Create(ci).Error)
	require.NoError(t, ls.db.Create(other).Error)
	dana := &models.User{Username: "dana", Email: "dana@example.com", PasswordHash: "x"}
	require.NoError(t, ls.db.Create(dana).Error)

	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.read", ActorType: "machine_identity", MachineIdentityID: &ci.ID,
		IPAddress: "10.0.0.1", EventTime: now.Add(time.Second),
	}))
	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.read", ActorType: "machine_identity", MachineIdentityID: &other.ID,
		IPAddress: "10.0.0.2", EventTime: now.Add(2 * time.Second),
	}))
	require.NoError(t, ls.LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.read", ActorType: "user", UserID: &dana.ID,
		IPAddress: "10.0.0.3", EventTime: now.Add(3 * time.Second),
	}))

	search := func(term string) []*models.AuditEvent {
		t.Helper()
		events, total, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorUsername: &term, PageSize: 50})
		require.NoError(t, err, term)
		assert.EqualValues(t, len(events), total, term)
		return events
	}

	for _, term := range []string{"payments-ci", "PAYMENTS", "ci"} {
		got := search(term)
		require.Len(t, got, 1, "term %q", term)
		assert.Equal(t, ci.ID, *got[0].MachineIdentityID, "term %q", term)
		assert.Equal(t, "secret.read", got[0].EventType)
	}

	assert.Empty(t, search("nobody-here"), "unrelated name finds nothing")

	// % and _ are literals: neither widens the match to every name.
	assert.Empty(t, search("%"), "a bare % must not match every identity")
	assert.Empty(t, search("payments_ci"), "_ must not match the - in payments-ci")
	assert.Empty(t, search("pay%ci"), "% must not act as a wildcard")

	// Users still match, and only users.
	got := search("dana")
	require.Len(t, got, 1)
	assert.Equal(t, dana.ID, *got[0].UserID)
}

func TestGetAuditLogs_ActorSearchMatchesMachineIdentity_SQLite(t *testing.T) {
	runActorMachineSearch(t, newActorMachineSQLiteStore(t))
}

func TestGetAuditLogs_ActorSearchMatchesMachineIdentity_Postgres(t *testing.T) {
	runActorMachineSearch(t, newActorMachinePGStore(t))
}
