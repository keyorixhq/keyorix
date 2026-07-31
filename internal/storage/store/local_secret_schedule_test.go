// local_secret_schedule_test.go — store-layer tests for LocalStorage SecretAccessSchedule.
//
// These tests exercise GetSecretAccessSchedule, SetSecretAccessSchedule, and
// DeleteSecretAccessSchedule at the store layer, including DB-error branches.
package store

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var schedStoreCounter atomic.Uint64

// newScheduleStore returns a LocalStorage + DB for schedule store tests,
// with the SecretAccessSchedule (and SecretNode, for FK) tables migrated
// and a seed SecretNode inserted.
func newScheduleStore(t *testing.T) (*LocalStorage, *gorm.DB, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := schedStoreCounter.Add(1)
	dsn := fmt.Sprintf("file:kxstore_sched_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretAccessSchedule{}))

	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "sched-store-secret", IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)

	return NewLocalStorage(db), db, s.ID
}

// ── GetSecretAccessSchedule ───────────────────────────────────────────────────

// TestLocalSchedule_GetNotFound returns nil, nil when no row exists.
func TestLocalSchedule_GetNotFound(t *testing.T) {
	ls, _, _ := newScheduleStore(t)
	got, err := ls.GetSecretAccessSchedule(context.Background(), 9999)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestLocalSchedule_GetDBError returns a wrapped error when the table is gone.
func TestLocalSchedule_GetDBError(t *testing.T) {
	ls, db, sid := newScheduleStore(t)
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_access_schedules").Error)

	_, err := ls.GetSecretAccessSchedule(context.Background(), sid)
	require.Error(t, err)
}

// TestLocalSchedule_GetExisting returns the row when it exists.
func TestLocalSchedule_GetExisting(t *testing.T) {
	ls, db, sid := newScheduleStore(t)
	require.NoError(t, db.Create(&models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}).Error)

	got, err := ls.GetSecretAccessSchedule(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "1,2,3,4,5", got.AllowedDays)
	assert.Equal(t, 9, got.StartHour)
	assert.Equal(t, 17, got.EndHour)
	assert.Equal(t, "UTC", got.Timezone)
}

// ── SetSecretAccessSchedule ───────────────────────────────────────────────────

// TestLocalSchedule_SetCreate inserts a new schedule when none exists.
func TestLocalSchedule_SetCreate(t *testing.T) {
	ls, _, sid := newScheduleStore(t)
	sched := &models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}
	require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), sched))
	assert.NotZero(t, sched.ID)

	got, err := ls.GetSecretAccessSchedule(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "1,2,3,4,5", got.AllowedDays)
}

// TestLocalSchedule_SetUpdate upserts fields on an existing row.
func TestLocalSchedule_SetUpdate(t *testing.T) {
	ls, _, sid := newScheduleStore(t)
	// Create initial schedule.
	require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	}))
	// Update with new hours.
	require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "America/New_York",
	}))

	// There should still be exactly one row, with the updated values.
	got, err := ls.GetSecretAccessSchedule(context.Background(), sid)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "*", got.AllowedDays)
	assert.Equal(t, "America/New_York", got.Timezone)
}

// TestLocalSchedule_SetDBError returns a wrapped error when the table is gone.
func TestLocalSchedule_SetDBError(t *testing.T) {
	ls, db, sid := newScheduleStore(t)
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_access_schedules").Error)

	err := ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "1,2,3,4,5", StartHour: 9, EndHour: 17, Timezone: "UTC",
	})
	require.Error(t, err)
}

// ── DeleteSecretAccessSchedule ────────────────────────────────────────────────

// TestLocalSchedule_Delete removes an existing schedule row.
func TestLocalSchedule_Delete(t *testing.T) {
	ls, _, sid := newScheduleStore(t)
	require.NoError(t, ls.SetSecretAccessSchedule(context.Background(), &models.SecretAccessSchedule{
		SecretNodeID: sid, AllowedDays: "*", StartHour: 0, EndHour: 24, Timezone: "UTC",
	}))

	require.NoError(t, ls.DeleteSecretAccessSchedule(context.Background(), sid))

	got, err := ls.GetSecretAccessSchedule(context.Background(), sid)
	require.NoError(t, err)
	assert.Nil(t, got, "row must be absent after deletion")
}

// TestLocalSchedule_DeleteIdempotent returns nil when no schedule exists.
func TestLocalSchedule_DeleteIdempotent(t *testing.T) {
	ls, _, _ := newScheduleStore(t)
	// No schedule has been created — Delete must return nil (idempotent).
	require.NoError(t, ls.DeleteSecretAccessSchedule(context.Background(), 9999))
}

// TestLocalSchedule_DeleteDBError returns a wrapped error when the table is gone.
func TestLocalSchedule_DeleteDBError(t *testing.T) {
	ls, db, sid := newScheduleStore(t)
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS secret_access_schedules").Error)

	err := ls.DeleteSecretAccessSchedule(context.Background(), sid)
	require.Error(t, err)
}
