package store

// STORE-LOCKS-NOV-1 item 3 (STALE-ROW-WRITES leftover): SetSecretAccessSchedule was
// FirstOrCreate + Assign followed by a full-row Save when the found row's UPDATE matched
// nothing. A schedule deleted by another replica between FirstOrCreate's read and its
// UPDATE was then brought back by the Save (UPDATE by id, zero rows, so GORM falls back to
// INSERT ... ON CONFLICT (id) DO UPDATE with the stale struct: the deleted row's id and
// created_at). A schedule deleted and re-created in that window made the Save collide on
// the secret_node_id unique index and the set failed. The struct-form Assign also dropped
// zero values, so moving an existing window's start hour to 0 was silently not written.
//
// Each test parks pool A's first UPDATE of secret_access_schedules (a gorm callback) and
// runs the concurrent writer on pool B there. Both backends: sqlite, and postgres with two
// pools (skips without KEYORIX_TEST_PG_DSN).

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newScheduleInterleaveEnv(t *testing.T, backend string) *interleaveEnv {
	t.Helper()
	env := newInterleaveEnv(t, backend)
	require.NoError(t, env.db.AutoMigrate(&models.SecretAccessSchedule{}))
	return env
}

// beforeFirstScheduleUpdate runs fn once, on pool A, just before A's first UPDATE of
// secret_access_schedules opens its statement transaction (so it holds no lock yet).
func beforeFirstScheduleUpdate(t *testing.T, ls *LocalStorage, fn func()) {
	t.Helper()
	var once sync.Once
	require.NoError(t, ls.db.Callback().Update().Before("gorm:begin_transaction").Register("test:schedule_interleave", func(tx *gorm.DB) {
		if tx.Statement.Table == "secret_access_schedules" {
			once.Do(fn)
		}
	}))
}

func TestSetSecretAccessSchedule_ConcurrentDeleteIsNotRevived(t *testing.T) {
	for _, backend := range interleaveBackends {
		t.Run(backend, func(t *testing.T) {
			env := newScheduleInterleaveEnv(t, backend)
			ctx := context.Background()
			seed := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "*", StartHour: 9, EndHour: 17, Timezone: "UTC"}
			require.NoError(t, env.db.Create(seed).Error)

			beforeFirstScheduleUpdate(t, env.a, func() {
				require.NoError(t, env.b.DeleteSecretAccessSchedule(ctx, 7))
			})
			set := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "1,2,3,4,5", StartHour: 8, EndHour: 18, Timezone: "UTC"}
			require.NoError(t, env.a.SetSecretAccessSchedule(ctx, set))

			var revived int64
			require.NoError(t, env.db.Model(&models.SecretAccessSchedule{}).Where("id = ?", seed.ID).Count(&revived).Error)
			assert.Zero(t, revived, "the schedule row deleted by B was written back under its old id by A's full-row Save")

			// The set lands after the delete, so it creates a new schedule with A's window.
			var rows []models.SecretAccessSchedule
			require.NoError(t, env.db.Where("secret_node_id = ?", 7).Find(&rows).Error)
			require.Len(t, rows, 1)
			assert.Equal(t, "1,2,3,4,5", rows[0].AllowedDays)
			assert.Equal(t, 8, rows[0].StartHour)
			assert.Equal(t, rows[0].ID, set.ID, "the caller's struct names the row actually written")
		})
	}
}

func TestSetSecretAccessSchedule_DeleteAndRecreateBetweenReadAndWrite(t *testing.T) {
	for _, backend := range interleaveBackends {
		t.Run(backend, func(t *testing.T) {
			env := newScheduleInterleaveEnv(t, backend)
			ctx := context.Background()
			seed := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "*", StartHour: 9, EndHour: 17, Timezone: "UTC"}
			require.NoError(t, env.db.Create(seed).Error)

			beforeFirstScheduleUpdate(t, env.a, func() {
				require.NoError(t, env.b.DeleteSecretAccessSchedule(ctx, 7))
				require.NoError(t, env.b.SetSecretAccessSchedule(ctx, &models.SecretAccessSchedule{
					SecretNodeID: 7, AllowedDays: "6,7", StartHour: 10, EndHour: 12, Timezone: "UTC"}))
			})
			set := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "1,2,3,4,5", StartHour: 8, EndHour: 18, Timezone: "Europe/Berlin"}
			require.NoError(t, env.a.SetSecretAccessSchedule(ctx, set), "A's set lands after B's re-create and must update that row, not collide with it")

			var rows []models.SecretAccessSchedule
			require.NoError(t, env.db.Where("secret_node_id = ?", 7).Find(&rows).Error)
			require.Len(t, rows, 1)
			assert.NotEqual(t, seed.ID, rows[0].ID, "the deleted row came back")
			assert.Equal(t, "1,2,3,4,5", rows[0].AllowedDays)
			assert.Equal(t, 8, rows[0].StartHour)
			assert.Equal(t, 18, rows[0].EndHour)
			assert.Equal(t, "Europe/Berlin", rows[0].Timezone)
		})
	}
}

func TestSetSecretAccessSchedule_ZeroStartHourIsWritten(t *testing.T) {
	for _, backend := range interleaveBackends {
		t.Run(backend, func(t *testing.T) {
			env := newScheduleInterleaveEnv(t, backend)
			ctx := context.Background()
			seed := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "*", StartHour: 9, EndHour: 17, Timezone: "UTC"}
			require.NoError(t, env.db.Create(seed).Error)

			set := &models.SecretAccessSchedule{SecretNodeID: 7, AllowedDays: "*", StartHour: 0, EndHour: 17, Timezone: "UTC"}
			require.NoError(t, env.a.SetSecretAccessSchedule(ctx, set))

			var got models.SecretAccessSchedule
			require.NoError(t, env.db.Where("secret_node_id = ?", 7).First(&got).Error)
			assert.Equal(t, 0, got.StartHour, "moving the window's start to hour 0 was not written")
			assert.Equal(t, 0, set.StartHour, "the caller's struct reports the old start hour")
			assert.Equal(t, seed.ID, got.ID, "an update must keep the row")
		})
	}
}
