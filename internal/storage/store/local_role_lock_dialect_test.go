package store

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// roleLockSQL returns the SQL LockRoleForUpdate issues against db, as a DryRun
// session (nothing is executed).
func roleLockSQL(t *testing.T, db *gorm.DB) string {
	t.Helper()
	capture := &sqlCapture{Interface: logger.Discard}
	db = db.Session(&gorm.Session{DryRun: true, Logger: capture})
	_, _ = NewLocalStorage(db).LockRoleForUpdate(context.Background(), 1)
	require.Len(t, capture.sql, 1, "the lock lookup must issue exactly one SELECT")
	return capture.sql[0]
}

// TestLockRoleForUpdate_DialectMatchedLocking is the default-CI half of #3919:
// Postgres MUST be sent FOR UPDATE (core.UpdateRole's scope classification holds
// until its write only through this lock); SQLite emits none. That the lock
// serializes two replicas is the pg-gated
// TestCTAReview_UpdateRoleExplicitScope_vs_NarrowScope_CrossReplicaPostgres in
// internal/core.
func TestLockRoleForUpdate_DialectMatchedLocking(t *testing.T) {
	t.Run("sqlite omits FOR UPDATE", func(t *testing.T) {
		db := newMachineStore(t).db
		assert.NotContains(t, strings.ToUpper(roleLockSQL(t, db)), "FOR UPDATE")
	})

	t.Run("postgres adds FOR UPDATE", func(t *testing.T) {
		db, err := gorm.Open(
			postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable"}),
			&gorm.Config{DisableAutomaticPing: true, Logger: logger.Discard},
		)
		require.NoError(t, err)
		assert.Contains(t, strings.ToUpper(roleLockSQL(t, db)), "FOR UPDATE")
	})
}
