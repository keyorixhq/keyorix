package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// sqlCapture is a gorm logger that records every statement's SQL.
type sqlCapture struct {
	logger.Interface
	sql []string
}

func (c *sqlCapture) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	s, _ := fc()
	c.sql = append(c.sql, s)
}

// lockSQL returns the SQL LockMachineIdentityForUpdate issues against db. db
// must be a DryRun session, so nothing is executed; the lookup result itself
// (not-found) is irrelevant here.
func lockSQL(t *testing.T, db *gorm.DB) string {
	t.Helper()
	capture := &sqlCapture{Interface: logger.Discard}
	db = db.Session(&gorm.Session{DryRun: true, Logger: capture})
	_, _ = NewLocalStorage(db).LockMachineIdentityForUpdate(context.Background(), 1)
	require.Len(t, capture.sql, 1, "the lock lookup must issue exactly one SELECT")
	return capture.sql[0]
}

// TestLockMachineIdentityForUpdate_DialectMatchedLocking is the default-CI half
// of INV-STORE-15: Postgres MUST be sent FOR UPDATE — a Postgres
// read-modify-write without it has no row lock at all — and SQLite must emit
// none. It asserts the generated SQL only. Limits, stated rather than implied:
// the Postgres subtest is the load-bearing one (it goes red if the dialect
// branch is removed); the SQLite subtest does NOT go red if the branch is
// widened to all dialects, because GORM's SQLite driver itself drops the
// locking clause — it guards against that driver behaviour changing. That the
// Postgres clause actually serializes writers is
// TestConcurrency_LockMachineIdentityForUpdate_MultiInstancePostgres (pg-gated).
func TestLockMachineIdentityForUpdate_DialectMatchedLocking(t *testing.T) {
	t.Run("sqlite omits FOR UPDATE", func(t *testing.T) {
		db := newMachineStore(t).db
		assert.NotContains(t, strings.ToUpper(lockSQL(t, db)), "FOR UPDATE")
	})

	t.Run("postgres adds FOR UPDATE", func(t *testing.T) {
		// DisableAutomaticPing + DryRun (in lockSQL): no server is contacted,
		// only the dialector's SQL generation is exercised.
		db, err := gorm.Open(
			postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable"}),
			&gorm.Config{DisableAutomaticPing: true, Logger: logger.Discard},
		)
		require.NoError(t, err)
		assert.Contains(t, strings.ToUpper(lockSQL(t, db)), "FOR UPDATE")
	})
}
