package store

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSchedLockStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return NewLocalStorage(db)
}

// On SQLite (single instance) the job always runs and fn's result propagates.
func TestWithSchedulerLock_SQLiteAlwaysRuns(t *testing.T) {
	ls := newSchedLockStore(t)
	ctx := context.Background()

	ran := false
	got, err := ls.WithSchedulerLock(ctx, 123, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, got, "ran=true on SQLite")
	assert.True(t, ran, "fn executed")

	// fn's error propagates, still ran=true.
	sentinel := errors.New("boom")
	got, err = ls.WithSchedulerLock(ctx, 123, func() error { return sentinel })
	assert.True(t, got)
	require.ErrorIs(t, err, sentinel)

	// Re-entrant: a second call still runs (no held lock on SQLite).
	got, err = ls.WithSchedulerLock(ctx, 123, func() error { return nil })
	require.NoError(t, err)
	assert.True(t, got)
}
