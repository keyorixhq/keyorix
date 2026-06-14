package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRiskTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RiskException{}))
	return NewLocalStorage(db)
}

func TestRiskExceptions_CreateListRevoke(t *testing.T) {
	ls := newRiskTestStore(t)
	ctx := context.Background()
	exp := time.Now().AddDate(0, 0, 30)

	a, err := ls.CreateRiskException(ctx, &models.RiskException{Title: "a", Category: "sod", ExpiresAt: exp})
	require.NoError(t, err)
	_, err = ls.CreateRiskException(ctx, &models.RiskException{Title: "b", Category: "mfa", ExpiresAt: exp, Revoked: true})
	require.NoError(t, err)

	// activeOnly excludes the revoked row.
	active, err := ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, "a", active[0].Title)

	// Without activeOnly, both are returned.
	all, err := ls.ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	assert.Len(t, all, 2)

	// Revoke via update; it then drops out of the active list.
	got, err := ls.GetRiskException(ctx, a.ID)
	require.NoError(t, err)
	got.Revoked = true
	require.NoError(t, ls.UpdateRiskException(ctx, got))
	active, err = ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	assert.Empty(t, active)
}
