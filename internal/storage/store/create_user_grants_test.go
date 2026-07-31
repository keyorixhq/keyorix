package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	stg "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newUserGrantStore(t *testing.T) (*LocalStorage, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.UserRole{}))
	return NewLocalStorage(db), db
}

func TestCreateUserWithRoleGrants_AtomicSuccess(t *testing.T) {
	ctx := context.Background()
	ls, db := newUserGrantStore(t)

	user := &models.User{Username: "atomic", Email: "atomic@x.io"}
	grants := []stg.RoleGrant{
		{RoleID: 1, Scope: stg.Scope{}},             // system role
		{RoleID: 5, Scope: stg.Scope{ProjectID: 3}}, // project role
	}
	created, err := ls.CreateUserWithRoleGrants(ctx, user, grants)
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	var roles []models.UserRole
	require.NoError(t, db.Where("user_id = ?", created.ID).Find(&roles).Error)
	assert.Len(t, roles, 2)
}

func TestCreateUserWithRoleGrants_RollsBackOnGrantFailure(t *testing.T) {
	ctx := context.Background()
	ls, db := newUserGrantStore(t)

	// Two identical grants collide on the UserRole composite PK; the second insert
	// fails, so the whole transaction — including the user — must roll back.
	user := &models.User{Username: "rollback", Email: "rollback@x.io"}
	grants := []stg.RoleGrant{
		{RoleID: 1, Scope: stg.Scope{ProjectID: 3}},
		{RoleID: 1, Scope: stg.Scope{ProjectID: 3}},
	}
	_, err := ls.CreateUserWithRoleGrants(ctx, user, grants)
	require.Error(t, err)

	var userCount int64
	require.NoError(t, db.Model(&models.User{}).Where("username = ?", "rollback").Count(&userCount).Error)
	assert.Equal(t, int64(0), userCount, "user must not persist when a grant fails")
	var roleCount int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&roleCount).Error)
	assert.Equal(t, int64(0), roleCount, "no role grants persist either")
}
