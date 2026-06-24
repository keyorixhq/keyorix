package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSCIMStateCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive}).Error)
	return c, db
}

// An admin security suspension must survive routine SCIM activation. The IdP re-sends
// active=true for every active user, so without a distinct deprovisioned state that
// sync would silently undo an incident-response lockout.
func TestUpdateSCIMUser_AdminSuspensionSurvivesReactivation(t *testing.T) {
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes := true

	require.NoError(t, c.SuspendUser(ctx, 99, 1)) // admin incident response

	updated, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes) // IdP sync
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, updated.AccountState, "SCIM activation must not clear an admin suspension")
	assert.True(t, AccountLoginBlocked(updated.AccountState), "the account stays login-blocked")
}

// The legitimate SCIM lifecycle still works: deactivation blocks login (deprovisioned),
// and a later reactivation restores access.
func TestUpdateSCIMUser_DeactivateThenReactivate(t *testing.T) {
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes, no := true, false

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	assert.Equal(t, AccountDeprovisioned, off.AccountState)
	assert.False(t, off.IsActive)
	assert.True(t, AccountLoginBlocked(off.AccountState), "a SCIM-deactivated account is login-blocked")

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	assert.Equal(t, AccountActive, on.AccountState, "reactivation clears its own deactivation")
	assert.True(t, on.IsActive)
	assert.False(t, AccountLoginBlocked(on.AccountState))
}

// Deactivating an already admin-suspended user must not downgrade the suspension to a
// deprovisioned state (which a later reactivation could then clear).
func TestUpdateSCIMUser_DeactivateKeepsAdminSuspension(t *testing.T) {
	c, _ := newSCIMStateCore(t)
	ctx := context.Background()
	yes, no := true, false
	require.NoError(t, c.SuspendUser(ctx, 99, 1))

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, off.AccountState, "an admin suspension is not downgraded by SCIM deactivation")

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	assert.Equal(t, AccountSuspended, on.AccountState, "and reactivation still cannot revive it")
}
