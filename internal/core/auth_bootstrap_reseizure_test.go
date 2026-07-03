package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #105 — SystemNeedsBootstrap/BootstrapSystem must stay "already initialised" even
// after every user is later removed (soft-deleted, hard-purged, or otherwise), not
// just while the live user count is nonzero. Before the fix, both keyed purely on
// ListUsers' count, so a full deprovision (accidental, malicious, or via a bug in
// some other deletion path) reopened bootstrap and let a stale/leaked bootstrap
// token re-seize admin on an install that had already been initialised.

// emptyUsersTable soft-deletes then hard-purges the given user IDs directly at the
// storage layer, bypassing every core-level guard (including guardLastAdminDeactivation)
// — simulating "every user is gone, however that happened", the scenario a live
// ListUsers count alone cannot distinguish from a never-initialised install.
func emptyUsersTable(t *testing.T, c *KeyorixCore, ids ...uint) {
	t.Helper()
	ctx := context.Background()
	for _, id := range ids {
		require.NoError(t, c.storage.DeleteUser(ctx, id))
	}
	_, err := c.storage.PurgeDeletedUsersBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
}

// TestSystemNeedsBootstrap_StaysFalseAfterUsersTableEmptied asserts the permanent
// marker keeps SystemNeedsBootstrap reporting false even once the users table is
// completely empty.
func TestSystemNeedsBootstrap_StaysFalseAfterUsersTableEmptied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	needs, err := c.SystemNeedsBootstrap(ctx)
	require.NoError(t, err)
	assert.False(t, needs, "freshly bootstrapped install must not need bootstrap")

	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	emptyUsersTable(t, c, admin.ID)

	needs, err = c.SystemNeedsBootstrap(ctx)
	require.NoError(t, err)
	assert.False(t, needs, "the permanent marker must survive the user table being emptied")
}

// TestBootstrapSystem_RefusesReseizureAfterUsersTableEmptied is the sharper form:
// even with zero live users AND a valid bootstrap token, BootstrapSystem must
// refuse to seed a NEW admin once the marker is set — the concrete re-seizure this
// finding describes.
func TestBootstrapSystem_RefusesReseizureAfterUsersTableEmptied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	emptyUsersTable(t, c, admin.ID)

	c.SetBootstrapToken("test-bootstrap-token")
	result, err := c.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "attacker", Email: "attacker@example.com", Password: "AttackerPass123!",
		DisplayName: "Attacker", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	assert.True(t, result.AlreadyInitialized, "must report already-initialised, not seed a new admin")
	assert.Nil(t, result.User, "no attacker user should be created")

	_, err = st.GetUserByEmail(ctx, "attacker@example.com")
	assert.Error(t, err, "the attacker account must never have been created")
}

// TestBootstrapSystem_TokenClearedAfterSuccess pins the token-single-use fix: once
// bootstrap succeeds, the in-memory token is cleared so a captured/logged token
// (GenerateBootstrapToken logs it) can never be replayed even before the marker
// check — belt-and-suspenders alongside the marker.
func TestBootstrapSystem_TokenClearedAfterSuccess(t *testing.T) {
	c := freshBootstrapCore(t)
	c.SetBootstrapToken("only-once-token")

	_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("only-once-token"))
	require.NoError(t, err)
	assert.Empty(t, c.bootstrapToken, "the bootstrap token must be cleared after first successful use")
}

// TestBootstrapSystem_BackfillsMarkerForPreFixInstall pins the upgrade path: an
// install that bootstrapped before this fix shipped has users but no marker row
// yet (simulated here by seeding a user directly, bypassing BootstrapSystem
// entirely so the marker is never written). The next BootstrapSystem call (e.g.
// the server's startup idempotency check) must backfill the marker rather than
// leaving the install unprotected.
func TestBootstrapSystem_BackfillsMarkerForPreFixInstall(t *testing.T) {
	c := freshBootstrapCore(t)
	ctx := context.Background()

	_, found, err := c.storage.GetSystemMetadata(ctx, systemInitializedKey)
	require.NoError(t, err)
	require.False(t, found, "precondition: no marker yet")

	_, err = c.storage.CreateUser(ctx, &models.User{Username: "legacy", Email: "legacy@example.com", IsActive: true})
	require.NoError(t, err)

	result, err := c.BootstrapSystem(ctx, &BootstrapRequest{Token: "irrelevant"})
	require.NoError(t, err)
	assert.True(t, result.AlreadyInitialized)

	_, found, err = c.storage.GetSystemMetadata(ctx, systemInitializedKey)
	require.NoError(t, err)
	assert.True(t, found, "the marker must be backfilled for a pre-fix install with existing users")
}
