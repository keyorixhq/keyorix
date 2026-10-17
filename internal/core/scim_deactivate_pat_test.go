package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newSCIMDeactivatePATCore is a SCIM-managed user (id 1) holding one live PAT,
// with the auth-cache invalidator recorded so a test can assert eviction.
func newSCIMDeactivatePATCore(t *testing.T) (c *KeyorixCore, db *gorm.DB, raw string, evicted *[]string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Role{}, &models.UserRole{}, &models.Project{}, &models.Environment{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.MFAStepUpGrant{}))
	c = NewKeyorixCore(store.NewLocalStorage(db))
	var seen []string
	c.SetTokenCacheInvalidator(func(h string) { seen = append(seen, h) })
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "carol", IsActive: true, AccountState: AccountActive, ExternalID: "okta|carol"}).Error)
	raw = patPrefix + "scim-deactivate-regression-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 1, UserID: 1, Name: "ci", TokenHash: sha256Hex(raw)}).Error)
	_, _, _, _, err = c.ValidatePATToken(context.Background(), raw)
	require.NoError(t, err, "precondition: the PAT works while the account is live")
	return c, db, raw, &seen
}

func requirePATRowRevoked(t *testing.T, db *gorm.DB) {
	t.Helper()
	var unrevoked int64
	require.NoError(t, db.Model(&models.PersonalAccessToken{}).
		Where("user_id = ? AND revoked = ?", 1, false).Count(&unrevoked).Error)
	require.Zero(t, unrevoked, "a SCIM deactivation must REVOKE the user's PATs, not leave them merely inert (#3419)")
}

// TestUpdateSCIMUser_DeactivateReactivateDoesNotHandBackPATs is #3419's
// regression test, the active=false sibling of
// TestDeprovisionSCIMUser_RestoreDoesNotHandBackPATs (#2855). Okta and Entra
// disable a user with PATCH/PUT active=false and re-enable with active=true, not
// with DELETE. While deactivated a PAT is inert (the account is blocked), so the
// property is that it stays refused AFTER the IdP re-enables the account.
func TestUpdateSCIMUser_DeactivateReactivateDoesNotHandBackPATs(t *testing.T) {
	t.Parallel()
	c, db, raw, evicted := newSCIMDeactivatePATCore(t)
	ctx := context.Background()
	yes, no := true, false

	_, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	require.True(t, on.IsActive, "the account must be live again, otherwise this test proves nothing")
	require.Equal(t, AccountActive, on.AccountState)

	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.ErrorIs(t, err, ErrPATRevoked,
		"a PAT that existed at SCIM deactivation must not authenticate after the IdP re-enables the account")
	requirePATRowRevoked(t, db)
	require.Contains(t, *evicted, sha256Hex(raw),
		"the revoked PAT's hash must be evicted from the auth cache after commit, not left for the cache TTL")
}

// TestUpdateSCIMUser_DeactivateRevokesPATsAndKeepsAdminSuspension: an account an
// administrator suspended keeps that suspension through an IdP deactivate and
// reactivate (SCIM-6), its PATs are revoked by the deactivation all the same, and
// the reactivation does not un-revoke them.
func TestUpdateSCIMUser_DeactivateRevokesPATsAndKeepsAdminSuspension(t *testing.T) {
	t.Parallel()
	c, db, raw, _ := newSCIMDeactivatePATCore(t)
	ctx := context.Background()
	yes, no := true, false

	require.NoError(t, c.SuspendUser(ctx, 99, 1))
	// SuspendUser revokes PATs itself; put a fresh one back so the deactivation
	// below is what has to revoke it.
	raw2 := raw + "-2"
	require.NoError(t, db.Create(&models.PersonalAccessToken{ID: 2, UserID: 1, Name: "ci2", TokenHash: sha256Hex(raw2)}).Error)

	off, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &no)
	require.NoError(t, err)
	require.Equal(t, AccountSuspended, off.AccountState, "a SCIM deactivation must not replace an admin suspension")
	requirePATRowRevoked(t, db)

	on, err := c.UpdateSCIMUser(ctx, 2, 1, nil, nil, &yes)
	require.NoError(t, err)
	require.Equal(t, AccountSuspended, on.AccountState, "a SCIM reactivation must not clear an admin suspension")
	requirePATRowRevoked(t, db)

	// The admin lifts the suspension; the revoked PAT still stays dead.
	require.NoError(t, c.ReactivateUser(ctx, 99, 1))
	_, _, _, _, err = c.ValidatePATToken(ctx, raw2)
	require.ErrorIs(t, err, ErrPATRevoked)
}

// TestUpdateSCIMUser_ProfileOnlyUpdateKeepsPATs: only a deactivating call revokes.
// A displayName/email PATCH, or active=true, must leave a working PAT alone.
func TestUpdateSCIMUser_ProfileOnlyUpdateKeepsPATs(t *testing.T) {
	t.Parallel()
	c, _, raw, _ := newSCIMDeactivatePATCore(t)
	ctx := context.Background()
	yes := true
	name := "Carol C"

	_, err := c.UpdateSCIMUser(ctx, 2, 1, &name, nil, &yes)
	require.NoError(t, err)
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.NoError(t, err, "a non-deactivating SCIM update must not revoke PATs")
}
