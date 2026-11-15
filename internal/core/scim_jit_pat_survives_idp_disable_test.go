package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestJITOffboardingGap_PATSurvivesSCIMDeactivation pins the DOCUMENTED gap, not a
// desirable behaviour (BACKLOG JIT-OFFBOARDING-GAP; threat model SCIM-7; operator text
// in CONFIGURATION.md "Offboarding an SSO / JIT account"): an account the IdP
// JIT-provisioned through SSO carries external_id `sso:<provider>:<sub>`, so SCIM does
// not manage it. A SCIM active=false (PUT/PATCH) or DELETE for that external id is
// refused as "not a SCIM-managed account", changes nothing, and the user's PAT keeps
// working until a Keyorix administrator suspends, deactivates or deletes the user.
//
// If this test fails, an offboarding design has changed the behaviour that operators
// are told to rely on. That may be intended (JIT-OFFBOARDING-GAP), but then the docs
// above, UPGRADING 6v and the SCIM-7 row must change in the same PR, and this test must
// be rewritten to the new contract, not deleted.
func TestJITOffboardingGap_PATSurvivesSCIMDeactivation(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{Name: ssoDefaultRole}).Error)

	// The user is created by the real JIT path, not seeded by hand.
	p := &SSOProvider{Name: "okta", AutoProvision: true}
	jit, err := c.ensureSSOUser(ctx, p, nil, "okta|jit-leaver", "leaver@x.io", true, "Leaver", "")
	require.NoError(t, err)
	require.Equal(t, ssoExternalID("okta", "okta|jit-leaver"), jit.ExternalID)

	raw := patPrefix + "jit-offboarding-gap-pin-token"
	require.NoError(t, db.Create(&models.PersonalAccessToken{UserID: jit.ID, Name: "ci", TokenHash: sha256Hex(raw)}).Error)
	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.NoError(t, err, "precondition: the JIT user's PAT is valid")

	// The IdP's SCIM connector finds the user by its external id (the userName/email
	// fallback of FindSCIMUser) and sends active=false, then DELETE.
	found, err := c.FindSCIMUser(ctx, jit.ExternalID, "")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, jit.ID, found.ID)
	require.False(t, IsSCIMManaged(found), "an sso: account is not SCIM-managed")

	off := false
	_, err = c.UpdateSCIMUser(ctx, 9, found.ID, nil, nil, &off)
	require.ErrorIs(t, err, ErrNotSCIMManaged, "the documented refusal for PUT/PATCH active=false")
	err = c.DeprovisionSCIMUser(ctx, 9, found.ID)
	require.ErrorIs(t, err, ErrNotSCIMManaged, "the documented refusal for DELETE")

	after := loadUser(t, db, jit.ID)
	require.True(t, after.IsActive)
	require.Equal(t, AccountActive, after.AccountState)
	require.False(t, after.DeletedAt.Valid)

	_, _, _, _, err = c.ValidatePATToken(ctx, raw)
	require.NoError(t, err, "the PAT keeps working after the IdP disable: only a Keyorix admin action revokes it")
	var revoked int64
	require.NoError(t, db.Model(&models.PersonalAccessToken{}).Where("user_id = ? AND revoked = ?", jit.ID, true).Count(&revoked).Error)
	require.Zero(t, revoked)
}
