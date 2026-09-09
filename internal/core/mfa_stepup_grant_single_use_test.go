// mfa_stepup_grant_single_use_test.go — regression coverage for the reauth
// step-up grant single-use fix (a follow-up to #1775's confused-deputy Purpose
// separation). #1775 stopped a login-minted grant from satisfying
// requireReauth, but left the grant it DOES accept (MFAStepUpPurposeReauth,
// minted by FinishWebAuthnReauth's live passkey re-assertion) valid for its
// entire ~15-minute window and good for EVERY requireReauth-gated action, not
// just the one the caller intended -- a single proof could chain disable-MFA,
// delete-WebAuthn-credential, regenerate-recovery-codes, and change-email
// together. requireReauth now calls the atomic ConsumeMFAStepUpGrant instead
// of the read-only HasActiveMFAStepUp, so accepting the grant also invalidates
// it.
//
// Investigation note (why there is no separate "TOTP-path" version of this
// suite): requireReauth has exactly ONE grant-based branch (see mfa.go,
// models.MFAStepUpPurposeReauth), fed by exactly ONE minting call site
// repo-wide (webauthn.go's FinishWebAuthnReauth). A TOTP-enrolled account
// satisfies requireReauth WITHOUT ever touching a persisted grant at all: it
// supplies a live TOTP code, verified directly against the active secret and
// atomically anti-replayed via MarkTOTPStepUsed on every single call (see
// TestRequireReauth_TOTPCode_AlreadyInherentlySingleUsePerCall below) --
// there is no separate TOTP step-up endpoint that mints an
// MFAStepUpPurposeReauth-equivalent grant (VerifyMFAStepUp exists, but mints
// the distinct MFAStepUpPurposeRestrictedSecretRead purpose for the
// classification gate only, and requireReauth never reads that purpose). So
// the single choke point this fix hardens -- ConsumeMFAStepUpGrant at
// requireReauth's grant branch -- is, structurally, the ONLY place a stored
// MFAStepUpPurposeReauth grant is ever consumed, regardless of whether the
// account also has TOTP enabled alongside WebAuthn.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestRequireReauth_PasswordPlusGrant_OneActionSucceeds is the positive control:
// a user re-authenticates once (an active MFAStepUpPurposeReauth grant exists,
// standing in for a completed FinishWebAuthnReauth ceremony), performs ONE
// sensitive action, and it succeeds -- the baseline the negative tests below
// must not break.
func TestRequireReauth_PasswordPlusGrant_OneActionSucceeds(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)

	codes, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.NoError(t, err, "password + a live, correctly-purposed step-up grant must satisfy re-auth for the FIRST sensitive action")
	assert.NotEmpty(t, codes)
}

// TestRequireReauth_GrantConsumedOnFirstAction_SecondDifferentActionRejected is
// the core negative case this fix closes: one grant, from one re-auth proof,
// must not satisfy a SECOND, DIFFERENT sensitive action. Actions are chosen so
// neither flips user.MFAEnabled/WebAuthnEnabled (RegenerateMFARecoveryCodes,
// then UpdateOwnProfile's email-change path) -- keeping secondFactorEnrolled
// true throughout isolates the grant-consumption behavior from any incidental
// "no second factor enrolled" fallback.
//
// Must fail RED against the pre-fix behavior (HasActiveMFAStepUp, a
// non-consuming read) -- the second call would have found the SAME grant still
// "active" and succeeded. GREEN after the fix (ConsumeMFAStepUpGrant).
func TestRequireReauth_GrantConsumedOnFirstAction_SecondDifferentActionRejected(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)

	// First sensitive action: succeeds, consuming the grant.
	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.NoError(t, err, "the first sensitive action must succeed off the live grant")

	// Second, DIFFERENT sensitive action, same (now-consumed) grant, same
	// ~15-minute window, no fresh re-auth performed: must be rejected.
	_, err = c.UpdateOwnProfile(ctx, 1, "", "alice-new@b.com", mfaTestPassword)
	require.Error(t, err, "a grant already consumed by one action must NOT satisfy a second, different action")
	assert.Contains(t, err.Error(), "invalid code or password")

	u, gerr := c.storage.GetUser(ctx, 1)
	require.NoError(t, gerr)
	assert.Equal(t, "a@b.com", u.Email, "the rejected second action must not have changed the email")
}

// TestRequireReauth_GrantConsumedOnFirstAction_ThirdActionAlsoRejected repeats
// the negative case with a THIRD distinct action type (DisableMFA), confirming
// the consumed grant doesn't happen to satisfy just the one action tried above
// -- it's dead for every action, not just UpdateOwnProfile specifically.
// DisableMFA is used LAST (not first) because a successful DisableMFA flips
// user.MFAEnabled to false, which would itself make secondFactorEnrolled false
// and let a bare password through the UNRELATED "no second factor enrolled"
// branch -- that would prove nothing about grant consumption.
func TestRequireReauth_GrantConsumedOnFirstAction_ThirdActionAlsoRejected(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)

	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.NoError(t, err, "the first sensitive action must succeed off the live grant")

	err = c.DisableMFA(ctx, 1, mfaTestPassword)
	require.Error(t, err, "the same consumed grant must not satisfy a third, still-different action either")
	assert.Contains(t, err.Error(), "invalid code or password")

	u, gerr := c.storage.GetUser(ctx, 1)
	require.NoError(t, gerr)
	assert.True(t, u.MFAEnabled, "the rejected DisableMFA attempt must not have disabled MFA")
}

// TestRequireReauth_FreshGrantAfterConsumption_SecondActionSucceeds proves the
// fix isn't over-tightened into "only one sensitive action ever, period": a
// SECOND, independent re-auth ceremony (a fresh grant, not a reuse of the
// consumed one) must satisfy a second sensitive action normally.
func TestRequireReauth_FreshGrantAfterConsumption_SecondActionSucceeds(t *testing.T) {
	t.Parallel()
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)

	_, err := c.RegenerateMFARecoveryCodes(ctx, 1, mfaTestPassword)
	require.NoError(t, err, "the first sensitive action must succeed off the live grant")

	// A fresh re-auth ceremony (e.g. a second FinishWebAuthnReauth passkey
	// touch) mints a brand-new grant -- NOT the same row as the consumed one.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)

	u, err := c.UpdateOwnProfile(ctx, 1, "", "alice-new@b.com", mfaTestPassword)
	require.NoError(t, err, "a genuinely FRESH grant from a second re-auth ceremony must satisfy a second, different action")
	assert.Equal(t, "alice-new@b.com", u.Email)
}

// TestRequireReauth_TOTPCode_AlreadyInherentlySingleUsePerCall documents and
// confirms the investigation finding referenced in this file's package
// comment: the TOTP direct-code branch of requireReauth (no persisted grant
// involved at all) is already single-use PER CODE via MarkTOTPStepUsed's
// atomic anti-replay -- presenting the exact same code twice across two
// separate requireReauth-gated actions must fail the second time, with no
// fix needed on that branch. This is the "verify before replicating, don't
// assume symmetry between the WebAuthn and TOTP paths" check the fix's
// investigation required.
func TestRequireReauth_TOTPCode_AlreadyInherentlySingleUsePerCall(t *testing.T) {
	t.Parallel()
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	secret, _ := activateMFAForTest(t, c, fixed)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// First action: a fresh, valid TOTP code succeeds.
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, code)
	require.NoError(t, err, "a fresh, valid TOTP code must satisfy the first sensitive action")

	// Second, different action, SAME TOTP code, well within its ~90s validity
	// window: must be rejected -- MarkTOTPStepUsed already marked this step used.
	_, err = c.UpdateOwnProfile(ctx, 1, "", "alice-new@b.com", code)
	require.Error(t, err, "the identical TOTP code must not satisfy a second action -- MarkTOTPStepUsed anti-replay, independent of this fix")
	assert.Contains(t, err.Error(), "invalid code or password")
}
