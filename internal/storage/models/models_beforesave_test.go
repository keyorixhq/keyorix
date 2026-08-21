// models_beforesave_test.go — coverage for the G81 BeforeSave UTC-normalization
// hooks on models.go, none of which were previously exercised by any test in
// this package. Each hook is a GORM callback invoked with a *gorm.DB that it
// never touches (its receiver is `_ *gorm.DB`), so every test below calls it
// directly with a nil *gorm.DB — real behavior, without needing a live DB.
//
// For hooks that normalize a *time.Time (pointer field), both branches are
// covered: the nil-guard (field left nil, no panic) and the normalization
// itself (a non-UTC Location is converted to UTC while the absolute instant
// is preserved). For hooks that normalize a plain time.Time field, only the
// normalization branch exists (there's no nil-guard to hit), so a single test
// covers the function's one branch.
package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonUTCTime returns a fixed instant expressed in a fixed-offset, non-UTC
// Location, so a BeforeSave hook's UTC-conversion is actually observable
// (time.Now() alone might already happen to report a UTC-Location value in
// some environments, which would make the assertion vacuous).
func nonUTCTime() time.Time {
	loc := time.FixedZone("UTC-5", -5*60*60)
	return time.Date(2026, 3, 15, 10, 30, 0, 0, loc)
}

// --- AccessRequest.BeforeSave (ResolvedAt *time.Time, nil-guarded) ---

func TestAccessRequest_BeforeSave_NilResolvedAt(t *testing.T) {
	r := &AccessRequest{}
	require.NoError(t, r.BeforeSave(nil))
	assert.Nil(t, r.ResolvedAt)
}

func TestAccessRequest_BeforeSave_NormalizesResolvedAt(t *testing.T) {
	src := nonUTCTime()
	r := &AccessRequest{ResolvedAt: &src}
	require.NoError(t, r.BeforeSave(nil))
	require.NotNil(t, r.ResolvedAt)
	assert.Equal(t, time.UTC, r.ResolvedAt.Location())
	assert.True(t, src.Equal(*r.ResolvedAt), "instant must be preserved across the Location conversion")
}

// --- BreakGlassActivation.BeforeSave (CreatedAt time.Time, unconditional) ---

func TestBreakGlassActivation_BeforeSave_NormalizesCreatedAt(t *testing.T) {
	src := nonUTCTime()
	b := &BreakGlassActivation{CreatedAt: src}
	require.NoError(t, b.BeforeSave(nil))
	assert.Equal(t, time.UTC, b.CreatedAt.Location())
	assert.True(t, src.Equal(b.CreatedAt))
}

// --- AccessReviewCampaign.BeforeSave (ClosedAt *time.Time, nil-guarded) ---

func TestAccessReviewCampaign_BeforeSave_NilClosedAt(t *testing.T) {
	c := &AccessReviewCampaign{}
	require.NoError(t, c.BeforeSave(nil))
	assert.Nil(t, c.ClosedAt)
}

func TestAccessReviewCampaign_BeforeSave_NormalizesClosedAt(t *testing.T) {
	src := nonUTCTime()
	c := &AccessReviewCampaign{ClosedAt: &src}
	require.NoError(t, c.BeforeSave(nil))
	require.NotNil(t, c.ClosedAt)
	assert.Equal(t, time.UTC, c.ClosedAt.Location())
	assert.True(t, src.Equal(*c.ClosedAt))
}

// --- User.BeforeSave (CreatedAt time.Time, unconditional) ---

func TestUser_BeforeSave_NormalizesCreatedAt(t *testing.T) {
	src := nonUTCTime()
	u := &User{CreatedAt: src}
	require.NoError(t, u.BeforeSave(nil))
	assert.Equal(t, time.UTC, u.CreatedAt.Location())
	assert.True(t, src.Equal(u.CreatedAt))
}

// --- MFAStepupToken.BeforeSave (ExpiresAt time.Time, unconditional) ---

func TestMFAStepupToken_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	tok := &MFAStepupToken{ExpiresAt: src}
	require.NoError(t, tok.BeforeSave(nil))
	assert.Equal(t, time.UTC, tok.ExpiresAt.Location())
	assert.True(t, src.Equal(tok.ExpiresAt))
}

// --- MFAStepUpGrant.BeforeSave (ExpiresAt time.Time, unconditional) ---

func TestMFAStepUpGrant_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	g := &MFAStepUpGrant{ExpiresAt: src}
	require.NoError(t, g.BeforeSave(nil))
	assert.Equal(t, time.UTC, g.ExpiresAt.Location())
	assert.True(t, src.Equal(g.ExpiresAt))
}

// --- MFAChallenge.BeforeSave (ExpiresAt time.Time, unconditional) ---

func TestMFAChallenge_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	c := &MFAChallenge{ExpiresAt: src}
	require.NoError(t, c.BeforeSave(nil))
	assert.Equal(t, time.UTC, c.ExpiresAt.Location())
	assert.True(t, src.Equal(c.ExpiresAt))
}

// --- LoginAttempt.BeforeSave (AttemptedAt time.Time, unconditional) ---

func TestLoginAttempt_BeforeSave_NormalizesAttemptedAt(t *testing.T) {
	src := nonUTCTime()
	a := &LoginAttempt{AttemptedAt: src}
	require.NoError(t, a.BeforeSave(nil))
	assert.Equal(t, time.UTC, a.AttemptedAt.Location())
	assert.True(t, src.Equal(a.AttemptedAt))
}

// --- WebAuthnSession.BeforeSave (ExpiresAt time.Time, unconditional) ---

func TestWebAuthnSession_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	s := &WebAuthnSession{ExpiresAt: src}
	require.NoError(t, s.BeforeSave(nil))
	assert.Equal(t, time.UTC, s.ExpiresAt.Location())
	assert.True(t, src.Equal(s.ExpiresAt))
}

// --- UserRole.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestUserRole_BeforeSave_NilExpiresAt(t *testing.T) {
	ur := &UserRole{}
	require.NoError(t, ur.BeforeSave(nil))
	assert.Nil(t, ur.ExpiresAt)
}

func TestUserRole_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	ur := &UserRole{ExpiresAt: &src}
	require.NoError(t, ur.BeforeSave(nil))
	require.NotNil(t, ur.ExpiresAt)
	assert.Equal(t, time.UTC, ur.ExpiresAt.Location())
	assert.True(t, src.Equal(*ur.ExpiresAt))
}

// --- GroupRole.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestGroupRole_BeforeSave_NilExpiresAt(t *testing.T) {
	gr := &GroupRole{}
	require.NoError(t, gr.BeforeSave(nil))
	assert.Nil(t, gr.ExpiresAt)
}

func TestGroupRole_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	gr := &GroupRole{ExpiresAt: &src}
	require.NoError(t, gr.BeforeSave(nil))
	require.NotNil(t, gr.ExpiresAt)
	assert.Equal(t, time.UTC, gr.ExpiresAt.Location())
	assert.True(t, src.Equal(*gr.ExpiresAt))
}

// --- SecretNode.BeforeSave (Expiration *time.Time, nil-guarded) ---

func TestSecretNode_BeforeSave_NilExpiration(t *testing.T) {
	s := &SecretNode{}
	require.NoError(t, s.BeforeSave(nil))
	assert.Nil(t, s.Expiration)
}

func TestSecretNode_BeforeSave_NormalizesExpiration(t *testing.T) {
	src := nonUTCTime()
	s := &SecretNode{Expiration: &src}
	require.NoError(t, s.BeforeSave(nil))
	require.NotNil(t, s.Expiration)
	assert.Equal(t, time.UTC, s.Expiration.Location())
	assert.True(t, src.Equal(*s.Expiration))
}

// --- DynamicSecretLease.BeforeSave (ExpiresAt time.Time, unconditional) ---

func TestDynamicSecretLease_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	l := &DynamicSecretLease{ExpiresAt: src}
	require.NoError(t, l.BeforeSave(nil))
	assert.Equal(t, time.UTC, l.ExpiresAt.Location())
	assert.True(t, src.Equal(l.ExpiresAt))
}

// --- SecretAccessLog.BeforeSave (AccessTime time.Time, unconditional) ---

func TestSecretAccessLog_BeforeSave_NormalizesAccessTime(t *testing.T) {
	src := nonUTCTime()
	l := &SecretAccessLog{AccessTime: src}
	require.NoError(t, l.BeforeSave(nil))
	assert.Equal(t, time.UTC, l.AccessTime.Location())
	assert.True(t, src.Equal(l.AccessTime))
}

// --- Session.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestSession_BeforeSave_NilExpiresAt(t *testing.T) {
	s := &Session{}
	require.NoError(t, s.BeforeSave(nil))
	assert.Nil(t, s.ExpiresAt)
}

func TestSession_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	s := &Session{ExpiresAt: &src}
	require.NoError(t, s.BeforeSave(nil))
	require.NotNil(t, s.ExpiresAt)
	assert.Equal(t, time.UTC, s.ExpiresAt.Location())
	assert.True(t, src.Equal(*s.ExpiresAt))
}

// --- PersonalAccessToken.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestPersonalAccessToken_BeforeSave_NilExpiresAt(t *testing.T) {
	tok := &PersonalAccessToken{}
	require.NoError(t, tok.BeforeSave(nil))
	assert.Nil(t, tok.ExpiresAt)
}

func TestPersonalAccessToken_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	tok := &PersonalAccessToken{ExpiresAt: &src}
	require.NoError(t, tok.BeforeSave(nil))
	require.NotNil(t, tok.ExpiresAt)
	assert.Equal(t, time.UTC, tok.ExpiresAt.Location())
	assert.True(t, src.Equal(*tok.ExpiresAt))
}

// --- SetupToken.BeforeSave (CreatedAt time.Time, unconditional) ---

func TestSetupToken_BeforeSave_NormalizesCreatedAt(t *testing.T) {
	src := nonUTCTime()
	tok := &SetupToken{CreatedAt: src}
	require.NoError(t, tok.BeforeSave(nil))
	assert.Equal(t, time.UTC, tok.CreatedAt.Location())
	assert.True(t, src.Equal(tok.CreatedAt))
}

// --- AuditEvent.BeforeSave (EventTime time.Time, unconditional) ---

func TestAuditEvent_BeforeSave_NormalizesEventTime(t *testing.T) {
	src := nonUTCTime()
	e := &AuditEvent{EventTime: src}
	require.NoError(t, e.BeforeSave(nil))
	assert.Equal(t, time.UTC, e.EventTime.Location())
	assert.True(t, src.Equal(e.EventTime))
}

// TestAuditEvent_BeforeSave_PreservesUnixMicro guards the specific invariant
// the hook's doc comment calls out: normalizing EventTime's Location must not
// change its UnixMicro() value, because the audit hash chain
// (computeAuditEntryHash) is computed from UnixMicro() and must stay stable
// whether the hook ran before or after that computation.
func TestAuditEvent_BeforeSave_PreservesUnixMicro(t *testing.T) {
	src := nonUTCTime()
	before := src.UnixMicro()
	e := &AuditEvent{EventTime: src}
	require.NoError(t, e.BeforeSave(nil))
	assert.Equal(t, before, e.EventTime.UnixMicro())
}

// --- ShareRecord.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestShareRecord_BeforeSave_NilExpiresAt(t *testing.T) {
	s := &ShareRecord{}
	require.NoError(t, s.BeforeSave(nil))
	assert.Nil(t, s.ExpiresAt)
}

func TestShareRecord_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	s := &ShareRecord{ExpiresAt: &src}
	require.NoError(t, s.BeforeSave(nil))
	require.NotNil(t, s.ExpiresAt)
	assert.Equal(t, time.UTC, s.ExpiresAt.Location())
	assert.True(t, src.Equal(*s.ExpiresAt))
}

// --- AnomalyAlert.BeforeSave (DetectedAt time.Time, unconditional) ---

func TestAnomalyAlert_BeforeSave_NormalizesDetectedAt(t *testing.T) {
	src := nonUTCTime()
	a := &AnomalyAlert{DetectedAt: src}
	require.NoError(t, a.BeforeSave(nil))
	assert.Equal(t, time.UTC, a.DetectedAt.Location())
	assert.True(t, src.Equal(a.DetectedAt))
}

// --- MachineIdentity.BeforeSave (CreatedAt time.Time, unconditional) ---

func TestMachineIdentity_BeforeSave_NormalizesCreatedAt(t *testing.T) {
	src := nonUTCTime()
	m := &MachineIdentity{CreatedAt: src}
	require.NoError(t, m.BeforeSave(nil))
	assert.Equal(t, time.UTC, m.CreatedAt.Location())
	assert.True(t, src.Equal(m.CreatedAt))
}

// --- MachineIdentityCredential.BeforeSave (ExpiresAt *time.Time, nil-guarded) ---

func TestMachineIdentityCredential_BeforeSave_NilExpiresAt(t *testing.T) {
	c := &MachineIdentityCredential{}
	require.NoError(t, c.BeforeSave(nil))
	assert.Nil(t, c.ExpiresAt)
}

func TestMachineIdentityCredential_BeforeSave_NormalizesExpiresAt(t *testing.T) {
	src := nonUTCTime()
	c := &MachineIdentityCredential{ExpiresAt: &src}
	require.NoError(t, c.BeforeSave(nil))
	require.NotNil(t, c.ExpiresAt)
	assert.Equal(t, time.UTC, c.ExpiresAt.Location())
	assert.True(t, src.Equal(*c.ExpiresAt))
}

// --- ProjectMembership.BeforeSave (InvitedAt time.Time, unconditional) ---

func TestProjectMembership_BeforeSave_NormalizesInvitedAt(t *testing.T) {
	src := nonUTCTime()
	m := &ProjectMembership{InvitedAt: src}
	require.NoError(t, m.BeforeSave(nil))
	assert.Equal(t, time.UTC, m.InvitedAt.Location())
	assert.True(t, src.Equal(m.InvitedAt))
}
