package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// RECOVERY-MFA-RESET-1: the online two-admin MFA reset.

const mfaResetUserPassword = "Tr1cky-Passphrase-For-Tests!"

type mfaResetFixture struct {
	c       *KeyorixCore
	st      *store.LocalStorage
	now     time.Time
	secrets map[uint]string
	// a, b, c are global admins with TOTP; member is a non-admin with TOTP.
	a, b, cAdmin, member, target *models.User
}

func newMFAResetFixture(t *testing.T) *mfaResetFixture {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	c.SetAuthEncryptor(enc)
	f := &mfaResetFixture{c: c, st: st, now: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC), secrets: map[uint]string{}}
	c.now = func() time.Time { return f.now }

	a, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	roleIDs, err := st.GetUserRoleIDsAt(ctx, a.ID, storage.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, roleIDs)
	mk := func(name string, admin bool) *models.User {
		u, err := c.CreateUser(ctx, &CreateUserRequest{Username: name, Email: name + "@example.com", DisplayName: name, Password: mfaResetUserPassword})
		require.NoError(t, err)
		if admin {
			require.NoError(t, st.AssignRole(ctx, u.ID, roleIDs[0], storage.Scope{}))
		}
		return u
	}
	f.a = a
	f.b = mk("admin-b", true)
	f.cAdmin = mk("admin-c", true)
	f.member = mk("member", false)
	f.target = mk("target", false)
	f.enrol(t, f.a.ID, "BootstrapPass123!")
	for _, u := range []*models.User{f.b, f.cAdmin, f.member, f.target} {
		f.enrol(t, u.ID, mfaResetUserPassword)
	}
	// The target also has a session and a PAT that the reset must kill.
	exp := f.now.Add(time.Hour)
	_, err = st.CreateSession(ctx, &models.Session{UserID: f.target.ID, SessionToken: "target-session-hash", CreatedAt: f.now, ExpiresAt: &exp})
	require.NoError(t, err)
	_, err = st.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{UserID: f.target.ID, Name: "ci", TokenHash: "target-pat-hash"})
	require.NoError(t, err)
	return f
}

// enrol activates TOTP for uid through the real enrolment path.
func (f *mfaResetFixture) enrol(t *testing.T, uid uint, password string) {
	t.Helper()
	ctx := context.Background()
	_, secret, err := f.c.BeginMFAEnrollment(ctx, uid)
	require.NoError(t, err)
	f.secrets[uid] = secret
	_, err = f.c.ActivateMFA(ctx, uid, f.code(t, uid), password, "")
	require.NoError(t, err)
}

// code advances the clock one TOTP step and returns uid's code for it, so every
// call is a fresh, never-used step.
func (f *mfaResetFixture) code(t *testing.T, uid uint) string {
	t.Helper()
	f.now = f.now.Add(31 * time.Second)
	c, err := totp.GenerateCode(f.secrets[uid], f.now)
	require.NoError(t, err)
	return c
}

func (f *mfaResetFixture) request(t *testing.T) *models.MFAResetRequest {
	t.Helper()
	r, err := f.c.RequestMFAReset(context.Background(), f.a.ID, false, MFAResetRequestInput{
		User: "target", Reason: "lost phone", VerifiedBy: "video", Evidence: "call with T. on 2026-10-27", Code: f.code(t, f.a.ID),
	})
	require.NoError(t, err)
	return r
}

func (f *mfaResetFixture) reload(t *testing.T, id uint) *models.User {
	t.Helper()
	u, err := f.st.GetUser(context.Background(), id)
	require.NoError(t, err)
	return u
}

func (f *mfaResetFixture) auditCount(t *testing.T, eventType string) int {
	t.Helper()
	logs, _, err := f.st.GetAuditLogs(context.Background(), &storage.AuditFilter{Actions: []string{eventType}})
	require.NoError(t, err)
	return len(logs)
}

// assertTargetIntact: the target keeps its factor, session, PAT and password.
func (f *mfaResetFixture) assertTargetIntact(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	u := f.reload(t, f.target.ID)
	assert.True(t, u.MFAEnabled, "TOTP flag cleared")
	assert.False(t, u.MFAEnrolmentRequired)
	assert.Equal(t, AccountActive, u.AccountState)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(mfaResetUserPassword)), "password replaced")
	sec, err := f.st.GetMFASecret(ctx, f.target.ID)
	require.NoError(t, err)
	assert.NotNil(t, sec, "TOTP secret removed")
	n, err := f.st.CountUnusedMFARecoveryCodes(ctx, f.target.ID)
	require.NoError(t, err)
	assert.Positive(t, n, "recovery codes removed")
	hashes, err := f.st.ListSessionTokenHashesForUser(ctx, f.target.ID)
	require.NoError(t, err)
	assert.Len(t, hashes, 1, "session removed")
}

func (f *mfaResetFixture) requestStatus(t *testing.T, id uint) string {
	t.Helper()
	r, err := f.st.GetMFAResetRequest(context.Background(), id)
	require.NoError(t, err)
	return r.Status
}

func TestMFAReset_TwoAdmins_FullCredentialReset_EverySessionAndPATDead(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	req := f.request(t)
	assert.Equal(t, 1, f.auditCount(t, EventMFAResetRequested))
	f.assertTargetIntact(t) // a request alone changes nothing

	res, err := f.c.ApproveMFAReset(ctx, f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.NoError(t, err)

	u := f.reload(t, f.target.ID)
	assert.False(t, u.MFAEnabled)
	assert.False(t, u.WebAuthnEnabled)
	assert.True(t, u.MFAEnrolmentRequired)
	assert.True(t, MFAEnrolmentOwed(u))
	assert.Equal(t, AccountPasswordResetRequired, u.AccountState)
	require.NotNil(t, u.OneTimePasswordExpiresAt)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(res.OneTimePassword)))
	sec, err := f.st.GetMFASecret(ctx, f.target.ID)
	assert.True(t, err != nil || sec == nil, "TOTP secret survived")
	n, err := f.st.CountUnusedMFARecoveryCodes(ctx, f.target.ID)
	require.NoError(t, err)
	assert.Zero(t, n, "recovery codes survived")

	// Every session and PAT of the target is dead.
	hashes, err := f.st.ListSessionTokenHashesForUser(ctx, f.target.ID)
	require.NoError(t, err)
	assert.Empty(t, hashes, "a session survived")
	_, err = f.st.GetSession(ctx, "target-session-hash")
	assert.Error(t, err, "the session row still resolves")
	pats, err := f.st.ListPersonalAccessTokensByUser(ctx, f.target.ID)
	require.NoError(t, err)
	require.NotEmpty(t, pats)
	for _, p := range pats {
		assert.True(t, p.Revoked, "PAT %d survived", p.ID)
	}

	assert.Equal(t, models.MFAResetStatusApproved, f.requestStatus(t, req.ID))
	assert.Equal(t, 1, f.auditCount(t, EventMFAResetApproved))
	assert.Equal(t, 1, f.auditCount(t, EventMFAReset))
	// The target and every admin are told.
	for _, uid := range []uint{f.target.ID, f.a.ID, f.b.ID, f.cAdmin.ID} {
		notes, err := f.st.ListNotifications(ctx, uid, false, 20)
		require.NoError(t, err)
		found := false
		for _, nt := range notes {
			found = found || nt.Type == EventMFAReset
		}
		assert.True(t, found, "user %d was not notified", uid)
	}
}

func TestMFAReset_SelfApprovalRefusedAndAudited(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	before := f.auditCount(t, EventMFAResetApproved)

	_, err := f.c.ApproveMFAReset(context.Background(), f.a.ID, false, req.ID, f.code(t, f.a.ID))
	require.ErrorIs(t, err, ErrMFAResetSelfApproval)

	assert.Equal(t, before+1, f.auditCount(t, EventMFAResetApproved), "the denied self-approval must be audited")
	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
	f.assertTargetIntact(t)
}

// One admin cannot supply both halves: not by approving their own request, and not
// by opening a second request for the same user to approve that one instead.
func TestMFAReset_SameAdminTwiceRefused(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	req := f.request(t)

	_, err := f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{
		User: "target", Reason: "again", VerifiedBy: "other", Code: f.code(t, f.a.ID),
	})
	require.ErrorIs(t, err, ErrMFAResetAlreadyPending)

	// Cancel and re-request: the new request is still A's, so A still cannot approve it.
	require.NoError(t, f.c.CancelMFAReset(ctx, f.a.ID, false, req.ID))
	again := f.request(t)
	_, err = f.c.ApproveMFAReset(ctx, f.a.ID, false, again.ID, f.code(t, f.a.ID))
	require.ErrorIs(t, err, ErrMFAResetSelfApproval)
	f.assertTargetIntact(t)
}

func TestMFAReset_NonAdminOrMachineApproverRefused(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	req := f.request(t)

	_, err := f.c.ApproveMFAReset(ctx, f.member.ID, false, req.ID, f.code(t, f.member.ID))
	require.ErrorIs(t, err, ErrMFAResetAdminRequired)
	_, err = f.c.ApproveMFAReset(ctx, f.b.ID, true, req.ID, f.code(t, f.b.ID))
	require.ErrorIs(t, err, ErrMFAResetAdminRequired, "a machine credential is never the second person")
	_, err = f.c.RequestMFAReset(ctx, f.member.ID, false, MFAResetRequestInput{User: "admin-b", Reason: "x", VerifiedBy: "other", Code: f.code(t, f.member.ID)})
	require.ErrorIs(t, err, ErrMFAResetAdminRequired)

	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
	f.assertTargetIntact(t)
}

func TestMFAReset_TargetRulesRefused(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	_, err := f.st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: 1, Name: "ci-runner", State: "active"})
	require.NoError(t, err)

	for _, tc := range []struct {
		ref  string
		want error
	}{
		{"ci-runner", ErrMFAResetMachineIdentity},
		{"admin-c", ErrMFAResetGlobalAdmin},
		{"admin", ErrCannotActOnSelf},
		{"nobody", ErrMFAResetTargetNotFound},
	} {
		_, err := f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{User: tc.ref, Reason: "x", VerifiedBy: "ticket", Code: f.code(t, f.a.ID)})
		assert.ErrorIs(t, err, tc.want, tc.ref)
	}
	assert.Zero(t, f.auditCount(t, EventMFAResetRequested))
}

func TestMFAReset_ReplayOfApprovedRequestRefused(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	req := f.request(t)
	_, err := f.c.ApproveMFAReset(ctx, f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.NoError(t, err)
	afterFirst := f.reload(t, f.target.ID).PasswordHash

	_, err = f.c.ApproveMFAReset(ctx, f.cAdmin.ID, false, req.ID, f.code(t, f.cAdmin.ID))
	require.ErrorIs(t, err, ErrMFAResetRequestDecided)
	_, err = f.c.ApproveMFAReset(ctx, f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.ErrorIs(t, err, ErrMFAResetRequestDecided)

	assert.Equal(t, afterFirst, f.reload(t, f.target.ID).PasswordHash, "a replay issued another password")
	assert.Equal(t, 1, f.auditCount(t, EventMFAReset))
}

func TestMFAReset_ExpiredRequestRefused(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	f.now = f.now.Add(MFAResetRequestTTL + time.Minute)
	_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.ErrorIs(t, err, ErrMFAResetRequestExpired)
	f.assertTargetIntact(t)
}

func TestMFAReset_WrongApproverCodeChangesNothing(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, "000000")
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
	f.assertTargetIntact(t)
}

// The reset and its audit rows are one fail-closed transaction: when the audit log
// refuses them, the target keeps every factor, session and its password, and the
// request stays pending so it can be approved once the log is back.
func TestMFAReset_AuditOutage_LeavesMFAIntact(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	req := f.request(t)
	code := f.code(t, f.b.ID)

	base := f.c.storage
	// Call 1 is requireReauth's best-effort mfa.reauth_verified row; call 2 is the
	// first row of the approval's own transaction.
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "LogAuditEvent", NthCall: 2, Kind: faultstorage.KindError, Err: errors.New("injected: audit log refused the row"),
	})
	f.c.storage = fs
	_, err := f.c.ApproveMFAReset(ctx, f.b.ID, false, req.ID, code)
	f.c.storage = base

	require.True(t, fs.Fired(), "the approval's audit write must have been reached")
	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	f.assertTargetIntact(t)
	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
	assert.Zero(t, f.auditCount(t, EventMFAReset))

	_, err = f.c.ApproveMFAReset(ctx, f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.NoError(t, err, "the request is still approvable once the audit log is back")
}

func TestMFAReset_SingleAdminInstallNamesHostCommand(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	// Only A can approve anything: B and C lose their roles.
	roleIDs, err := f.st.GetUserRoleIDsAt(ctx, f.a.ID, storage.Scope{})
	require.NoError(t, err)
	for _, u := range []*models.User{f.b, f.cAdmin} {
		require.NoError(t, f.st.RemoveRole(ctx, u.ID, roleIDs[0], storage.Scope{}))
	}
	_, err = f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{User: "target", Reason: "lost phone", VerifiedBy: "in_person", Code: f.code(t, f.a.ID)})
	require.ErrorIs(t, err, ErrMFAResetNoSecondAdmin)
	assert.Contains(t, MFAResetNoSecondAdminMessage, "keyorix-server admin reset-mfa")
}
