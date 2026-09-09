// remote_storage_conformance_tranche4_misc_test.go — issue #1808, tranche 4.
//
// Covers 26 of the 27 assigned methods, spanning eight source files:
// remote_risk_exceptions.go, remote_notifications.go,
// remote_access_activity.go, remote_sod.go, remote_legal_hold.go,
// remote_break_glass.go (the two read-only survivors,
// GetBreakGlassActivation/ListBreakGlassActivations), remote_audit.go
// (GetRBACAuditLogs only), and remote_stats.go (HealthCheck).
//
// GetAuditLogs is deliberately NOT covered — see the comment where its test
// would otherwise sit (just above TestConformance_GetRBACAuditLogs) for why:
// building it surfaced a genuine, live wire-shape defect (RemoteStorage.
// GetAuditLogs silently returns an empty event list with a correct-looking
// total, against its own real, currently-registered route) that this file's
// "one new file, no other edits" scope cannot fix without touching
// remote_audit.go/audit.go, and CLAUDE.md is explicit that a found defect
// must never be papered over by weakening the assertion to match it.
//
// # A different shape than tranche 2/3, and why
//
// Tranche 2/3 compared RemoteStorage.M(x) against LocalStorage.M(x) run with
// the SAME scenario on both sides, because their methods are raw storage
// primitives on both ends — the proxy handler forwards straight to
// storage.Storage with no extra business logic in between.
//
// Several methods in this tranche are not that shape. Risk exceptions, SoD
// policies, and legal hold are governance controls whose CREATE/APPROVE/
// REVOKE/DELETE/LIFT routes deliberately route through core.KeyorixCore
// SERVER-SIDE (confirmed by reading risk_exceptions_proxy.go, sod_proxy.go,
// legal_hold_proxy.go directly) — re-deriving the acting principal from the
// AUTHENTICATED HTTP SESSION and re-running admin-tier/dual-control/human-only
// checks, rather than trusting anything the wire body carries for actor
// attribution. LocalStorage's own primitives (local_risk_exceptions.go,
// local_sod.go, local_legal_hold.go), by contrast, are raw GORM calls that
// trust the caller's struct completely — the authority check is the CALLING
// core's job, not storage's, on both backends; this tranche calls the raw
// storage primitives directly on the LocalStorage side, without a calling
// core in front of them.
//
// So for that subset, a "same scenario on both sides" comparison would prove
// nothing (LocalStorage would trivially trust whatever we hand it). Instead
// each such test compares LocalStorage's raw, fully-caller-trusting contract
// against RemoteStorage's ACTUAL server-enforced contract, using a
// deliberately FORGED wire attribution field (CreatedBy/ApprovedBy/RevokedBy/
// PlacedBy/ReleasedBy) as the differential probe: does the real router+handler
// ignore it and derive the true actor from the session, the way tranche 3's
// TestConformance_RevokeBreakGlassActivation already proved for break-glass
// revocation? This generalizes that discipline to every method in this file
// carrying a similar actor-identity field, per the task brief's own callout.
//
// HealthCheck (remote_stats.go) has no LocalStorage analog at all — see its
// own test for the documented deviation.
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// timePtr returns a *time.Time pointing at a copy of t -- a small helper so
// call sites can inline a pointer to a computed time.Time value.
func timePtr(t time.Time) *time.Time { return &t }

// newAdminSession creates a brand-new user, grants it the global "admin" role
// directly at the storage layer (the same globalScope := coreStorage.Scope{}
// pattern TestConformance_RemoveGlobalAdminRoleGuarded uses), logs it in for a
// REAL session token, and returns both the user (for its ID, when a test only
// needs to assert on an actor identity) and a RemoteStorage client
// authenticated as them.
//
// Needed throughout this file wherever a core-layer function requires a
// human, admin-tier actor: h.rs's shared node/machine credential can never
// satisfy this (isMachineActor(r) is unconditionally true for it, and
// actorID(r) always resolves to 0 for a machine caller, which holds no role
// grant of its own — see catalog.go's actorID/isMachineActor doc comments).
func newAdminSession(t *testing.T, h *conformanceHarness, suffix string) (*models.User, *store.RemoteStorage) {
	t.Helper()
	ctx := context.Background()
	username := "conformance-t4-" + suffix
	password := "Conformance-T4-Pw-1!"
	user, err := h.upstreamCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", Password: password,
	})
	require.NoError(t, err)
	adminRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, h.ls.AssignRole(ctx, user.ID, adminRole.ID, coreStorage.Scope{}))
	session, _, err := h.upstreamCore.Login(ctx, &core.LoginRequest{Username: username, Password: password})
	require.NoError(t, err)
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: session.SessionToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	return user, rs
}

// ============================================================================
// remote_risk_exceptions.go
// ============================================================================

// --- CreateRiskException ---

func TestConformance_CreateRiskException(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	userToken := createTestToken(t, h.upstreamCore) // session for h.adminUserID (global admin)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	const forgedCreatedBy = 999999

	// LocalStorage's own primitive: a raw insert that fully trusts whatever
	// CreatedBy the caller sets -- no actor derivation, no human/machine
	// check, no admin-tier check. This is the raw contract the proxy's own
	// additional server-side hardening (below) deliberately narrows.
	localException, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-cre-local", Category: "other", Justification: "conformance test",
		CreatedBy: forgedCreatedBy, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(forgedCreatedBy), localException.CreatedBy,
		"sanity: LocalStorage.CreateRiskException trusts the caller-supplied CreatedBy verbatim")

	// RemoteStorage.CreateRiskException, authenticated as a real human
	// admin-tier user, sending the SAME forged CreatedBy on the wire.
	// CreateRiskExceptionProxy decodes only Title/Category/Reference/
	// Justification/ExpiresAt off the wire body and passes actorID(r) to
	// core.CreateRiskException -- body.CreatedBy is never read.
	remoteException, err := rsAsUser.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-cre-remote", Category: "other", Justification: "conformance test",
		CreatedBy: forgedCreatedBy, ExpiresAt: expiresAt,
	})
	require.NoError(t, err, "RemoteStorage.CreateRiskException must succeed for a genuine human admin-tier actor")
	assert.Equal(t, h.adminUserID, remoteException.CreatedBy,
		"CreatedBy must be derived from the authenticated session server-side, not trusted from the wire -- "+
			"the forged value above must never land")
	assert.Equal(t, "conformance-cre-remote", remoteException.Title)
	assert.Equal(t, "other", remoteException.Category)
	assert.True(t, expiresAt.Equal(remoteException.ExpiresAt), "ExpiresAt must round-trip")
	assert.False(t, remoteException.Revoked)
	assert.False(t, remoteException.Approved)

	persisted, err := h.ls.GetRiskException(ctx, remoteException.ID)
	require.NoError(t, err)
	assert.Equal(t, h.adminUserID, persisted.CreatedBy,
		"the real CreatedBy must actually be persisted server-side, not just reported so in the response")

	// Negative: a machine-authenticated caller (h.rs's node/machine
	// credential) must be refused entirely -- dual control's own "creator"
	// must always be attributable to a real human.
	_, err = h.rs.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-cre-machine", Category: "other", Justification: "conformance test", ExpiresAt: expiresAt,
	})
	assert.Error(t, err, "RemoteStorage.CreateRiskException must refuse a machine-authenticated caller")
}

// --- GetRiskException ---

func TestConformance_GetRiskException(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

	// GetRiskExceptionProxy is a raw storage passthrough (no core call, no
	// actor check) -- confirmed by reading risk_exceptions_proxy.go -- so
	// h.rs's shared node/machine credential can read it directly.
	seeded, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-gre", Category: "other", Justification: "conformance test",
		CreatedBy: h.adminUserID, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)

	localGot, err := h.ls.GetRiskException(ctx, seeded.ID)
	require.NoError(t, err)
	remoteGot, err := h.rs.GetRiskException(ctx, seeded.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "GetRiskException", localGot, remoteGot, nil)

	_, err = h.rs.GetRiskException(ctx, seeded.ID+999999)
	assert.Error(t, err, "a nonexistent risk exception id must error, not silently return a zero value")
}

// --- ListRiskExceptions ---

func TestConformance_ListRiskExceptions(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

	active, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-lre-active", Category: "other", Justification: "j", CreatedBy: h.adminUserID, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	revoked, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-lre-revoked", Category: "other", Justification: "j", CreatedBy: h.adminUserID, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	revokedAt := time.Now().UTC()
	revoked.Revoked = true
	revoked.RevokedBy = h.adminUserID
	revoked.RevokedAt = &revokedAt
	matched, err := h.ls.RevokeRiskExceptionIfNotRevoked(ctx, revoked)
	require.NoError(t, err)
	require.True(t, matched)

	localAll, err := h.ls.ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	remoteAll, err := h.rs.ListRiskExceptions(ctx, false)
	require.NoError(t, err)
	require.Equal(t, len(localAll), len(remoteAll), "active_only=false must return the same row count on both paths")

	localActiveOnly, err := h.ls.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	remoteActiveOnly, err := h.rs.ListRiskExceptions(ctx, true)
	require.NoError(t, err)
	require.Equal(t, len(localActiveOnly), len(remoteActiveOnly))
	foundActive := false
	for _, e := range remoteActiveOnly {
		assert.NotEqual(t, revoked.ID, e.ID, "active_only=true must exclude the revoked exception")
		if e.ID == active.ID {
			foundActive = true
		}
	}
	assert.True(t, foundActive, "active_only=true must still include the non-revoked exception")
}

// --- ApproveRiskExceptionIfPending ---

func TestConformance_ApproveRiskExceptionIfPending(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	const forgedApprovedBy = 888888

	// LocalStorage's raw CAS primitive: no actor/dual-control check at all --
	// it trusts whatever ApprovedBy the caller sets.
	localException, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-arei-local", Category: "other", Justification: "j",
		CreatedBy: h.adminUserID, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	approvedAt := time.Now().UTC()
	localException.Approved = true
	localException.ApprovedBy = forgedApprovedBy
	localException.ApprovedAt = &approvedAt
	localMatched, err := h.ls.ApproveRiskExceptionIfPending(ctx, localException)
	require.NoError(t, err)
	assert.True(t, localMatched, "sanity: the raw CAS primitive must match a genuinely pending exception")
	localPersisted, err := h.ls.GetRiskException(ctx, localException.ID)
	require.NoError(t, err)
	assert.Equal(t, uint(forgedApprovedBy), localPersisted.ApprovedBy,
		"sanity: LocalStorage.ApproveRiskExceptionIfPending trusts the caller-supplied ApprovedBy verbatim")

	// RemoteStorage: real dual control -- the creator and approver must be
	// two DIFFERENT human, admin-tier actors, and ApproveRiskExceptionProxy
	// doesn't even decode a request body (it only reads the URL id) -- the
	// approver identity comes entirely from the authenticated session.
	creatorToken := createTestToken(t, h.upstreamCore)
	rsCreator, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: creatorToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	approver, rsApprover := newAdminSession(t, h, "arei-approver")

	remoteException, err := rsCreator.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-arei-remote", Category: "other", Justification: "j", ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	require.Equal(t, h.adminUserID, remoteException.CreatedBy)

	// Self-approval must be refused -- dual control (#170): the creator can
	// never approve their own exception.
	_, err = rsCreator.ApproveRiskExceptionIfPending(ctx, remoteException)
	assert.Error(t, err, "the exception's own creator must not be able to approve it (dual control)")

	remoteException.Approved = true
	remoteException.ApprovedBy = forgedApprovedBy
	remoteMatched, err := rsApprover.ApproveRiskExceptionIfPending(ctx, remoteException)
	require.NoError(t, err)
	assert.True(t, remoteMatched,
		"RemoteStorage.ApproveRiskExceptionIfPending must match a genuinely pending exception approved by a "+
			"different admin-tier human")

	remotePersisted, err := h.ls.GetRiskException(ctx, remoteException.ID)
	require.NoError(t, err)
	assert.True(t, remotePersisted.Approved)
	assert.Equal(t, approver.ID, remotePersisted.ApprovedBy,
		"ApprovedBy must be derived from the authenticated session server-side, not trusted from the wire -- "+
			"the forged value above must never land")

	// Wrong-state: an already-approved exception must not match a second
	// time -- a normal matched=false outcome, not an error.
	secondMatched, err := rsApprover.ApproveRiskExceptionIfPending(ctx, remoteException)
	require.NoError(t, err)
	assert.False(t, secondMatched)
}

// --- RevokeRiskExceptionIfNotRevoked ---

func TestConformance_RevokeRiskExceptionIfNotRevoked(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	const forgedRevokedBy = 777777

	localException, err := h.ls.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-rrei-local", Category: "other", Justification: "j",
		CreatedBy: h.adminUserID, ExpiresAt: expiresAt,
	})
	require.NoError(t, err)
	revokedAt := time.Now().UTC()
	localException.Revoked = true
	localException.RevokedBy = forgedRevokedBy
	localException.RevokedAt = &revokedAt
	localMatched, err := h.ls.RevokeRiskExceptionIfNotRevoked(ctx, localException)
	require.NoError(t, err)
	assert.True(t, localMatched)
	localPersisted, err := h.ls.GetRiskException(ctx, localException.ID)
	require.NoError(t, err)
	assert.Equal(t, uint(forgedRevokedBy), localPersisted.RevokedBy,
		"sanity: LocalStorage.RevokeRiskExceptionIfNotRevoked trusts the caller-supplied RevokedBy verbatim")

	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	remoteException, err := rsAsUser.CreateRiskException(ctx, &models.RiskException{
		Title: "conformance-rrei-remote", Category: "other", Justification: "j", ExpiresAt: expiresAt,
	})
	require.NoError(t, err)

	remoteException.Revoked = true
	remoteException.RevokedBy = forgedRevokedBy
	remoteMatched, err := rsAsUser.RevokeRiskExceptionIfNotRevoked(ctx, remoteException)
	require.NoError(t, err, "RemoteStorage.RevokeRiskExceptionIfNotRevoked must succeed for the exception's own creator")
	assert.True(t, remoteMatched)

	remotePersisted, err := h.ls.GetRiskException(ctx, remoteException.ID)
	require.NoError(t, err)
	assert.True(t, remotePersisted.Revoked)
	assert.Equal(t, h.adminUserID, remotePersisted.RevokedBy,
		"RevokedBy must be derived from the authenticated session server-side, not trusted from the wire -- "+
			"the forged value above must never land")

	secondMatched, err := rsAsUser.RevokeRiskExceptionIfNotRevoked(ctx, remoteException)
	require.NoError(t, err, "an already-revoked exception is a normal matched=false outcome, not an error")
	assert.False(t, secondMatched)
}

// ============================================================================
// remote_notifications.go
// ============================================================================

// --- CreateNotification ---

func TestConformance_CreateNotification(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	localUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-cn-local", Email: "conformance-cn-local@example.com", DisplayName: "Conformance CN Local", IsActive: true,
	})
	require.NoError(t, err)
	localNotif, err := h.ls.CreateNotification(ctx, &models.Notification{
		UserID: localUser.ID, Type: "conformance.local", Title: "Local Title", Message: "Local Message",
		Link: "/local", Severity: models.NotificationSeverityWarning, CreatedAt: time.Now().UTC().Truncate(time.Second),
	})
	require.NoError(t, err)
	assert.False(t, localNotif.IsRead)

	remoteUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-cn-remote", Email: "conformance-cn-remote@example.com", DisplayName: "Conformance CN Remote", IsActive: true,
	})
	require.NoError(t, err)
	sentCreatedAt := time.Now().UTC().Truncate(time.Second)
	remoteNotif, err := h.rs.CreateNotification(ctx, &models.Notification{
		UserID: remoteUser.ID, Type: "conformance.remote", Title: "Remote Title", Message: "Remote Message",
		Link: "/remote", Severity: models.NotificationSeverityWarning, CreatedAt: sentCreatedAt,
	})
	require.NoError(t, err, "RemoteStorage.CreateNotification must succeed for a genuine, non-zero recipient")
	assert.Equal(t, remoteUser.ID, remoteNotif.UserID)
	assert.Equal(t, "conformance.remote", remoteNotif.Type)
	assert.Equal(t, "Remote Title", remoteNotif.Title)
	assert.Equal(t, "Remote Message", remoteNotif.Message)
	assert.Equal(t, "/remote", remoteNotif.Link)
	assert.Equal(t, models.NotificationSeverityWarning, remoteNotif.Severity)
	assert.False(t, remoteNotif.IsRead, "CreateNotificationProxy always creates with IsRead=false")
	assert.True(t, sentCreatedAt.Equal(remoteNotif.CreatedAt))

	persisted, err := h.ls.ListNotifications(ctx, remoteUser.ID, false, 10)
	require.NoError(t, err)
	require.Len(t, persisted, 1, "the notification must actually be persisted server-side, not just reported so")
	assertFieldExhaustiveEqual(t, "CreateNotification (wire round trip)", remoteNotif, persisted[0], nil)

	// Negative: a zero recipient must be refused, not silently create an
	// unaddressed notification.
	_, err = h.rs.CreateNotification(ctx, &models.Notification{
		Type: "conformance.norecipient", Title: "x", Message: "y", CreatedAt: time.Now().UTC(),
	})
	assert.Error(t, err, "CreateNotificationProxy must refuse a zero UserID")
}

// --- ListNotifications ---

func TestConformance_ListNotifications(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// ListNotifications/CountUnreadNotifications/MarkNotificationRead/
	// MarkAllNotificationsRead are all self-scoped: the server derives the
	// caller from the authenticated session (ADR-024), never from a wire
	// userID (notifications_handler.go's List/MarkRead/MarkAllRead all read
	// middleware.GetUserFromContext, which is nil for h.rs's shared
	// node/machine credential -- exactly why tranche 3's
	// RevokeBreakGlassActivation needed a second, human-authenticated client
	// instead of h.rs).
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		_, err := h.ls.CreateNotification(ctx, &models.Notification{
			UserID: h.adminUserID, Type: fmt.Sprintf("conformance.ln.unread.%d", i),
			Title: fmt.Sprintf("Unread %d", i), Message: "m", CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		})
		require.NoError(t, err)
	}
	readOne, err := h.ls.CreateNotification(ctx, &models.Notification{
		UserID: h.adminUserID, Type: "conformance.ln.read", Title: "Read", Message: "m",
		CreatedAt: time.Now().UTC().Add(2 * time.Second),
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.MarkNotificationRead(ctx, readOne.ID, h.adminUserID))

	localAll, err := h.ls.ListNotifications(ctx, h.adminUserID, false, 10)
	require.NoError(t, err)
	require.Len(t, localAll, 3, "sanity: all three notifications must be visible via LocalStorage")

	remoteAll, err := rsAsUser.ListNotifications(ctx, 0 /* ignored -- self-scoped */, false, 10)
	require.NoError(t, err, "RemoteStorage.ListNotifications must succeed for a genuine authenticated human session")
	require.Len(t, remoteAll, len(localAll),
		"the self-scoped GET /notifications route must return the SAME rows LocalStorage sees for this user")
	for i := range localAll {
		assert.Equal(t, localAll[i].ID, remoteAll[i].ID, "same order, same rows -- both read the identical underlying data")
		assert.Equal(t, localAll[i].Type, remoteAll[i].Type)
		assert.Equal(t, localAll[i].IsRead, remoteAll[i].IsRead)
	}

	localUnreadOnly, err := h.ls.ListNotifications(ctx, h.adminUserID, true, 10)
	require.NoError(t, err)
	remoteUnreadOnly, err := rsAsUser.ListNotifications(ctx, 0, true, 10)
	require.NoError(t, err)
	assert.Equal(t, len(localUnreadOnly), len(remoteUnreadOnly), "unread=true must filter identically on both paths")
	for _, n := range remoteUnreadOnly {
		assert.NotEqual(t, readOne.ID, n.ID, "the already-read notification must be excluded from unread=true")
	}
}

// --- CountUnreadNotifications ---

func TestConformance_CountUnreadNotifications(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := h.ls.CreateNotification(ctx, &models.Notification{
			UserID: h.adminUserID, Type: fmt.Sprintf("conformance.cun.%d", i), Title: "t", Message: "m", CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	localCount, err := h.ls.CountUnreadNotifications(ctx, h.adminUserID)
	require.NoError(t, err)
	require.EqualValues(t, 3, localCount, "sanity")

	remoteCount, err := rsAsUser.CountUnreadNotifications(ctx, 0 /* ignored -- self-scoped */)
	require.NoError(t, err, "RemoteStorage.CountUnreadNotifications must succeed for a genuine authenticated human session")
	assert.Equal(t, localCount, remoteCount,
		"the unread count must reflect the SAME underlying rows LocalStorage sees for this user, not a stale or "+
			"differently-scoped count")
}

// --- MarkNotificationRead ---

func TestConformance_MarkNotificationRead(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	localNotif, err := h.ls.CreateNotification(ctx, &models.Notification{
		UserID: h.adminUserID, Type: "conformance.mnr.local", Title: "t", Message: "m", CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.MarkNotificationRead(ctx, localNotif.ID, h.adminUserID))
	localAfter, err := h.ls.ListNotifications(ctx, h.adminUserID, false, 10)
	require.NoError(t, err)
	require.True(t, findNotificationRead(localAfter, localNotif.ID), "sanity: LocalStorage.MarkNotificationRead must mark the row read")

	remoteNotif, err := h.ls.CreateNotification(ctx, &models.Notification{
		UserID: h.adminUserID, Type: "conformance.mnr.remote", Title: "t", Message: "m", CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, rsAsUser.MarkNotificationRead(ctx, remoteNotif.ID, 0 /* ignored -- self-scoped */),
		"RemoteStorage.MarkNotificationRead must succeed for the authenticated caller's own notification")
	remoteAfter, err := h.ls.ListNotifications(ctx, h.adminUserID, false, 10)
	require.NoError(t, err)
	assert.True(t, findNotificationRead(remoteAfter, remoteNotif.ID),
		"the notification marked read via RemoteStorage must actually be read server-side, not just report success")

	// Negative: marking a nonexistent notification read must error, not
	// silently succeed, on both paths.
	assert.Error(t, h.ls.MarkNotificationRead(ctx, remoteNotif.ID+999999, h.adminUserID))
	assert.Error(t, rsAsUser.MarkNotificationRead(ctx, remoteNotif.ID+999999, 0))
}

func findNotificationRead(notifs []*models.Notification, id uint) bool {
	for _, n := range notifs {
		if n.ID == id {
			return n.IsRead
		}
	}
	return false
}

// --- MarkAllNotificationsRead ---

func TestConformance_MarkAllNotificationsRead(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	// A bystander user whose unrelated notification must NOT be touched --
	// the self-scoped route must only ever act on the AUTHENTICATED caller's
	// own rows, matching tranche 2's bystander-scope-drop discipline.
	bystander, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-marn-bystander", Email: "conformance-marn-bystander@example.com", DisplayName: "Bystander", IsActive: true,
	})
	require.NoError(t, err)
	bystanderNotif, err := h.ls.CreateNotification(ctx, &models.Notification{
		UserID: bystander.ID, Type: "conformance.marn.bystander", Title: "t", Message: "m", CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		_, err := h.ls.CreateNotification(ctx, &models.Notification{
			UserID: h.adminUserID, Type: fmt.Sprintf("conformance.marn.%d", i), Title: "t", Message: "m", CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	require.NoError(t, rsAsUser.MarkAllNotificationsRead(ctx, 0 /* ignored -- self-scoped */),
		"RemoteStorage.MarkAllNotificationsRead must succeed for the authenticated caller")

	callerAfter, err := h.ls.ListNotifications(ctx, h.adminUserID, true, 10)
	require.NoError(t, err)
	assert.Empty(t, callerAfter, "every one of the caller's own notifications must actually be marked read server-side")

	bystanderAfter, err := h.ls.ListNotifications(ctx, bystander.ID, true, 10)
	require.NoError(t, err)
	require.Len(t, bystanderAfter, 1,
		"a bystander user's unrelated notification must survive -- the self-scoped route must only touch the "+
			"authenticated caller's own rows")
	assert.Equal(t, bystanderNotif.ID, bystanderAfter[0].ID)
}

// ============================================================================
// remote_access_activity.go
// ============================================================================

// seedAccessActivityEvent writes one audit_events row directly via
// h.ls.LogAuditEvent, scoped to projectID/userID/eventType -- the fixture
// shape LastUser*Activity's shared lastUserActivityByEventTypes query reads
// (local_access_activity.go).
func seedAccessActivityEvent(t *testing.T, h *conformanceHarness, projectID, userID uint, eventType string, at time.Time) {
	t.Helper()
	uid, pid, success := userID, projectID, true
	require.NoError(t, h.ls.LogAuditEvent(context.Background(), &models.AuditEvent{
		EventType: eventType, UserID: &uid, ProjectID: &pid, Success: &success, EventTime: at,
	}))
}

// assertAccessActivityMatches compares two map[uint]time.Time results the way
// assertFieldExhaustiveEqual would for a struct field: time.Time needs
// .Equal(), not ==/DeepEqual (see fieldDiffs' own doc for why), and the two
// key sets must match exactly -- a dropped/wrong project_id on the wire would
// either drop users or pull in ones that don't belong.
func assertAccessActivityMatches(t *testing.T, label string, local, remote map[uint]time.Time) {
	t.Helper()
	require.Len(t, remote, len(local), "%s: user-count mismatch", label)
	for uid, lt := range local {
		rt, ok := remote[uid]
		require.True(t, ok, "%s: remote result missing user %d", label, uid)
		assert.True(t, lt.Equal(rt), "%s: user %d: want %v got %v", label, uid, lt, rt)
	}
}

func TestConformance_LastUserSecretActivity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	activeUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusa-active", Email: "conformance-lusa-active@example.com", DisplayName: "Active", IsActive: true})
	require.NoError(t, err)
	dormantUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusa-dormant", Email: "conformance-lusa-dormant@example.com", DisplayName: "Dormant", IsActive: true})
	require.NoError(t, err)
	seedAccessActivityEvent(t, h, h.projectID, activeUser.ID, "secret.read", time.Now().UTC().Truncate(time.Second))

	localActivity, err := h.ls.LastUserSecretActivity(ctx, h.projectID)
	require.NoError(t, err)
	remoteActivity, err := h.rs.LastUserSecretActivity(ctx, h.projectID)
	require.NoError(t, err)
	assertAccessActivityMatches(t, "LastUserSecretActivity", localActivity, remoteActivity)
	assert.Contains(t, remoteActivity, activeUser.ID)
	assert.NotContains(t, remoteActivity, dormantUser.ID, "a user with no matching event must be absent, not zero-valued")
}

func TestConformance_LastUserRoleManagementActivity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	activeUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lurma-active", Email: "conformance-lurma-active@example.com", DisplayName: "Active", IsActive: true})
	require.NoError(t, err)
	dormantUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lurma-dormant", Email: "conformance-lurma-dormant@example.com", DisplayName: "Dormant", IsActive: true})
	require.NoError(t, err)
	seedAccessActivityEvent(t, h, h.projectID, activeUser.ID, "role.assigned", time.Now().UTC().Truncate(time.Second))

	localActivity, err := h.ls.LastUserRoleManagementActivity(ctx, h.projectID)
	require.NoError(t, err)
	remoteActivity, err := h.rs.LastUserRoleManagementActivity(ctx, h.projectID)
	require.NoError(t, err)
	assertAccessActivityMatches(t, "LastUserRoleManagementActivity", localActivity, remoteActivity)
	assert.Contains(t, remoteActivity, activeUser.ID)
	assert.NotContains(t, remoteActivity, dormantUser.ID)
}

func TestConformance_LastUserSecretDeletionActivity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	activeUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusda-active", Email: "conformance-lusda-active@example.com", DisplayName: "Active", IsActive: true})
	require.NoError(t, err)
	dormantUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusda-dormant", Email: "conformance-lusda-dormant@example.com", DisplayName: "Dormant", IsActive: true})
	require.NoError(t, err)
	seedAccessActivityEvent(t, h, h.projectID, activeUser.ID, "secret.deleted", time.Now().UTC().Truncate(time.Second))

	localActivity, err := h.ls.LastUserSecretDeletionActivity(ctx, h.projectID)
	require.NoError(t, err)
	remoteActivity, err := h.rs.LastUserSecretDeletionActivity(ctx, h.projectID)
	require.NoError(t, err)
	assertAccessActivityMatches(t, "LastUserSecretDeletionActivity", localActivity, remoteActivity)
	assert.Contains(t, remoteActivity, activeUser.ID)
	assert.NotContains(t, remoteActivity, dormantUser.ID)
}

func TestConformance_LastUserSecretReadActivity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	activeUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusra-active", Email: "conformance-lusra-active@example.com", DisplayName: "Active", IsActive: true})
	require.NoError(t, err)
	writeOnlyUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-lusra-write", Email: "conformance-lusra-write@example.com", DisplayName: "WriteOnly", IsActive: true})
	require.NoError(t, err)
	seedAccessActivityEvent(t, h, h.projectID, activeUser.ID, "secret.read", time.Now().UTC().Truncate(time.Second))
	// writeOnlyUser only ever writes, never reads -- the read-only bucket
	// must not credit their write activity (the plain-tier read/write split,
	// #487 round 112).
	seedAccessActivityEvent(t, h, h.projectID, writeOnlyUser.ID, "secret.created", time.Now().UTC().Truncate(time.Second))

	localActivity, err := h.ls.LastUserSecretReadActivity(ctx, h.projectID)
	require.NoError(t, err)
	remoteActivity, err := h.rs.LastUserSecretReadActivity(ctx, h.projectID)
	require.NoError(t, err)
	assertAccessActivityMatches(t, "LastUserSecretReadActivity", localActivity, remoteActivity)
	assert.Contains(t, remoteActivity, activeUser.ID)
	assert.NotContains(t, remoteActivity, writeOnlyUser.ID, "a write-only event must not satisfy the read-activity bucket")
}

func TestConformance_LastUserSecretWriteActivity(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	activeUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-luswa-active", Email: "conformance-luswa-active@example.com", DisplayName: "Active", IsActive: true})
	require.NoError(t, err)
	readOnlyUser, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-luswa-read", Email: "conformance-luswa-read@example.com", DisplayName: "ReadOnly", IsActive: true})
	require.NoError(t, err)
	seedAccessActivityEvent(t, h, h.projectID, activeUser.ID, "secret.updated", time.Now().UTC().Truncate(time.Second))
	seedAccessActivityEvent(t, h, h.projectID, readOnlyUser.ID, "secret.read", time.Now().UTC().Truncate(time.Second))

	localActivity, err := h.ls.LastUserSecretWriteActivity(ctx, h.projectID)
	require.NoError(t, err)
	remoteActivity, err := h.rs.LastUserSecretWriteActivity(ctx, h.projectID)
	require.NoError(t, err)
	assertAccessActivityMatches(t, "LastUserSecretWriteActivity", localActivity, remoteActivity)
	assert.Contains(t, remoteActivity, activeUser.ID)
	assert.NotContains(t, remoteActivity, readOnlyUser.ID, "a read-only event must not satisfy the write-activity bucket")
}

// ============================================================================
// remote_sod.go
// ============================================================================

// --- CreateSoDPolicy ---

func TestConformance_CreateSoDPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	const forgedCreatedBy = 555555

	localPolicy, err := h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: "conformance-csp-local", PermissionA: "roles.assign", PermissionB: "secrets.delete",
		CreatedBy: forgedCreatedBy, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	assert.Equal(t, uint(forgedCreatedBy), localPolicy.CreatedBy,
		"sanity: LocalStorage.CreateSoDPolicy trusts the caller-supplied CreatedBy verbatim")

	remotePolicy, err := rsAsUser.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: "conformance-csp-remote", PermissionA: "roles.assign", PermissionB: "secrets.delete", CreatedBy: forgedCreatedBy,
	})
	require.NoError(t, err, "RemoteStorage.CreateSoDPolicy must succeed for a genuine human admin-tier actor")
	assert.Equal(t, h.adminUserID, remotePolicy.CreatedBy,
		"CreatedBy must be derived from the authenticated session server-side, not trusted from the wire")

	persisted, err := h.ls.GetSoDPolicy(ctx, remotePolicy.ID)
	require.NoError(t, err)
	assert.Equal(t, h.adminUserID, persisted.CreatedBy)

	// Negative: a machine-authenticated caller must be refused -- creating a
	// policy requires an admin-tier HUMAN actor, and a machine credential's
	// actorID(r) resolves to 0, which holds no role grant.
	_, err = h.rs.CreateSoDPolicy(ctx, &models.SoDPolicy{Name: "conformance-csp-machine", PermissionA: "a", PermissionB: "b"})
	assert.Error(t, err, "RemoteStorage.CreateSoDPolicy must refuse a machine-authenticated caller")
}

// --- DeleteSoDPolicy ---

func TestConformance_DeleteSoDPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	localPolicy, err := h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: "conformance-dsp-local", PermissionA: "a1", PermissionB: "b1", CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteSoDPolicy(ctx, localPolicy.ID), "sanity: LocalStorage.DeleteSoDPolicy has no actor check at all")

	remotePolicy, err := h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: "conformance-dsp-remote", PermissionA: "a2", PermissionB: "b2", CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, rsAsUser.DeleteSoDPolicy(ctx, remotePolicy.ID),
		"RemoteStorage.DeleteSoDPolicy must succeed for the policy's own creator")
	_, err = h.ls.GetSoDPolicy(ctx, remotePolicy.ID)
	assert.Error(t, err, "the policy deleted via RemoteStorage must actually be gone server-side")

	// Negative: deleting a nonexistent policy must error identically on both paths.
	assert.Error(t, h.ls.DeleteSoDPolicy(ctx, remotePolicy.ID+999999))
	assert.Error(t, rsAsUser.DeleteSoDPolicy(ctx, remotePolicy.ID+999999))
}

// --- GetSoDPolicy ---

func TestConformance_GetSoDPolicy(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	seeded, err := h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: "conformance-gsp", Description: "d", PermissionA: "a", PermissionB: "b", CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	localGot, err := h.ls.GetSoDPolicy(ctx, seeded.ID)
	require.NoError(t, err)
	remoteGot, err := h.rs.GetSoDPolicy(ctx, seeded.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "GetSoDPolicy", localGot, remoteGot, nil)

	_, err = h.rs.GetSoDPolicy(ctx, seeded.ID+999999)
	assert.Error(t, err)
}

// --- ListSoDPolicies ---

func TestConformance_ListSoDPolicies(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	_, err := h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{Name: "conformance-lsp-1", PermissionA: "a1", PermissionB: "b1", CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC()})
	require.NoError(t, err)
	_, err = h.ls.CreateSoDPolicy(ctx, &models.SoDPolicy{Name: "conformance-lsp-2", PermissionA: "a2", PermissionB: "b2", CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC()})
	require.NoError(t, err)

	localList, err := h.ls.ListSoDPolicies(ctx)
	require.NoError(t, err)
	remoteList, err := h.rs.ListSoDPolicies(ctx)
	require.NoError(t, err)
	require.Equal(t, len(localList), len(remoteList))
	for i := range localList {
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListSoDPolicies[%d]", i), localList[i], remoteList[i], nil)
	}
}

// ============================================================================
// remote_legal_hold.go
// ============================================================================

// --- GetActiveLegalHold ---

func TestConformance_GetActiveLegalHold(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Precondition: no legal hold is active yet.
	localNone, err := h.ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	remoteNone, err := h.rs.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, localNone, "sanity: no hold is active yet")
	assert.Nil(t, remoteNone, "RemoteStorage.GetActiveLegalHold must also report no active hold")

	seeded, err := h.ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "conformance-galh", PlacedBy: h.adminUserID, PlacedAt: time.Now().UTC(), Released: false})
	require.NoError(t, err)

	// internal/storage/remote.HTTPClient caches successful GET responses for
	// 5 minutes, keyed by path, invalidated only by a MUTATION performed
	// through that SAME client instance (client.go's cache/cacheMux) -- h.rs
	// already served (and cached) "no active hold" for this exact path
	// (/api/v1/system/legal-hold/active, no query string) via remoteNone
	// above, and the mutation just above went through h.ls, not h.rs, so
	// h.rs's cache is never invalidated. Reusing h.rs here would silently
	// replay the stale cached response instead of exercising the real
	// round trip -- mint a fresh client (empty cache) for the post-mutation
	// read instead, matching this file's own createNodeToken-based node
	// credential exactly.
	rsFresh, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: h.nodeToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	localGot, err := h.ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	remoteGot, err := rsFresh.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, remoteGot)
	assertFieldExhaustiveEqual(t, "GetActiveLegalHold", localGot, remoteGot, nil)
	assert.Equal(t, seeded.ID, remoteGot.ID)
}

// --- CreateLegalHold ---

func TestConformance_CreateLegalHold(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	const forgedPlacedBy = 444444

	// Legal hold is a deployment-wide SINGLETON (a partial unique index
	// allows at most one un-released row) -- unlike every other method in
	// this file, the local and remote scenarios below cannot coexist as two
	// simultaneously "active" rows, so they run sequentially against the
	// same slot instead of against two independently seeded rows.
	remoteHold, err := rsAsUser.CreateLegalHold(ctx, &models.LegalHold{Reason: "conformance-clh-remote", PlacedBy: forgedPlacedBy})
	require.NoError(t, err, "RemoteStorage.CreateLegalHold must succeed for a genuine human admin-tier actor")
	assert.Equal(t, h.adminUserID, remoteHold.PlacedBy,
		"PlacedBy must be derived from the authenticated session server-side, not trusted from the wire")
	assert.Equal(t, "conformance-clh-remote", remoteHold.Reason)
	assert.False(t, remoteHold.Released)

	persisted, err := h.ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, h.adminUserID, persisted.PlacedBy)

	// Negative: a second placement while one is already active must be
	// refused, reconstructing the SAME sentinel a local caller's own
	// pre-check/DB-race branch would produce -- proving the DB-level partial
	// unique index's rejection survives the HTTP hop.
	_, err = rsAsUser.CreateLegalHold(ctx, &models.LegalHold{Reason: "conformance-clh-second"})
	assert.ErrorIs(t, err, coreStorage.ErrLegalHoldAlreadyActive,
		"a second concurrent placement must be refused, reconstructing the same sentinel a local caller would see")

	// Free the slot, then exercise LocalStorage's own raw contract: unlike
	// the proxy above, it trusts whatever PlacedBy the caller sets.
	require.NoError(t, h.ls.UpdateLegalHold(ctx, &models.LegalHold{
		ID: persisted.ID, Reason: persisted.Reason, PlacedBy: persisted.PlacedBy, PlacedAt: persisted.PlacedAt,
		Released: true, ReleasedBy: h.adminUserID, ReleasedAt: timePtr(time.Now().UTC()), ReleaseReason: "freeing the slot for the local-contract check",
	}))
	localHold, err := h.ls.CreateLegalHold(ctx, &models.LegalHold{
		Reason: "conformance-clh-local", PlacedBy: forgedPlacedBy, PlacedAt: time.Now().UTC(), Released: false,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(forgedPlacedBy), localHold.PlacedBy,
		"sanity: LocalStorage.CreateLegalHold trusts the caller-supplied PlacedBy verbatim")
}

// --- UpdateLegalHold ---

func TestConformance_UpdateLegalHold(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	const forgedReleasedBy = 333333

	// LocalStorage's own raw contract first: an unconditional Save that
	// trusts whatever ReleasedBy the caller sets.
	localHold, err := h.ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "conformance-ulh-local", PlacedBy: h.adminUserID, PlacedAt: time.Now().UTC(), Released: false})
	require.NoError(t, err)
	localHold.Released = true
	localHold.ReleasedBy = forgedReleasedBy
	localHold.ReleasedAt = timePtr(time.Now().UTC())
	localHold.ReleaseReason = "conformance local release"
	require.NoError(t, h.ls.UpdateLegalHold(ctx, localHold))
	assert.Equal(t, uint(forgedReleasedBy), localHold.ReleasedBy,
		"sanity: LocalStorage.UpdateLegalHold trusts the caller-supplied ReleasedBy verbatim")
	// storage.Storage exposes no GetLegalHold-by-ID -- GetActiveLegalHold is
	// the only read primitive, and it now (correctly) reports no active hold.
	afterLocalRelease, err := h.ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, afterLocalRelease, "sanity: the just-released hold must no longer be the active one")

	// Remote: place fresh (the slot is free again), then lift via
	// RemoteStorage with a forged ReleasedBy. UpdateLegalHoldProxy routes
	// through core.LiftLegalHold, which re-resolves the active hold and
	// every field itself except ReleaseReason -- there is no
	// GetLegalHold-by-ID to read the released row's ReleasedBy back
	// directly, so the derivation check instead reads core.LiftLegalHold's
	// own audit trail (writeAuditEvent's userID parameter is the actor core
	// resolved, EventLegalHoldLifted) -- an equally direct signal of which
	// actor the server actually attributed the lift to.
	remoteHold, err := h.ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "conformance-ulh-remote", PlacedBy: h.adminUserID, PlacedAt: time.Now().UTC(), Released: false})
	require.NoError(t, err)
	require.NoError(t, rsAsUser.UpdateLegalHold(ctx, &models.LegalHold{
		ID: remoteHold.ID, ReleaseReason: "conformance remote release", ReleasedBy: forgedReleasedBy,
	}), "RemoteStorage.UpdateLegalHold must succeed for the placing admin lifting the currently-active hold")

	afterRemoteRelease, err := h.ls.GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, afterRemoteRelease, "the hold lifted via RemoteStorage must actually no longer be active server-side")

	liftEventType := "data.legal_hold_lifted"
	events, total, err := h.ls.GetAuditLogs(ctx, &coreStorage.AuditFilter{Action: &liftEventType})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "exactly one lift event must have been recorded (the local scenario above used the raw primitive, which writes no audit event)")
	require.Len(t, events, 1)
	require.NotNil(t, events[0].UserID)
	assert.Equal(t, h.adminUserID, *events[0].UserID,
		"the lift's own actor attribution must be derived from the authenticated session server-side, not trusted "+
			"from the wire -- the forged ReleasedBy above must never land")

	// Negative: lifting again when nothing is active must be refused.
	err = rsAsUser.UpdateLegalHold(ctx, &models.LegalHold{ID: remoteHold.ID, ReleaseReason: "conformance second release"})
	assert.Error(t, err, "RemoteStorage.UpdateLegalHold must refuse to lift when no legal hold is active")
}

// ============================================================================
// remote_break_glass.go (GetBreakGlassActivation / ListBreakGlassActivations
// only -- the other three break-glass methods were already covered by
// tranche 3's TestConformance_RevokeBreakGlassActivation, and
// CreateBreakGlassActivation/UpdateBreakGlassActivation are permanently
// remoteUnsupported per the G80 liveness sweep, not live methods this
// harness could exercise)
// ============================================================================

// --- GetBreakGlassActivation ---

func TestConformance_GetBreakGlassActivation(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	user, err := h.ls.CreateUser(ctx, &models.User{Username: "conformance-gbga", Email: "conformance-gbga@example.com", DisplayName: "GBGA", IsActive: true})
	require.NoError(t, err)
	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	seeded, err := h.ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: h.projectID, UserID: user.ID, RoleID: role.ID, RoleName: role.Name, Justification: "conformance test", State: "active",
	})
	require.NoError(t, err)

	localGot, err := h.ls.GetBreakGlassActivation(ctx, seeded.ID)
	require.NoError(t, err)
	remoteGot, err := h.rs.GetBreakGlassActivation(ctx, seeded.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "GetBreakGlassActivation", localGot, remoteGot, nil)

	_, err = h.rs.GetBreakGlassActivation(ctx, seeded.ID+999999)
	assert.Error(t, err, "a nonexistent activation id must error, not silently return a zero value")
}

// --- ListBreakGlassActivations ---

func TestConformance_ListBreakGlassActivations(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lbga-other", "", []string{"dev"})
	require.NoError(t, err)
	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	newActivation := func(projectID uint, suffix string) *models.BreakGlassActivation {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-lbga-" + suffix, Email: "conformance-lbga-" + suffix + "@example.com", DisplayName: suffix, IsActive: true,
		})
		require.NoError(t, err)
		a, err := h.ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
			ProjectID: projectID, UserID: user.ID, RoleID: role.ID, RoleName: role.Name, Justification: "j", State: "active",
		})
		require.NoError(t, err)
		return a
	}
	inScope := newActivation(h.projectID, "in-scope")
	_ = newActivation(otherProject.ID, "other-project") // must NOT appear in a project_id-scoped list

	localList, err := h.ls.ListBreakGlassActivations(ctx, h.projectID)
	require.NoError(t, err)
	remoteList, err := h.rs.ListBreakGlassActivations(ctx, h.projectID)
	require.NoError(t, err)
	require.Equal(t, len(localList), len(remoteList))
	require.Len(t, remoteList, 1,
		"a dropped/ignored project_id on the wire would return every project's activations, not just this one's")
	assertFieldExhaustiveEqual(t, "ListBreakGlassActivations[0]", localList[0], remoteList[0], nil)
	assert.Equal(t, inScope.ID, remoteList[0].ID)
}

// ============================================================================
// remote_audit.go
// ============================================================================

// --- GetAuditLogs: SKIPPED, not a fixture-cost skip -- a confirmed live defect ---
//
// GetAuditLogs is deliberately NOT covered by a TestConformance_GetAuditLogs
// in this file. Building the test surfaced a genuine, live wire-shape defect
// that this task's "one new file, no other edits" scope cannot fix, and
// CLAUDE.md is explicit that a found defect must never be papered over by
// weakening the assertion to match broken behavior -- so the honest options
// were "skip and report" or "fix production code," and only the former is in
// scope here.
//
// The defect: apiAuditLogsPath ("/api/v1/audit/logs", internal/storage/store/
// constants.go) resolves to the HUMAN-facing AuditHandler.GetAuditLogs
// (server/http/handlers/audit.go) -- the only handler registered on that
// route (router.go: r.Get("/logs", auditHandler.GetAuditLogs) under the
// permAuditRead-gated /audit group). That handler's response envelope is
// {"logs": [...AuditLogEntry...], "total":..., "page":..., ...} -- key
// "logs", and each entry is a UI-oriented AuditLogEntry DTO (Actor as a
// resolved username STRING, Timestamp instead of EventTime, no UserID/
// SecretNodeID/ProjectID/IPAddress/Success/PrevHash/EntryHash at all).
// RemoteStorage.GetAuditLogs (internal/storage/store/remote_audit.go),
// however, decodes the response as:
//
//	var result struct {
//	    Events []*models.AuditEvent `json:"events"`
//	    Total  int64                `json:"total"`
//	}
//
// "total" happens to decode correctly (the key name matches), which is what
// makes this defect insidious rather than loudly broken: RemoteStorage.
// GetAuditLogs returns a NONZERO, seemingly-correct total count alongside an
// ALWAYS-EMPTY event list, for every real deployment, unconditionally --
// json key "events" never appears in the actual response body, so
// result.Events stays at its zero value regardless of how many matching
// events exist server-side. Verified directly: a fixture of 3 real, matching
// audit_events rows plus a correct filter (project_id/user_id/action/time
// range/pagination) round-tripped through the real router produced
// total=3, events=[] on the RemoteStorage side, against total=3, len(events)=3
// on the LocalStorage side. This is exactly the defect class #1808 exists to
// catch -- confirmed live via the real router, not a fake-handler artifact --
// and needs a follow-up fix to remote_audit.go's response struct (and
// probably a dedicated non-human-facing wire DTO/route) before a
// TestConformance_GetAuditLogs can be added truthfully.
//
// GetRBACAuditLogs below has the SAME class of route (it also resolves to a
// human-facing DashboardHandler.GetRBACAuditLogs, whose per-entry shape --
// "actor_user_id" instead of "user_id", "created_at" instead of "timestamp",
// no username/target_name/ip_address/success at all -- doesn't match
// storage.RBACAuditLog's json tags either), but its top-level envelope key
// ("logs") DOES happen to match what remote_audit.go's GetRBACAuditLogs
// decodes for, and LocalStorage.GetRBACAuditLogs is itself an unimplemented
// stub that always returns empty regardless of filter -- so unlike
// GetAuditLogs, there is no nonzero local baseline available to make this
// harness's own comparison actually notice the per-entry field-name
// mismatch. See that test's own comment for what it can and cannot prove.

// --- GetRBACAuditLogs ---

func TestConformance_GetRBACAuditLogs(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	uid := h.adminUserID
	action := "role.assigned"
	targetType := "role"
	var targetID uint = 1
	// A realistic filter+pagination payload, not a bare empty-params call --
	// same #1808 rationale as GetAuditLogs above.
	filter := &coreStorage.RBACAuditFilter{
		UserID: &uid, Action: &action, TargetType: &targetType, TargetID: &targetID,
		StartTime: timePtr(now.Add(-time.Hour)), EndTime: timePtr(now.Add(time.Hour)), Page: 1, PageSize: 10,
	}
	// LocalStorage.GetRBACAuditLogs is explicitly "not yet implemented" (its
	// own doc comment) -- it always returns (nil, 0, nil) regardless of
	// filter, on both backends (the server proxies onto the SAME LocalStorage
	// method). The point of this test is #1808's own callout: prove the real
	// route exists and accepts a realistic filter without 404ing, not to
	// exercise filtering logic that doesn't exist yet.
	localLogs, localTotal, err := h.ls.GetRBACAuditLogs(ctx, filter)
	require.NoError(t, err)
	remoteLogs, remoteTotal, err := h.rs.GetRBACAuditLogs(ctx, filter)
	require.NoError(t, err, "GetRBACAuditLogs must succeed against the real router with a realistic filter")
	assert.Equal(t, localTotal, remoteTotal)
	assert.Equal(t, len(localLogs), len(remoteLogs))
}

// ============================================================================
// remote_stats.go
// ============================================================================

// --- HealthCheck ---

func TestConformance_HealthCheck(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	// HealthCheck has no LocalStorage-comparable "same backing store"
	// scenario to differentially compare against: it's a RemoteStorage-only
	// liveness probe against /health, an unauthenticated, non-enveloped
	// k8s-probe-style endpoint (see remote_stats.go's own doc comment on
	// Health/HealthCheck). Deviating from this file's usual local-vs-remote
	// shape: just verify it succeeds against the live harness server.
	require.NoError(t, h.rs.HealthCheck(ctx), "RemoteStorage.HealthCheck must succeed against a live, healthy server")
}
