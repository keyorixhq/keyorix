package interceptors

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// secretMethod is a representative non-public RPC method that requires auth.
const secretMethod = "/keyorix.v1.SecretService/GetSecret"

// okHandler records the context it was invoked with and returns a sentinel.
func okHandler(captured *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		if captured != nil {
			*captured = ctx
		}
		return "ok", nil
	}
}

func bearerCtx(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// setupAuthHelper builds an RBAC test helper and migrates the sessions table,
// which the base helper does not include but the auth path requires.
func setupAuthHelper(t *testing.T) *testhelper.RBACTestHelper {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	require.NoError(t, h.DB.AutoMigrate(&models.Session{}))
	return h
}

// mintSessionForTest inserts a user and a session token directly via storage and
// returns the token. expiresAt controls whether the session is live or expired.
func mintSessionForTest(t *testing.T, h *testhelper.RBACTestHelper, userID uint, username, token string, expiresAt time.Time) {
	t.Helper()
	h.CreateTestUser(t, username, userID)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID:       userID,
		SessionToken: token,
		ExpiresAt:    &expiresAt,
	})
	require.NoError(t, err)
}

// An impersonation session must not be able to mint a durable machine token over gRPC:
// the credential would outlive the bounded, audited impersonation session. Parity with
// the HTTP BlockWhenImpersonating guard. A benign RPC under the same session still works.
func TestAuthInterceptor_BlocksMachineTokenIssuanceWhileImpersonating(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	admin := uint(7000)
	target := uint(7001)
	h.CreateTestUser(t, "imp-admin", admin)
	h.CreateTestUser(t, "imp-target", target)
	expiry := time.Now().Add(time.Hour)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: target, SessionToken: "imp-token", ExpiresAt: &expiry, ImpersonatedBy: &admin,
	})
	require.NoError(t, err)

	interceptor := AuthInterceptor(h.CoreService, false)
	const machineIssue = "/keyorix.v1.MachineIdentityService/IssueMachineToken"

	// Credential-minting RPC under impersonation → refused.
	_, err = interceptor(bearerCtx("imp-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: machineIssue}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// A non-credential-minting RPC under the same impersonation session still proceeds.
	resp, err := interceptor(bearerCtx("imp-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

// The predicate is the single source of truth for which gRPC methods are blocked while
// impersonating; keep it aligned with the HTTP BlockWhenImpersonating routes.
func TestBlockedUnderImpersonation(t *testing.T) {
	assert.True(t, blockedUnderImpersonation("/keyorix.v1.MachineIdentityService/IssueMachineToken"))
	assert.False(t, blockedUnderImpersonation(secretMethod))
	assert.False(t, blockedUnderImpersonation("/keyorix.v1.MachineIdentityService/ListMachineTokens"))
}

func TestAuthInterceptor_ValidSessionPopulatesUserContext(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9001, "grpc-alice", "live-token", time.Now().Add(time.Hour))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	resp, err := interceptor(bearerCtx("live-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user, "handler context must carry the authenticated user")
	assert.Equal(t, uint(9001), user.UserID)
	assert.Equal(t, "grpc-alice", user.Username)
}

// Regression guard: the removed mock validator granted full admin to the literal
// token "valid-token". It must now be rejected like any other unknown token.
func TestAuthInterceptor_LegacyBackdoorTokenRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	interceptor := AuthInterceptor(h.CoreService, false)
	for _, tok := range []string{"valid-token", "test-token"} {
		_, err := interceptor(bearerCtx(tok), nil,
			&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
		require.Error(t, err, "legacy mock token %q must not authenticate", tok)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	}
}

func TestAuthInterceptor_ExpiredSessionRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9002, "grpc-bob", "stale-token", time.Now().Add(-time.Minute))

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("stale-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_MissingAndMalformedCredentials(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	interceptor := AuthInterceptor(h.CoreService, false)
	info := &grpc.UnaryServerInfo{FullMethod: secretMethod}

	cases := map[string]context.Context{
		"no metadata":    context.Background(),
		"no auth header": metadata.NewIncomingContext(context.Background(), metadata.MD{}),
		"not bearer":     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc")),
		"empty bearer":   bearerCtx(""),
		"unknown token":  bearerCtx("nope"),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := interceptor(ctx, nil, info, okHandler(nil))
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

// A nil core service must fail closed (never authenticate) rather than panic.
func TestAuthInterceptor_NilCoreFailsClosed(t *testing.T) {
	interceptor := AuthInterceptor(nil, false)
	_, err := interceptor(bearerCtx("whatever"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// Public methods (health, reflection) bypass authentication entirely.
func TestAuthInterceptor_PublicMethodBypassesAuth(t *testing.T) {
	interceptor := AuthInterceptor(nil, false) // never consulted for public methods
	var captured context.Context
	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"},
		okHandler(&captured))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.Nil(t, GetUserFromGRPCContext(captured), "public method must not set a user context")
}

// A personal access token authenticates over gRPC (previously rejected outright)
// AND its ADR-042 least-privilege restriction rides the handler context, so
// core.Authorize enforces scoping over gRPC exactly as it does over HTTP.
func TestAuthInterceptor_PATAuthenticatesAndEnforcesScope(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "grpc-ci", 9100)
	proj2 := uint(2)
	h.AssignUserRole(t, 9100, 3, &proj2) // editor (secrets.read + secrets.write) in project 2

	// A token confined to secrets.read in project 2 only.
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9100, "ci", nil, []string{"secrets.read"}, 2, 0, nil)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.PlainToken, "kx_pat_"))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	resp, err := interceptor(bearerCtx(res.PlainToken), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err, "a kx_pat_ token must now authenticate over gRPC")
	assert.Equal(t, "ok", resp)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.Equal(t, uint(9100), user.UserID, "authenticated as the PAT's owner")

	// Restriction is on the handler context → core.Authorize enforces it.
	readP2, err := h.CoreService.Authorize(captured, 9100, "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.True(t, readP2, "in-scope read allowed (restriction permits + owner's role grants)")

	writeP2, err := h.CoreService.Authorize(captured, 9100, "secrets.write", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, writeP2, "permission outside the token's allowlist is denied")

	readP3, err := h.CoreService.Authorize(captured, 9100, "secrets.read", core.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.False(t, readP3, "scope outside the token's project is denied")
}

// A machine-identity token (ADR-030) authenticates over gRPC (previously rejected)
// as a machine principal, and authorization uses machine RBAC with NO admin bypass.
func TestAuthInterceptor_MachineTokenAuthenticatesAndUsesMachineRBAC(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}))

	m, err := h.CoreService.CreateMachineIdentity(context.Background(), 2, "ci-bot", "service", "", "", 1)
	require.NoError(t, err)
	tok, err := h.CoreService.IssueMachineToken(context.Background(), 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(tok.PlainToken, "kx_machine_"))
	// Grant the machine viewer (secrets.read) in project 2 only.
	require.NoError(t, h.CoreService.AssignMachineRole(context.Background(), m.ID, 4, core.Scope{ProjectID: 2}, 1))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err = interceptor(bearerCtx(tok.PlainToken), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err, "a kx_machine_ token must authenticate over gRPC")

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.Equal(t, core.ActorTypeMachine, user.ActorType)
	assert.Equal(t, m.ID, user.MachineIdentityID)
	assert.Equal(t, uint(0), user.UserID, "a machine has no owning user")
	assert.Equal(t, core.ActorTypeMachine, user.ActorKind())
	assert.Equal(t, m.ID, user.PrincipalID())

	// Machine RBAC via AuthorizePrincipal: granted read allowed, ungranted write
	// denied — and no admin bypass (a machine is never a super-user).
	readP2, err := h.CoreService.AuthorizePrincipal(captured, user.ActorKind(), user.PrincipalID(), "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.True(t, readP2, "granted machine role permits the scoped read")

	writeP2, err := h.CoreService.AuthorizePrincipal(captured, user.ActorKind(), user.PrincipalID(), "secrets.write", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, writeP2, "machine holds only viewer — write denied, no admin bypass")

	readP3, err := h.CoreService.AuthorizePrincipal(captured, user.ActorKind(), user.PrincipalID(), "secrets.read", core.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.False(t, readP3, "machine role is scoped to project 2 — denied in project 3")
}

// An invalid PAT fails closed with Unauthenticated, same as a bad session token.
func TestAuthInterceptor_InvalidPATRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("kx_pat_bogus"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// bearerCtxFromIP is bearerCtx plus a gRPC peer with the given source IP.
func bearerCtxFromIP(token, ip string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 5555}})
}

// A PAT's IP allowlist (ADR-066) is enforced over gRPC too — otherwise the restriction
// would be bypassable by switching transports. In-range peer is allowed; off-network is
// PermissionDenied.
func TestAuthInterceptor_PATNetworkAllowlistOverGRPC(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "grpc-cidr", 9200)
	proj2 := uint(2)
	h.AssignUserRole(t, 9200, 3, &proj2)

	// A token restricted to 10.0.0.0/8 (no permission/project scoping).
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9200, "ci-cidr", nil, nil, 0, 0, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	interceptor := AuthInterceptor(h.CoreService, false)

	_, err = interceptor(bearerCtxFromIP(res.PlainToken, "10.1.2.3"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.NoError(t, err, "in-range source IP is allowed over gRPC")

	_, err = interceptor(bearerCtxFromIP(res.PlainToken, "203.0.113.9"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err, "off-network source IP must be denied over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// setUserFields fetches a user by id, applies mutate, and persists — used to put a
// test user into a restricted account state or flip its MFA flag.
func setUserFields(t *testing.T, h *testhelper.RBACTestHelper, userID uint, mutate func(*models.User)) {
	t.Helper()
	var u models.User
	require.NoError(t, h.DB.First(&u, userID).Error)
	mutate(&u)
	require.NoError(t, h.DB.Save(&u).Error)
}

// A restricted account (ADR-025 password_reset_required / pending_first_login) must
// change its password first. HTTP confines it to the change-password allowlist; gRPC
// has no such endpoint, so it is denied outright — otherwise the restriction would be
// bypassable by switching transports.
func TestAuthInterceptor_RestrictedAccountDeniedOverGRPC(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9300, "grpc-reset", "reset-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 9300, func(u *models.User) { u.AccountState = core.AccountPasswordResetRequired })

	interceptor := AuthInterceptor(h.CoreService, false)
	_, err := interceptor(bearerCtx("reset-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err, "a restricted account must not access RPCs over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// When the deployment mandates MFA (security.require_mfa), an interactive session
// without MFA is confined to the enrolment endpoints on HTTP; gRPC has none, so it is
// denied. A session with MFA is allowed, and a PAT is exempt (non-interactive) — both
// matching the HTTP EnforceMFAEnrollment policy.
func TestAuthInterceptor_MFAEnrolmentGateOverGRPC(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	mintSessionForTest(t, h, 9400, "grpc-nomfa", "nomfa-token", time.Now().Add(time.Hour))
	mintSessionForTest(t, h, 9401, "grpc-mfa", "mfa-token", time.Now().Add(time.Hour))
	setUserFields(t, h, 9401, func(u *models.User) { u.MFAEnabled = true })

	// A PAT owned by a user without MFA — non-interactive, so exempt from the gate.
	h.CreateTestUser(t, "grpc-pat-nomfa", 9402)
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9402, "ci", nil, nil, 0, 0, nil)
	require.NoError(t, err)

	mfaRequired := AuthInterceptor(h.CoreService, true)
	info := &grpc.UnaryServerInfo{FullMethod: secretMethod}

	_, err = mfaRequired(bearerCtx("nomfa-token"), nil, info, okHandler(nil))
	require.Error(t, err, "session without MFA must be denied when the deployment requires MFA")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = mfaRequired(bearerCtx("mfa-token"), nil, info, okHandler(nil))
	require.NoError(t, err, "session with MFA is allowed")

	_, err = mfaRequired(bearerCtx(res.PlainToken), nil, info, okHandler(nil))
	require.NoError(t, err, "a PAT is non-interactive and exempt from the MFA-enrolment gate")

	// With the policy off, the same un-enrolled session authenticates fine.
	_, err = AuthInterceptor(h.CoreService, false)(bearerCtx("nomfa-token"), nil, info, okHandler(nil))
	require.NoError(t, err, "no MFA gate when the deployment does not require MFA")
}

// A machine-identity request over gRPC must produce audit events actored as a
// machine (ADR-023/030), not silently defaulted to "user" — parity with HTTP's
// buildRequestContext, which tags the request context the same way. Without the
// interceptor tagging the context, switching transport to gRPC would mislabel
// every machine action as a user action in the audit trail.
func TestAuthInterceptor_MachineRequestStampsMachineActorInAudit(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{}, &models.MachineIdentityCredential{}, &models.MachineIdentityRole{}, &models.AuditEvent{}))

	m, err := h.CoreService.CreateMachineIdentity(context.Background(), 2, "ci-bot", "service", "", "", 1)
	require.NoError(t, err)
	tok, err := h.CoreService.IssueMachineToken(context.Background(), 2, m.ID, 1, core.IssueMachineTokenParams{Name: "tok"})
	require.NoError(t, err)

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err = interceptor(bearerCtx(tok.PlainToken), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	// An audit event written downstream with the handler's context must be machine-actored.
	h.CoreService.LogRoleAssigned(captured, 0, 1, 4, core.Scope{ProjectID: 2})
	var ev models.AuditEvent
	require.NoError(t, h.DB.Order("id desc").First(&ev).Error)
	assert.Equal(t, core.ActorTypeMachine, ev.ActorType,
		"a machine request over gRPC must stamp ActorType=machine_identity in audit")
}

// An impersonation session used over gRPC must keep the initiating admin
// attributable: every audit event it writes records ImpersonatedBy and
// Impersonation=true, exactly as on HTTP. Without resolving SessionImpersonator
// and tagging the context, an admin acting through impersonation over gRPC would
// be invisible in the audit trail — an accountability bypass by transport.
func TestAuthInterceptor_ImpersonationSessionStampsAdminInAudit(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))

	const adminID, targetID uint = 7001, 7002
	h.CreateTestUser(t, "imp-target", targetID)
	// The impersonating admin must exist and be active: ValidateSessionToken now
	// re-checks the impersonator's account state on every impersonation-session request
	// (so suspending the admin ends their impersonation immediately).
	h.CreateTestUser(t, "imp-admin", adminID)
	exp := time.Now().Add(time.Hour)
	admin := adminID
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID:         targetID,
		SessionToken:   "imp-token",
		ExpiresAt:      &exp,
		ImpersonatedBy: &admin,
	})
	require.NoError(t, err)

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService, false)
	_, err = interceptor(bearerCtx("imp-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err)

	// The token authenticates as the impersonated target, carrying the admin's id.
	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.Equal(t, targetID, user.UserID)
	require.NotNil(t, user.ImpersonatedBy, "impersonation must be resolved over gRPC")
	assert.Equal(t, adminID, *user.ImpersonatedBy)

	// An audit event written downstream records the initiating admin and the flag.
	h.CoreService.LogRoleAssigned(captured, targetID, 1, 4, core.Scope{ProjectID: 2})
	var ev models.AuditEvent
	require.NoError(t, h.DB.Order("id desc").First(&ev).Error)
	require.NotNil(t, ev.ImpersonatedBy, "audit over gRPC must record the impersonating admin")
	assert.Equal(t, adminID, *ev.ImpersonatedBy)
	assert.True(t, ev.Impersonation, "audit over gRPC must mark the event as impersonated")

	// A non-impersonation session leaves the tag unset (no false positives).
	mintSessionForTest(t, h, 7003, "plain-user", "plain-token", time.Now().Add(time.Hour))
	var plainCtx context.Context
	_, err = interceptor(bearerCtx("plain-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&plainCtx))
	require.NoError(t, err)
	assert.Nil(t, GetUserFromGRPCContext(plainCtx).ImpersonatedBy,
		"an ordinary session must not be tagged as impersonation")
}
