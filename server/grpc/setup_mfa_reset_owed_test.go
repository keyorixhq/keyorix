package grpc_test

// setup_mfa_reset_owed_test.go -- #3799 on gRPC: an administrator MFA reset sets
// users.mfa_enrolment_required, and the interceptor's account-setup gate and
// access policy must read it even with security.require_mfa off. The HTTP side is
// server/http account_setup_mfa_reset_owed_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	grpcResetUserPassword = "Reset#User-Passw0rd-3"
	grpcResetNewPassword  = "Brand#New-Passw0rd-77"
	grpcMFAEnrolmentMsg   = "multi-factor authentication enrolment required"
)

var grpcListSecrets = grpcRPC{full: "/keyorix.v1.SecretService/ListSecrets"}

func (e *setupGRPCEnv) mfaResetUser(t *testing.T, username string) uint {
	t.Helper()
	ctx := context.Background()
	u, err := e.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: username + "@example.com", Password: grpcResetUserPassword,
	})
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte(setupGateGRPCOTP), bcrypt.MinCost)
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, e.core.Storage().WithTransaction(ctx, func(tx storage.Storage) error {
		locked, lerr := tx.LockUserForUpdate(ctx, u.ID)
		if lerr != nil {
			return lerr
		}
		_, rerr := core.ResetMFACredentialsInTx(ctx, tx, locked, string(hash), now.Add(time.Hour), now)
		return rerr
	}))
	return u.ID
}

func TestGRPCAccountSetup_MFAResetOwesEnrolment_WithoutRequireMFA(t *testing.T) {
	e := newSetupGRPCEnvPolicy(t, false)
	ctx := context.Background()
	uid := e.mfaResetUser(t, "reset_user")

	// The one-time-password login owes both steps: a setup-only session, refused
	// every RPC by the setup gate.
	sess, _, err := e.core.Login(ctx, &core.LoginRequest{Username: "reset_user", Password: setupGateGRPCOTP})
	require.NoError(t, err)
	stored, err := e.core.Storage().GetSession(ctx, sess.SessionToken)
	require.NoError(t, err)
	assert.True(t, stored.SetupOnly, "a reset user owes both steps: the login must mint a setup-only session")
	st := status.Convert(e.call(grpcListSecrets, sess.SessionToken))
	assert.Equal(t, codes.PermissionDenied, st.Code(), st.Message())
	assert.Equal(t, setupOnlyRefusedMsg, st.Message())

	// The password alone does not finish setup: the setup-only session stays
	// confined, and a fresh ordinary session is refused by the access policy.
	require.NoError(t, e.core.ChangePassword(ctx, uid, setupGateGRPCOTP, grpcResetNewPassword, sess.SessionToken))
	st = status.Convert(e.call(grpcListSecrets, sess.SessionToken))
	assert.Equal(t, codes.PermissionDenied, st.Code(), st.Message())
	assert.Equal(t, setupOnlyRefusedMsg, st.Message(), "the setup-only session ended before the enrolment was made")

	sess2, _, err := e.core.Login(ctx, &core.LoginRequest{Username: "reset_user", Password: grpcResetNewPassword})
	require.NoError(t, err)
	st = status.Convert(e.call(grpcListSecrets, sess2.SessionToken))
	assert.Equal(t, codes.PermissionDenied, st.Code(), "a reset user reached an RPC without enrolling: %s", st.Message())
	assert.Equal(t, grpcMFAEnrolmentMsg, st.Message())
}

// A user who was never reset is unaffected: with require_mfa off a password-only
// session passes both interceptor gates.
func TestGRPCAccountSetup_NeverResetUser_Unaffected(t *testing.T) {
	e := newSetupGRPCEnvPolicy(t, false)
	ctx := context.Background()
	_, err := e.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "plain_user", Email: "plain_user@example.com", Password: grpcResetUserPassword,
	})
	require.NoError(t, err)
	sess, _, err := e.core.Login(ctx, &core.LoginRequest{Username: "plain_user", Password: grpcResetUserPassword})
	require.NoError(t, err)
	st := status.Convert(e.call(grpcListSecrets, sess.SessionToken))
	assert.NotEqual(t, grpcMFAEnrolmentMsg, st.Message())
	assert.NotEqual(t, setupOnlyRefusedMsg, st.Message())
	assert.NotEqual(t, codes.Unauthenticated, st.Code(), st.Message())
}
