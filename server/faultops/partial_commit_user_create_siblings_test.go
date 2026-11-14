package faultops

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// #3225, the siblings of #4208's createUser fix (PARTIAL-COMMIT-NOV-2): every other
// core path that inserts a user read a create transaction that COMMITTED and then
// reported an error (a lost acknowledgement) as "nothing committed". The list and
// how it was derived: docs/design/user-create-lost-ack-2026-11.md. Each case below
// drives the op's create transaction (WithTransaction#1, the ordinal the probe in
// that doc found) commit-then-error, and checks the path-specific part of the
// success answer the client must get; the generic "every insert site is covered"
// guard is TestPartialCommit_EveryUserCreateSiteHandlesLostAck.

// lostAckCreate drives op's create transaction commit-then-error and checks the
// premise: the fault fired and the create committed exactly one user row.
func lostAckCreate(t *testing.T, op string) oracleInput {
	t.Helper()
	in, outcome, why := driveFaultCase(t, op, "WithTransaction", 1, faultstorage.KindEffectThenError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.Equal(t, 1, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"premise: the create transaction committed its user row")
	return in
}

// rolledBackCreate drives op's create transaction with a plain error (a rollback)
// and checks the read-back did not turn it into a success: no user, an error.
func rolledBackCreate(t *testing.T, op string) oracleInput {
	t.Helper()
	in, outcome, why := driveFaultCase(t, op, "WithTransaction", 1, faultstorage.KindError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.False(t, in.result.Success, "a rolled-back create must be answered as an error, got: %s", in.result.Detail)
	require.Equal(t, 0, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"a rolled-back create must leave no user row")
	return in
}

// gRPC UserService.CreateUser (and REST POST /api/v1/users/ with a role or project
// assignments) -> CreateUserWithAssignments: answered Internal while the user, its
// grants and user.created had committed, and the post-commit password-history seed
// was skipped (oracle (d): the state matched neither side).
func TestPartialCommit_CreateUserWithAssignmentsLostAckAnswersSuccess(t *testing.T) {
	in := lostAckCreate(t, "GRPC keyorix.v1.UserService.CreateUser")
	require.True(t, in.result.Success, "a committed create must be answered as a success, got: %s", in.result.Detail)
	require.True(t, snapshotHasAuditEvent(in.after, "user.created"), "user.created committed with the user")
	sink := &driveSink{t: t}
	checkOraclesReporting(sink, in)
	require.Empty(t, sink.findings, "no oracle may flag the lost-ack create (password history seeded)")
}

func TestPartialCommit_CreateUserWithAssignmentsRolledBackStaysAnError(t *testing.T) {
	rolledBackCreate(t, "GRPC keyorix.v1.UserService.CreateUser")
}

// SCIM POST /scim/v2/Users -> ProvisionSCIMUser: answered 500 while the account,
// its baseline role and scim.user_provisioned had committed; the IdP's retry then
// got a 409 for an account whose id it never learned. No generic oracle flagged it
// (the committed state equals the fault-free one).
func TestPartialCommit_SCIMProvisionLostAckAnswersCreated(t *testing.T) {
	in := lostAckCreate(t, "REST POST /scim/v2/Users")
	require.True(t, strings.HasPrefix(in.result.Detail, "HTTP 201"), "a committed provision must be answered 201 with the user, got: %s", in.result.Detail)
	require.Contains(t, in.result.Detail, `"id"`, "the IdP must learn the new account's id")
	require.True(t, snapshotHasAuditEvent(in.after, "scim.user_provisioned"), "scim.user_provisioned committed with the account")
}

// A real rollback stays an error, and one the IdP retries (5xx), never a 4xx it
// would give up on.
func TestPartialCommit_SCIMProvisionRolledBackStaysRetryable(t *testing.T) {
	in := rolledBackCreate(t, "REST POST /scim/v2/Users")
	require.True(t, strings.HasPrefix(in.result.Detail, "HTTP 5"), "a rolled-back provision is a retryable 5xx, got: %s", in.result.Detail)
}

// SAML ACS JIT -> provisionSSOUser (the OIDC callback's JIT is the same function):
// the login was refused while the account and its default role had committed, and
// auth.sso_jit_provisioned, written only after the commit, was never written; the
// next login resolves the account by its sso: external id as an existing one, so
// that row never appeared at all. No generic oracle flagged it.
func TestPartialCommit_SSOJITLostAckProvisionsAndSignsIn(t *testing.T) {
	in := lostAckCreate(t, "REST POST /auth/saml/{provider}/acs")
	require.True(t, in.result.Success, "a committed JIT provision must sign the user in, got: %s", in.result.Detail)
	require.True(t, snapshotHasAuditEvent(in.after, "auth.sso_jit_provisioned"), "the JIT provision is audited")
	require.Equal(t, 1, len(in.after.Tables["Session"].Rows)-len(in.before.Tables["Session"].Rows), "the login minted its session")
}

func TestPartialCommit_SSOJITRolledBackStaysAnError(t *testing.T) {
	in := rolledBackCreate(t, "REST POST /auth/saml/{provider}/acs")
	require.False(t, snapshotHasAuditEvent(in.after, "auth.sso_jit_provisioned"), "nothing was provisioned, nothing is audited")
}
