// auth_userid_invariant_test.go — pins the invariant #1545's machine-only reach
// classification depends on. #1545 (internal/core/rbac_management.go's
// AssignPermissionToRole, internal/core/bulk_delete.go's BulkDeleteSecrets)
// concluded their actorID==0 exemptions are reachable ONLY by a machine
// credential, never a real human, because a human session's UserID is never 0
// -- verified there by reading every UserContext construction site
// (server/middleware/auth.go, server/grpc/interceptors/auth.go) by hand. That
// conclusion is currently maintained by convention (every construction site
// happens to be written correctly), not by a type system that makes the
// mistake unrepresentable -- P3 (docs/g80-remediation-notes.md, actor_sentinel_completeness_test.go)
// explicitly declined to build that type, on the reasoning that P2's route
// classification already closes the class at the boundary where it bites. This
// test is the other half of that reasoning holding up: if a future change
// broke the "human session -> nonzero UserID" invariant, #1545's machine-only
// verdict (and therefore its "filed, not fixed" status) would silently stop
// being true. This test is what keeps it honest.
package middleware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestValidateToken_UserIDInvariant exercises validateToken (the single real
// dispatch point every HTTP request's UserContext is built from -- session,
// PAT, machine token, and OIDC-federated JWT all funnel through it) via
// fakeValidator and asserts: a human-authenticated principal (session or PAT)
// always carries a nonzero UserID; a machine-authenticated principal (machine
// token or OIDC federation) always carries UserID==0.
//
// Two paths #1545's classification also relied on are NOT separately
// exercised here because they structurally reduce to the cases below rather
// than bypassing them:
//   - Bootstrap: a bootstrap-created account (internal/core/auth_bootstrap.go)
//     is just a row created via the same autoincrement path every user gets;
//     it authenticates by logging in afterward, which is the "session token"
//     case below, not a separate construction path.
//   - Impersonation: ImpersonatedBy is set at server/middleware/auth.go:327
//     (`userCtx.ImpersonatedBy = coreService.SessionImpersonator(...)`) AFTER
//     the session-validated UserContext (with its real, already-nonzero
//     UserID) is constructed -- it adds a field, it never replaces UserID.
//     Exercising it needs a real *core.KeyorixCore (SessionImpersonator is a
//     storage-backed lookup), which fakeValidator-based unit tests
//     deliberately don't wire up (see newTestAuthMiddleware's doc comment);
//     the invariant it depends on is the same one the session case here
//     already pins.
func TestValidateToken_UserIDInvariant(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		wantHumanActor bool // true: session/PAT, must be UserID != 0; false: machine/OIDC, must be UserID == 0
	}{
		{name: "session token (admin fixture)", token: validToken, wantHumanActor: true},
		{name: "session token (second fixture)", token: testToken, wantHumanActor: true},
		{name: "personal access token", token: "kx_pat_validtoken", wantHumanActor: true},
		{name: "machine token", token: "kx_machine_validtoken", wantHumanActor: false},
		{name: "OIDC-federated token", token: "header.valid.sig", wantHumanActor: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCtx, err := validateToken(context.Background(), fakeValidator{}, tt.token)
			require.NoError(t, err)
			require.NotNil(t, userCtx)

			if tt.wantHumanActor {
				assert.NotZero(t, userCtx.UserID,
					"a human-authenticated (session/PAT) UserContext must never carry UserID==0 -- "+
						"that value is reserved for a machine-credential-authenticated caller and the "+
						"genuinely-trusted local/embedded pseudo-actor; #1545's machine-only classification "+
						"depends on this never happening")
				assert.Equal(t, core.ActorTypeUser, userCtx.ActorKind())
			} else {
				assert.Zero(t, userCtx.UserID,
					"a machine-credential-authenticated UserContext must carry UserID==0 by construction "+
						"(machineUserContext, server/middleware/auth.go)")
				assert.Equal(t, core.ActorTypeMachine, userCtx.ActorKind())
			}
		})
	}
}
