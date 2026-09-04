// setup_token_expire_audit_test.go — #1622 invariant guard.
//
// ExpireSetupTokenProxy (server/http/handlers/setup_tokens_proxy.go) used to
// call storage.MarkSetupTokenExpired directly: a system.write holder could
// mass-expire setup tokens with zero audit trail. The fix (#1622) is
// structural, not per-route: expireSetupToken is now the ONE place that
// performs the state mutation and the setup_token.expired audit write as a
// single unit, and both exported entry points -- the lazy expiry-on-read
// path (ValidateSetupToken/ConsumeSetupToken, via inspectActiveSetupToken)
// and the explicit by-ID path (ExpireSetupTokenByID, which
// ExpireSetupTokenProxy now calls) -- route through it.
//
// This test asserts the INVARIANT, not either route: expiring a token by ANY
// exported path produces exactly one setup_token.expired audit event,
// correctly attributed to the calling actor via ctx (the auth middleware's
// WithActorType/WithMachineActor tagging, read automatically by
// writeAuditEventFull -> emitAudit). A future change that reintroduces a
// direct storage.MarkSetupTokenExpired call in either path -- bypassing
// expireSetupToken -- fails this test: temporarily rewriting
// ExpireSetupTokenByID to call c.storage.MarkSetupTokenExpired directly
// (skipping the audit write) was confirmed to fail both subtests before this
// fix, with LogAuditEvent asserted called 0 times instead of 1.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestExpireSetupToken_Invariant_ExactlyOneAuditEventWithCorrectActor(t *testing.T) {
	background := context.Background()

	cases := []struct {
		name string
		run  func(t *testing.T, c *KeyorixCore, ctx context.Context, tok *models.SetupToken)
	}{
		{
			// inspectActiveSetupToken's lazy-expiry-on-read branch, reached via
			// the exported ValidateSetupToken.
			name: "lazy expiry on read (ValidateSetupToken)",
			run: func(t *testing.T, c *KeyorixCore, ctx context.Context, tok *models.SetupToken) {
				t.Helper()
				_, err := c.ValidateSetupToken(ctx, "kx_setup_1622_lazy", tok.Purpose)
				require.Error(t, err, "an overdue token must still be reported as expired to the caller")
				assert.Contains(t, err.Error(), "expired")
			},
		},
		{
			// The explicit by-ID path backing ExpireSetupTokenProxy.
			name: "explicit expire by ID (ExpireSetupTokenByID)",
			run: func(t *testing.T, c *KeyorixCore, ctx context.Context, tok *models.SetupToken) {
				t.Helper()
				require.NoError(t, c.ExpireSetupTokenByID(ctx, tok.ID))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := new(MockStorage)
			c := NewKeyorixCore(ms)

			const machineID = uint(77)
			actorCtx := WithMachineActor(WithActorType(background, ActorTypeMachine), machineID)

			subjectUserID := uint(42)
			tok := &models.SetupToken{
				ID:            5,
				State:         SetupTokenActive,
				Purpose:       SetupPurposeAccountSetup,
				SubjectEmail:  "victim@acme.io",
				SubjectUserID: &subjectUserID,
				ExpiresAt:     c.now().Add(-time.Hour), // overdue, for the lazy-expiry subtest
			}

			ms.On("GetSetupTokenByHash", actorCtx, sha256Hex("kx_setup_1622_lazy")).Return(tok, nil)
			ms.On("GetSetupTokenByID", actorCtx, tok.ID).Return(tok, nil)
			ms.On("MarkSetupTokenExpired", actorCtx, tok.ID).Return(nil)

			var captured *models.AuditEvent
			ms.On("LogAuditEvent", actorCtx, mock.AnythingOfType("*models.AuditEvent")).
				Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
				Return(nil)

			tc.run(t, c, actorCtx, tok)

			ms.AssertNumberOfCalls(t, "MarkSetupTokenExpired", 1)
			ms.AssertNumberOfCalls(t, "LogAuditEvent", 1)
			require.NotNil(t, captured, "expiring a token must write an audit event")
			assert.Equal(t, "setup_token.expired", captured.EventType)
			assert.Equal(t, ActorTypeMachine, captured.ActorType,
				"the audit event must be attributed to the calling actor's type from ctx")
			require.NotNil(t, captured.MachineIdentityID,
				"the calling actor's machine identity must be attached, not just ActorType")
			assert.Equal(t, machineID, *captured.MachineIdentityID)
			assert.Nil(t, captured.UserID, "a machine actor must not occupy UserID (ADR-092)")
		})
	}
}
