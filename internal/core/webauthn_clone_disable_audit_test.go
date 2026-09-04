// webauthn_clone_disable_audit_test.go — #1714 invariant guard.
//
// UpdateWebAuthnCredentialProxy used to call storage.UpdateWebAuthnCredential
// directly: any system.write holder could reassign a credential's ownership
// or silently re-enable a clone-disabled one, with no audit trail either way.
// The authz half of the fix is covered by
// server/http/handlers/webauthn_proxy_1622_authz_test.go (rejection at the
// HTTP layer, before any mutation). This file covers the audit half: the
// fix is structural, not per-route -- markWebAuthnCredentialClonedDisabled is
// the ONE place that performs the disable mutation and the
// EventWebAuthnCloneDetected audit write as a single unit, and both exported
// entry points -- rejectIfCloned's own login-time disable (unchanged
// behavior, now delegating) and MarkWebAuthnCredentialClonedByLookup (which
// UpdateWebAuthnCredentialProxy now calls) -- route through it.
//
// This test asserts the INVARIANT, not either route: disabling a credential
// on a clone signal by ANY exported path produces exactly one
// EventWebAuthnCloneDetected audit event, correctly attributed to the
// calling actor via ctx (the auth middleware's WithActorType/WithMachineActor
// tagging, read automatically by writeAuditEventFull -> emitAudit). A future
// change that reintroduces a direct storage.UpdateWebAuthnCredential call in
// either path -- bypassing markWebAuthnCredentialClonedDisabled -- fails this
// test: temporarily rewriting markWebAuthnCredentialClonedDisabled to call
// c.storage.UpdateWebAuthnCredential directly (skipping the audit write) was
// confirmed to fail both subtests before this fix, with the audit event count
// asserted at 0 instead of 1.
package core

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const invariantTestMachineID = uint(88)

func TestDisableClonedWebAuthnCredential_Invariant_ExactlyOneAuditEventWithCorrectActor(t *testing.T) {
	t.Run("login-time disable (rejectIfCloned)", func(t *testing.T) {
		c, db := newWebAuthnTestCore(t, true)
		credID := []byte("cred-invariant-login")
		seedCredential(t, c, db, 1, string(credID))

		actorCtx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), invariantTestMachineID)
		cred := &webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{CloneWarning: true}}
		err := c.rejectIfCloned(actorCtx, 1, cred, "203.0.113.9")
		require.Error(t, err, "a regressed signature counter must still refuse the authentication")

		var reloaded models.WebAuthnCredential
		require.NoError(t, db.Where("credential_id = ?", credID).First(&reloaded).Error)
		assert.True(t, reloaded.Disabled, "the credential must be disabled")

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", EventWebAuthnCloneDetected).Find(&events).Error)
		require.Len(t, events, 1, "exactly one clone-detected audit event must be written")
		assertCorrectMachineActor(t, events[0])
	})

	t.Run("explicit disable by lookup (MarkWebAuthnCredentialClonedByLookup)", func(t *testing.T) {
		c, db := newWebAuthnTestCore(t, true)
		credID := []byte("cred-invariant-lookup")
		seedCredential(t, c, db, 1, string(credID))

		var row models.WebAuthnCredential
		require.NoError(t, db.Where("credential_id = ?", credID).First(&row).Error)

		actorCtx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), invariantTestMachineID)
		_, err := c.MarkWebAuthnCredentialClonedByLookup(actorCtx, credID, 1, row.ID, "203.0.113.9")
		require.NoError(t, err)

		var reloaded models.WebAuthnCredential
		require.NoError(t, db.Where("credential_id = ?", credID).First(&reloaded).Error)
		assert.True(t, reloaded.Disabled, "the credential must be disabled")

		var events []models.AuditEvent
		require.NoError(t, db.Where("event_type = ?", EventWebAuthnCloneDetected).Find(&events).Error)
		require.Len(t, events, 1, "exactly one clone-detected audit event must be written")
		assertCorrectMachineActor(t, events[0])
	})
}

func assertCorrectMachineActor(t *testing.T, ev models.AuditEvent) {
	t.Helper()
	assert.Equal(t, ActorTypeMachine, ev.ActorType,
		"the audit event must be attributed to the calling actor's type from ctx")
	require.NotNil(t, ev.MachineIdentityID,
		"the calling actor's machine identity must be attached, not just ActorType")
	assert.Equal(t, invariantTestMachineID, *ev.MachineIdentityID)
	assert.Nil(t, ev.UserID, "a machine actor must not occupy UserID (ADR-092)")
}
