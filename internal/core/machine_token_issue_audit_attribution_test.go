package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// A token issued by a machine caller is audited as that machine: the
// token_issued row carries actor_type machine_identity and the CALLER's id
// (not the target's), and no user id. ctx is tagged the way the auth layer
// and the token-issue handlers tag a machine request.
func TestIssueMachineToken_MachineCallerAuditRowNamesTheCaller(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "audit")
	raw := addCallerCredential(t, st, caller.ID, "plain", "")

	ctx := WithMachineActor(WithActorType(context.Background(), ActorTypeMachine), caller.ID)
	ctx = WithMachineCallerCredential(WithSelfMachineGranter(ctx, caller.ID), raw)
	_, err := c.IssueMachineToken(ctx, 1, peer.ID, 0, IssueMachineTokenParams{Name: "audited"})
	require.NoError(t, err)

	var rows []models.AuditEvent
	require.NoError(t, st.DB().Where("event_type = ?", "machine_identity.token_issued").Find(&rows).Error)
	require.Len(t, rows, 1)
	row := rows[0]
	require.Equal(t, ActorTypeMachine, row.ActorType)
	require.NotNil(t, row.MachineIdentityID)
	require.Equal(t, caller.ID, *row.MachineIdentityID, "the row must name the calling machine, not the target")
	require.Nil(t, row.UserID, "a machine-actored row carries no user id")
}
