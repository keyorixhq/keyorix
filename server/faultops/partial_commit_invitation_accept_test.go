package faultops

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// PARTIAL-COMMIT-TAILS-NOV-3 item 2: invitation accept (POST /auth/setup/consume,
// purpose invitation_accept) creates the invitee's account through c.CreateUser, so
// a create transaction that commits and then reports an error (#3225) is read back
// (#4208) and the accept continues: the link is spent, the project grant made, the
// invitation accepted and the invitee signed in. Before this op the path was never
// driven under faults (docs/design/user-create-lost-ack-2026-11.md said "already
// correct" by reading alone).
func TestPartialCommit_InvitationAcceptLostAckSignsTheInviteeIn(t *testing.T) {
	in := lostAckCreate(t, setupInvitationOpKey)
	require.True(t, in.result.Success, "a committed account create must finish the accept, got: %s", in.result.Detail)
	require.Contains(t, in.result.Detail, `"username":"fuzzinvitee"`)
	require.Equal(t, 1, len(in.after.Tables["Session"].Rows)-len(in.before.Tables["Session"].Rows), "the invitee is signed in")
	require.Equal(t, 1, len(in.after.Tables["ProjectMembership"].Rows), "the invitation's membership is created")
	accepted := false
	for _, row := range in.after.Tables["ProjectInvitation"].Rows {
		accepted = accepted || strings.Contains(row, `"State":"accepted"`)
	}
	require.True(t, accepted, "the invitation is accepted")

	sink := &driveSink{t: t}
	checkOraclesReporting(sink, in)
	require.Empty(t, sink.findings, "no oracle may flag the lost-ack accept")
}

// A real rollback of the create stays the dead-link answer and leaves the link usable.
func TestPartialCommit_InvitationAcceptRolledBackKeepsTheLink(t *testing.T) {
	in := rolledBackCreate(t, setupInvitationOpKey)
	require.Equal(t, setupConsumeDeadLinkResponse, in.result.Detail)
	for _, row := range in.after.Tables["SetupToken"].Rows {
		require.Contains(t, row, `"State":"active"`, "the link is not spent by a rolled-back create")
	}
}
