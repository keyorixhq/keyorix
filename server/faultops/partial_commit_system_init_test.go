package faultops

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// #3225, PARTIAL-COMMIT-TAILS-NOV-3 item 1: POST /system/init whose bootstrap
// transaction COMMITS and then reports an error (a lost acknowledgement) used to
// answer 500 while the admin, the catalog, the default project and the initialised
// marker committed, and skipped user.created / project.created and the
// password-history seed. It must answer the bootstrap, write both audit rows, and
// leave no second claim open.
func TestPartialCommit_SystemInitLostAckAnswersBootstrapped(t *testing.T) {
	in := lostAckCreate(t, "REST POST /system/init")
	require.True(t, strings.HasPrefix(in.result.Detail, "HTTP 200"), "a committed bootstrap must be answered 200, got: %s", in.result.Detail)
	require.Contains(t, in.result.Detail, `"already_initialized":false`, "the answer is the bootstrap itself")
	// The world's own bootstrap already wrote one of each: count the new ones.
	require.Equal(t, 1, snapshotAuditEventCount(in.after, "user.created")-snapshotAuditEventCount(in.before, "user.created"),
		"user.created is written after the lost ack")
	require.Equal(t, 1, snapshotAuditEventCount(in.after, "project.created")-snapshotAuditEventCount(in.before, "project.created"),
		"project.created is written after the lost ack")
	require.Equal(t, 1, len(in.after.Tables["PasswordHistory"].Rows)-len(in.before.Tables["PasswordHistory"].Rows),
		"the initial password seeds the history")

	sink := &driveSink{t: t}
	checkOraclesReporting(sink, in)
	require.Empty(t, sink.findings, "no oracle may flag the lost-ack bootstrap")

	// A second claim with the same token, after the answer: refused as initialised.
	st, body, err := httpJSONAs(context.Background(), in.world, "", http.MethodPost, "/system/init", map[string]any{
		"username": "intruder", "email": "intruder@example.com",
		"password": systemInitPassword, "bootstrap_token": systemInitToken,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, st, "body: %s", body)
	require.Contains(t, string(body), `"already_initialized":true`, "a second claim is refused, got: %s", body)
}

func TestPartialCommit_SystemInitRolledBackStaysAnError(t *testing.T) {
	in := rolledBackCreate(t, "REST POST /system/init")
	require.Equal(t, len(in.before.Tables["Project"].Rows), len(in.after.Tables["Project"].Rows), "nothing was bootstrapped")
	require.Equal(t, snapshotAuditEventCount(in.before, "user.created"), snapshotAuditEventCount(in.after, "user.created"),
		"a rolled-back bootstrap is not audited")
}

// snapshotAuditEventCount counts snap's AuditEvent rows of eventType (snapshotHasAuditEvent's match).
func snapshotAuditEventCount(snap dbSnapshot, eventType string) int {
	n := 0
	for _, row := range snap.Tables["AuditEvent"].Rows {
		if strings.Contains(row, `"`+eventType+`"`) {
			n++
		}
	}
	return n
}
