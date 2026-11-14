package faultops

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// #3225: POST /api/v1/users/ whose create transaction COMMITS and then reports an
// error (a lost acknowledgement) used to answer 500 while the user, its baseline
// role and its user.created row were all committed, and skipped the post-commit
// password-history seed: a client that retried got a duplicate-user conflict on a
// create that had worked, and the committed state matched neither the pre-fault
// state nor the fault-free one (oracle (d)). The answer must reflect the commit:
// the create is read back, and a row that landed is delivered as a success with
// the rest of the success path (password history) done.
func TestPartialCommit_UserCreateLostAckAnswersSuccess(t *testing.T) {
	in, outcome, why := driveFaultCase(t, "REST POST /api/v1/users/", "WithTransaction", 1, faultstorage.KindEffectThenError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.Equal(t, 1, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"premise: the create transaction committed its user row")

	require.True(t, in.result.Success, "a committed create must be answered as a success, got: %s", in.result.Detail)

	sink := &driveSink{t: t}
	checkOraclesReporting(sink, in)
	require.Empty(t, sink.findings, "no oracle may flag the lost-ack create")
}

// The read-back must not turn a real failure into a success: when the create
// transaction rolls back (a plain error, nothing committed), the error stands and
// no user exists.
func TestPartialCommit_UserCreateRolledBackStaysAnError(t *testing.T) {
	in, outcome, why := driveFaultCase(t, "REST POST /api/v1/users/", "WithTransaction", 1, faultstorage.KindError)
	require.Equal(t, driveObserved, outcome, "premise: the fault must fire: %s", why)
	require.False(t, in.result.Success, "a rolled-back create must be answered as an error")
	require.Equal(t, 0, len(in.after.Tables["User"].Rows)-len(in.before.Tables["User"].Rows),
		"a rolled-back create must leave no user row")
}
