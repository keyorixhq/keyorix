package core

// MSG-ACCURACY-1 item 2 (#3912): an audit-log outage inside DeleteSecret's transaction was
// reported per item as "internal error". It must say the audit log is unavailable and the
// item can be retried, delete nothing, and stay fail-closed.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestBulkDeleteSecrets_AuditOutageReportsRetryableMessageAndDeletesNothing(t *testing.T) {
	w := newSMAWorld(t, newCTAReviewSQLite(t))
	s := w.secret("bulk-audit-outage")
	before := w.state(s.ID, s.Name)

	// w.ctx carries WithSecretMutationAudit, so DeleteSecret appends its audit row inside
	// its own transaction; that append is the call that fails.
	w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEventWithAccessLog", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected audit failure")})
	res, err := w.c.BulkDeleteSecrets(w.ctx, BulkDeleteRequest{SecretIDs: []uint{s.ID}}, w.f.projectID, "admin", w.f.adminID, "198.51.100.7", "sma-test")
	fired := w.fs.Fired()
	w.fs.Arm(nil)

	require.True(t, fired, "bulk delete never appended its audit row through storage")
	require.NoError(t, err, "per-item failures are reported in the result, not as a request error")
	require.Empty(t, res.Deleted)
	require.Len(t, res.Failed, 1)
	require.Equal(t, s.ID, res.Failed[0].SecretID)
	require.Equal(t, MutationAuditUnavailableMessage, res.Failed[0].Error)
	require.Equal(t, before, w.state(s.ID, s.Name), "a failed audit append must leave the secret in place")
}
