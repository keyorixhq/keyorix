package core

// GRPC-OUTAGE-TAILS-1 item 3 (#3912): a bulk-delete item that failed because the audit
// log or storage was unavailable is marked retryable with the stable code the single
// delete answers (audit_unavailable / storage_unavailable), and the batch summary counts
// how many items are retryable. A real not-found is NOT retryable: it must not be turned
// into an outage, or an operator would retry an item that will never exist.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestBulkDeleteSecrets_RetryableItemsAreMarkedAndCounted(t *testing.T) {
	w := newSMAWorld(t, newCTAReviewSQLite(t))
	outage := w.secret("bulk-retry-audit-outage")
	ok := w.secret("bulk-retry-ok")
	const missingID = 987654

	// w.ctx carries WithSecretMutationAudit: the first item's audit append fails.
	w.fs.Arm(&faultstorage.FaultSpec{Method: "LogAuditEventWithAccessLog", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected audit failure")})
	res, err := w.c.BulkDeleteSecrets(w.ctx, BulkDeleteRequest{SecretIDs: []uint{outage.ID, missingID, ok.ID}}, w.f.projectID, "admin", w.f.adminID, "198.51.100.7", "retry-test")
	fired := w.fs.Fired()
	w.fs.Arm(nil)

	require.True(t, fired, "bulk delete never appended its audit row through storage")
	require.NoError(t, err)
	require.Equal(t, []uint{ok.ID}, res.Deleted, "the healthy item is deleted")
	require.Len(t, res.Failed, 2)

	byID := map[uint]BulkOpError{}
	for _, f := range res.Failed {
		byID[f.SecretID] = f
	}
	require.Equal(t, MutationAuditUnavailableMessage, byID[outage.ID].Error)
	require.Equal(t, BulkErrCodeAuditUnavailable, byID[outage.ID].Code)
	require.True(t, byID[outage.ID].Retryable, "an audit outage is retryable")

	require.Equal(t, "secret not found", byID[missingID].Error)
	require.Empty(t, byID[missingID].Code, "a real not-found carries no outage code")
	require.False(t, byID[missingID].Retryable, "a real not-found is not retryable")

	require.Equal(t, 1, res.Retryable, "the summary counts only the retryable item")
	require.Equal(t, 3, res.Total)

	// Effect: the retryable item is still there and a retry after the outage deletes it.
	retry, err := w.c.BulkDeleteSecrets(w.ctx, BulkDeleteRequest{SecretIDs: []uint{outage.ID}}, w.f.projectID, "admin", w.f.adminID, "198.51.100.7", "retry-test")
	require.NoError(t, err)
	require.Equal(t, []uint{outage.ID}, retry.Deleted)
	require.Zero(t, retry.Retryable)
}

func TestBulkDeleteSecrets_StorageReadFaultIsRetryable(t *testing.T) {
	w := newSMAWorld(t, newCTAReviewSQLite(t))
	s := w.secret("bulk-retry-read-fault")
	before := w.state(s.ID, s.Name)

	w.fs.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected read failure")})
	res, err := w.c.BulkDeleteSecrets(w.ctx, BulkDeleteRequest{SecretIDs: []uint{s.ID}}, w.f.projectID, "admin", w.f.adminID, "198.51.100.7", "retry-test")
	fired := w.fs.Fired()
	w.fs.Arm(nil)

	require.True(t, fired)
	require.NoError(t, err)
	require.Empty(t, res.Deleted)
	require.Len(t, res.Failed, 1)
	require.Equal(t, StorageReadUnavailableMessage, res.Failed[0].Error)
	require.Equal(t, BulkErrCodeStorageUnavailable, res.Failed[0].Code)
	require.True(t, res.Failed[0].Retryable)
	require.Equal(t, 1, res.Retryable)
	require.Equal(t, before, w.state(s.ID, s.Name), "a refused item leaves the secret in place")
}
