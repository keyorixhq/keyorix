package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBulkDeleteSecrets_AuthzPanicOnLaterItemDoesNotLoseAlreadyCommittedDeletes
// is the regression test for a panic escaping BulkDeleteSecrets' per-item loop:
// the loop has no recover anywhere, so a panic raised while checking/deleting
// item N — including inside the per-secret AUTHORIZATION check
// (GetSecretWithPermissionCheck/DeleteSecretWithPermissionCheck, the same path
// #G31 added to close an authz bypass) — unwinds past BulkDeleteSecrets
// entirely, reaching only the transport layer's Recovery middleware. The
// caller is told the WHOLE batch failed (500) even though earlier items in
// the loop already committed their deletes — directly contradicting this
// file's own documented "Partial success is allowed" design.
//
// Fault targets storage.GetSecret's 5th call: for an owner-fast-path caller,
// one fully-processed item (GetSecretWithPermissionCheck's authz read + data
// fetch, DeleteSecretWithPermissionCheck's authz read + DeleteSecret's own
// fetch) makes exactly 4 GetSecret calls, so call #5 lands on the SECOND
// item's read-authorization check — after the first secret is already gone.
func TestBulkDeleteSecrets_AuthzPanicOnLaterItemDoesNotLoseAlreadyCommittedDeletes(t *testing.T) {
	c, mk, projectID := setupBulkDeleteDB(t)
	ctx := context.Background()

	id1 := mk("secret-one")
	id2 := mk("secret-two")

	faulty := faultstorage.NewFaultyStorage(c.storage, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "GetSecret", NthCall: 5, Kind: faultstorage.KindPanic,
	})

	result, err := c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{id1, id2}}, projectID, "tester", 1, "203.0.113.5", "test-agent/1.0")

	require.NoError(t, err, "a panic processing one item must not surface as an error from the whole batch call")
	require.NotNil(t, result)

	// The first secret's delete already committed before the panic — it must be
	// reported as deleted (reflecting reality), not silently dropped because a
	// LATER item blew up.
	assert.Contains(t, result.Deleted, id1, "secret 1 was already deleted before the panic and must be reported as such")

	// The second secret hit the panic — it must be reported as a per-item
	// failure (the documented partial-success contract), not lost.
	found := false
	for _, f := range result.Failed {
		if f.SecretID == id2 {
			found = true
		}
	}
	assert.True(t, found, "secret 2's panic must be reported as a per-item failure, not silently dropped")

	// Confirm via a fresh, unfaulted read that secret 1 is really gone.
	_, getErr := c.GetSecret(ctx, id1)
	assert.Error(t, getErr, "secret 1 must actually be deleted, not just reported as deleted")
}
