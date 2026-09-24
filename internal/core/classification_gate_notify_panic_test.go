package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequestSecretAccess_NotifyPanicDoesNotUndoAlreadyCommittedRequest is the
// regression test for docs/findings/2026-09-24-FINDING-secret-access-request-notify-panic.md,
// found by server/faultops' FuzzStorageFaultOperations fuzzing its own new
// "REST POST /api/v1/secret-access-requests" catalog entry
// (fault=(ListProjectMembers, NthCall=1, kind=panic)): RequestSecretAccess
// already commits the AccessRequest row before calling
// notifySecretAccessRequested — a panic in that best-effort fan-out must not
// make the caller (and, one layer up, the HTTP handler) report the whole
// operation as failed when the request row genuinely exists.
func TestRequestSecretAccess_NotifyPanicDoesNotUndoAlreadyCommittedRequest(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "ListProjectMembers", NthCall: 1, Kind: faultstorage.KindPanic,
	})

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it for an incident")

	// Pre-fix: this panicked past RequestSecretAccess entirely (caught only by
	// the HTTP layer's Recovery middleware, reporting the whole call as a 500)
	// while the AccessRequest row it panicked AFTER creating stayed committed.
	require.NoError(t, err, "a panic in the best-effort notify fan-out must not surface as an error from the primary operation")
	require.NotNil(t, req)
	assert.NotZero(t, req.ID)

	// Confirm via a fresh, unfaulted read — not just the in-memory return value.
	reread, err := st.GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestPending, reread.State)
}
