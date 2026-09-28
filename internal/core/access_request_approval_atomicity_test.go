package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceCreateAccessRequestApprovalStorage makes CreateAccessRequestApproval
// fail once, mirroring the failOnceStorage idiom from #2295.
type failOnceCreateAccessRequestApprovalStorage struct {
	storage.Storage
	armed *bool
}

func (s *failOnceCreateAccessRequestApprovalStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&failOnceCreateAccessRequestApprovalStorage{Storage: tx, armed: s.armed})
	})
}

func (s *failOnceCreateAccessRequestApprovalStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	if *s.armed {
		*s.armed = false
		return errors.New("injected fault: CreateAccessRequestApproval")
	}
	return s.Storage.CreateAccessRequestApproval(ctx, a)
}

// TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant is the
// red-proof for Session O's O3 access-request-approval fix: a failure
// recording the approval AFTER the role grant already landed must revert the
// grant too -- not the pre-fix behavior where the existing compensating
// revert only covered the LAST write's failure (UpdateAccessRequest's !ok
// race), leaving a CreateAccessRequestApproval failure with the role granted,
// zero approval record, and the request never flipping to approved.
func TestFinalizeAccessRequestApproval_ApprovalRecordFailureRevertsGrant(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "approval-proj", Description: "d"})
	require.NoError(t, err)
	requester, err := st.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)

	req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: proj.ID, UserID: requester.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
	})
	require.NoError(t, err)

	armed := true
	c.storage = &failOnceCreateAccessRequestApprovalStorage{Storage: st, armed: &armed}

	// actor 1 is the bootstrapped global admin (satisfies the grant-ceiling check).
	_, err = c.ApproveAccessRequestWithExpiry(ctx, proj.ID, req.ID, 1, 0, "project_viewer", time.Hour)
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	roles, rerr := st.GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, rerr)
	assert.Empty(t, roles, "a failed approval-record write must revert the role grant that already landed")

	reloaded, gerr := st.GetAccessRequest(ctx, req.ID)
	require.NoError(t, gerr)
	assert.Equal(t, AccessRequestPending, reloaded.State, "the request must stay pending, not silently approved with no approval record")

	approvals, aerr := st.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, aerr)
	assert.Empty(t, approvals)

	// Retry (fault disarmed) must fully succeed.
	_, err = c.ApproveAccessRequestWithExpiry(ctx, proj.ID, req.ID, 1, 0, "project_viewer", time.Hour)
	require.NoError(t, err)
	roles, rerr = st.GetUserRoleIDsAt(ctx, requester.ID, storage.Scope{ProjectID: proj.ID})
	require.NoError(t, rerr)
	assert.NotEmpty(t, roles, "a clean retry must grant the role")
}
