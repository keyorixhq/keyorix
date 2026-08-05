package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newBulkTestCore(t *testing.T) *KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	m := &MockStorage{}
	return &KeyorixCore{storage: m, now: time.Now}
}

// pendingReq builds a pending AccessRequest with projectID=1 so we can reuse it.
func pendingReq(id uint) *models.AccessRequest {
	return &models.AccessRequest{
		ID:            id,
		ProjectID:     1,
		UserID:        99,
		SuggestedRole: "editor",
		State:         AccessRequestPending,
	}
}

// ── BulkApproveAccessRequests ─────────────────────────────────────────────────

func TestBulkApproveAccessRequests_EmptyIDs(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.BulkApproveAccessRequests(context.Background(), nil, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBulkApproveAccessRequests_EmptySlice(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.BulkApproveAccessRequests(context.Background(), []uint{}, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBulkApproveAccessRequests_FetchError(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	storageErr := errors.New("db exploded")
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{1}).Return(nil, storageErr)

	_, err := k.BulkApproveAccessRequests(context.Background(), []uint{1}, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch")
}

func TestBulkApproveAccessRequests_NotFound(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	// ListAccessRequestsByIDs returns empty — the ID was not found.
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{42}).
		Return([]*models.AccessRequest{}, nil)

	result, err := k.BulkApproveAccessRequests(context.Background(), []uint{42}, 2)
	require.NoError(t, err)
	assert.Empty(t, result.Approved)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(42), result.Failed[0].RequestID)
	assert.Contains(t, result.Failed[0].Error, "not found")
}

func TestBulkApproveAccessRequests_ApproveError(t *testing.T) {
	// BulkApproveAccessRequests delegates to ApproveAccessRequest which calls
	// GetAccessRequest, GetProject, GetRoleByName, etc. — the simplest way to
	// exercise the "approve failed" branch is to have GetAccessRequest return an
	// error so ApproveAccessRequest itself returns an error.
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req := pendingReq(5)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{5}).
		Return([]*models.AccessRequest{req}, nil)
	// The per-project Authorize check calls scopedRoleIDs which reads these two
	// tables; return empty → no permission → "permission denied" in Failed.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkApproveAccessRequests(context.Background(), []uint{5}, 2)
	require.NoError(t, err)
	assert.Empty(t, result.Approved)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(5), result.Failed[0].RequestID)
}

func TestBulkApproveAccessRequests_TooManyIDs(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	ids := make([]uint, maxBulkAccessRequestBatchSize+1)
	for i := range ids {
		ids[i] = uint(i + 1)
	}

	result, err := k.BulkApproveAccessRequests(context.Background(), ids, 2)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "exceeds the maximum batch size")
	// The cap is checked before any storage access — no partial processing.
	m.AssertNotCalled(t, "ListAccessRequestsByIDs", mock.Anything, mock.Anything)
}

func TestBulkApproveAccessRequests_AtBatchLimit(t *testing.T) {
	// A batch exactly AT the cap must not be rejected by the size check, and every
	// item must still reach the per-item processing loop as before (no regression
	// on legitimate use). Permission is denied for all items (as in
	// TestBulkApproveAccessRequests_MixedResults) purely to keep the mock setup
	// simple; what this test verifies is that the cap itself does not trip and
	// that all items are attempted, not that approval succeeds.
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	ids := make([]uint, maxBulkAccessRequestBatchSize)
	reqs := make([]*models.AccessRequest, maxBulkAccessRequestBatchSize)
	for i := range ids {
		ids[i] = uint(i + 1)
		reqs[i] = pendingReq(uint(i + 1))
	}
	m.On("ListAccessRequestsByIDs", mock.Anything, ids).Return(reqs, nil)
	// Empty roles → Authorize denies every item → each lands in Failed, but the
	// loop still runs to completion for the full batch.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkApproveAccessRequests(context.Background(), ids, 2)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Approved)
	assert.Len(t, result.Failed, maxBulkAccessRequestBatchSize)
}

func TestBulkApproveAccessRequests_MixedResults(t *testing.T) {
	// ID 1 will succeed (found), ID 99 will fail (not found in pre-fetch).
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req1 := pendingReq(1)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{1, 99}).
		Return([]*models.AccessRequest{req1}, nil) // only req1 returned
	// Authorize check: empty roles → denied → "permission denied" in Failed.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkApproveAccessRequests(context.Background(), []uint{1, 99}, 2)
	require.NoError(t, err)

	// ID 1: failed (permission denied by Authorize); ID 99: failed (not in pre-fetch).
	assert.Empty(t, result.Approved)
	assert.Len(t, result.Failed, 2)
}

// ── BulkRejectAccessRequests ──────────────────────────────────────────────────

func TestBulkRejectAccessRequests_EmptyIDs(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.BulkRejectAccessRequests(context.Background(), nil, 1, "no access")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBulkRejectAccessRequests_EmptySlice(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.BulkRejectAccessRequests(context.Background(), []uint{}, 1, "no access")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBulkRejectAccessRequests_EmptyReason(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.BulkRejectAccessRequests(context.Background(), []uint{1}, 1, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason")
}

func TestBulkRejectAccessRequests_FetchError(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{1}).
		Return(nil, errors.New("db down"))

	_, err := k.BulkRejectAccessRequests(context.Background(), []uint{1}, 2, "not allowed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch")
}

func TestBulkRejectAccessRequests_NotFound(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{55}).
		Return([]*models.AccessRequest{}, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), []uint{55}, 2, "not allowed")
	require.NoError(t, err)
	assert.Empty(t, result.Rejected)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(55), result.Failed[0].RequestID)
	assert.Contains(t, result.Failed[0].Error, "not found")
}

func TestBulkRejectAccessRequests_RejectError(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req := pendingReq(7)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{7}).
		Return([]*models.AccessRequest{req}, nil)
	// Authorize check: empty roles → denied → "permission denied" in Failed.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), []uint{7}, 2, "denied")
	require.NoError(t, err)
	assert.Empty(t, result.Rejected)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(7), result.Failed[0].RequestID)
}

func TestBulkRejectAccessRequests_RejectNonPending(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	already := &models.AccessRequest{
		ID:        8,
		ProjectID: 1,
		UserID:    99,
		State:     AccessRequestApproved, // already resolved
	}
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{8}).
		Return([]*models.AccessRequest{already}, nil)
	// Authorize check: grant admin role so code reaches RejectAccessRequest.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{1}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetRoleByName", mock.Anything, mock.Anything).Return(&models.Role{ID: 1, Name: "admin"}, nil)
	m.On("GetAccessRequest", mock.Anything, uint(8)).
		Return(already, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), []uint{8}, 2, "denied")
	require.NoError(t, err)
	assert.Empty(t, result.Rejected)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(8), result.Failed[0].RequestID)
	assert.Contains(t, result.Failed[0].Error, "pending")
}

func TestBulkRejectAccessRequests_TooManyIDs(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	ids := make([]uint, maxBulkAccessRequestBatchSize+1)
	for i := range ids {
		ids[i] = uint(i + 1)
	}

	result, err := k.BulkRejectAccessRequests(context.Background(), ids, 2, "denied")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "exceeds the maximum batch size")
	// The cap is checked before any storage access — no partial processing.
	m.AssertNotCalled(t, "ListAccessRequestsByIDs", mock.Anything, mock.Anything)
}

func TestBulkRejectAccessRequests_AtBatchLimit(t *testing.T) {
	// A batch exactly AT the cap must not be rejected by the size check, and every
	// item must still reach the per-item processing loop as before (no regression
	// on legitimate use). See TestBulkApproveAccessRequests_AtBatchLimit for why
	// permission-denied is used to keep the mock setup simple.
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	ids := make([]uint, maxBulkAccessRequestBatchSize)
	reqs := make([]*models.AccessRequest, maxBulkAccessRequestBatchSize)
	for i := range ids {
		ids[i] = uint(i + 1)
		reqs[i] = pendingReq(uint(i + 1))
	}
	m.On("ListAccessRequestsByIDs", mock.Anything, ids).Return(reqs, nil)
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), ids, 2, "denied")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Rejected)
	assert.Len(t, result.Failed, maxBulkAccessRequestBatchSize)
}

func TestBulkRejectAccessRequests_MixedResults(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req3 := pendingReq(3)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{3, 77}).
		Return([]*models.AccessRequest{req3}, nil) // only req3 returned
	// Authorize check: empty roles → denied → "permission denied" for ID 3.
	m.On("GetUserRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)
	m.On("GetUserGroupRoleIDsAt", mock.Anything, uint(2), mock.Anything).Return([]uint{}, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), []uint{3, 77}, 2, "no")
	require.NoError(t, err)
	assert.Empty(t, result.Rejected)
	assert.Len(t, result.Failed, 2)
}

// ── RejectionReasonTemplate CRUD ──────────────────────────────────────────────

func TestCreateRejectionReasonTemplate_EmptyName(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.CreateRejectionReasonTemplate(context.Background(), 1, "", "too many requests")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestCreateRejectionReasonTemplate_EmptyReason(t *testing.T) {
	k := newBulkTestCore(t)
	_, err := k.CreateRejectionReasonTemplate(context.Background(), 1, "no-resources", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason")
}

func TestCreateRejectionReasonTemplate_StorageError(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("CreateRejectionReasonTemplate", mock.Anything, mock.AnythingOfType("*models.RejectionReasonTemplate")).
		Return(errors.New("unique constraint"))

	_, err := k.CreateRejectionReasonTemplate(context.Background(), 1, "no-resources", "we have none")
	require.Error(t, err)
}

func TestCreateRejectionReasonTemplate_Success(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("CreateRejectionReasonTemplate", mock.Anything, mock.AnythingOfType("*models.RejectionReasonTemplate")).
		Return(nil)

	tmpl, err := k.CreateRejectionReasonTemplate(context.Background(), 1, "no-resources", "we have none right now")
	require.NoError(t, err)
	assert.Equal(t, "no-resources", tmpl.Name)
	assert.Equal(t, "we have none right now", tmpl.Reason)
	assert.Equal(t, uint(1), tmpl.CreatedBy)
}

func TestListRejectionReasonTemplates_Success(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	templates := []models.RejectionReasonTemplate{
		{ID: 1, Name: "a", Reason: "reason-a"},
		{ID: 2, Name: "b", Reason: "reason-b"},
	}
	m.On("ListRejectionReasonTemplates", mock.Anything).Return(templates, nil)

	got, err := k.ListRejectionReasonTemplates(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestListRejectionReasonTemplates_StorageError(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("ListRejectionReasonTemplates", mock.Anything).Return(nil, errors.New("db error"))

	_, err := k.ListRejectionReasonTemplates(context.Background())
	require.Error(t, err)
}

func TestDeleteRejectionReasonTemplate_Success(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("DeleteRejectionReasonTemplate", mock.Anything, uint(5)).Return(nil)

	err := k.DeleteRejectionReasonTemplate(context.Background(), 5)
	require.NoError(t, err)
}

func TestDeleteRejectionReasonTemplate_NotFound(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)
	m.On("DeleteRejectionReasonTemplate", mock.Anything, uint(99)).
		Return(errors.New("not found"))

	err := k.DeleteRejectionReasonTemplate(context.Background(), 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
