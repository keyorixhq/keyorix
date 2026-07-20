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
	// GetAccessRequest is called inside ApproveAccessRequest.
	m.On("GetAccessRequest", mock.Anything, uint(5)).
		Return(nil, errors.New("record not found"))

	result, err := k.BulkApproveAccessRequests(context.Background(), []uint{5}, 2)
	require.NoError(t, err)
	assert.Empty(t, result.Approved)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(5), result.Failed[0].RequestID)
}

func TestBulkApproveAccessRequests_MixedResults(t *testing.T) {
	// ID 1 will succeed (found), ID 99 will fail (not found in pre-fetch).
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req1 := pendingReq(1)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{1, 99}).
		Return([]*models.AccessRequest{req1}, nil) // only req1 returned

	// For ID 1: ApproveAccessRequest → GetAccessRequest (returns error to
	// trigger the "failed" path without having to mock the entire RBAC chain).
	m.On("GetAccessRequest", mock.Anything, uint(1)).
		Return(nil, errors.New("something broke"))

	result, err := k.BulkApproveAccessRequests(context.Background(), []uint{1, 99}, 2)
	require.NoError(t, err)

	// ID 1: failed (GetAccessRequest error inside ApproveAccessRequest)
	// ID 99: failed (not in pre-fetch result)
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
	// GetAccessRequest is called inside RejectAccessRequest.
	m.On("GetAccessRequest", mock.Anything, uint(7)).
		Return(nil, errors.New("record not found"))

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
	m.On("GetAccessRequest", mock.Anything, uint(8)).
		Return(already, nil)

	result, err := k.BulkRejectAccessRequests(context.Background(), []uint{8}, 2, "denied")
	require.NoError(t, err)
	assert.Empty(t, result.Rejected)
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(8), result.Failed[0].RequestID)
	assert.Contains(t, result.Failed[0].Error, "pending")
}

func TestBulkRejectAccessRequests_MixedResults(t *testing.T) {
	k := newBulkTestCore(t)
	m := k.storage.(*MockStorage)

	req3 := pendingReq(3)
	m.On("ListAccessRequestsByIDs", mock.Anything, []uint{3, 77}).
		Return([]*models.AccessRequest{req3}, nil) // only req3 returned

	m.On("GetAccessRequest", mock.Anything, uint(3)).
		Return(nil, errors.New("storage error"))

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
