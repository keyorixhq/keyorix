// remote_group_b_invitations_error_sweep_test.go — closes the remaining
// uncovered branches in remote_invitations.go: the transport-error branch on
// every method (remote_invitations_test.go and
// remote_coverage_campaigns_dynamic_invitations_test.go only exercise the
// success and !resp.Success branches, not transport error), plus the
// !success/malformed-JSON branches of ListProjectInvitations and
// ListAccessRequests, which had no error-path tests at all before this file.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteStorage_CreateProjectInvitation_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ProjectID: 10, Email: "bob@example.com", Role: "viewer", State: "pending", InvitedBy: 5,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create invitation")
}

func TestRemoteStorage_GetProjectInvitation_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetProjectInvitation(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get invitation")
}

func TestRemoteStorage_UpdateProjectInvitation_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.UpdateProjectInvitation(context.Background(), &models.ProjectInvitation{ID: 1, State: "accepted"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update invitation")
}

func TestRemoteStorage_ListProjectInvitations_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListProjectInvitations(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list invitations")
}

func TestRemoteStorage_ListProjectInvitations_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectInvitations(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list invitations failed")
}

func TestRemoteStorage_ListProjectInvitations_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectInvitations(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_CreateAccessRequest_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: 10, UserID: 3, SuggestedRole: "editor", State: "pending",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create access request")
}

func TestRemoteStorage_GetAccessRequest_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetAccessRequest(context.Background(), 50)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get access request")
}

func TestRemoteStorage_UpdateAccessRequest_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.UpdateAccessRequest(context.Background(), &models.AccessRequest{ID: 50, State: "approved"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update access request")
}

func TestRemoteStorage_ListAccessRequests_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListAccessRequests(context.Background(), 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list access requests")
}

func TestRemoteStorage_ListAccessRequests_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessRequests(context.Background(), 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list access requests failed")
}

func TestRemoteStorage_ListAccessRequests_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessRequests(context.Background(), 10)
	assert.Error(t, err)
}

func TestRemoteStorage_CreateAccessRequestApproval_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateAccessRequestApproval(context.Background(), &models.AccessRequestApproval{RequestID: 50, ApproverID: 2})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create access request approval")
}

func TestRemoteStorage_ListAccessRequestApprovals_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListAccessRequestApprovals(context.Background(), 50)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list access request approvals")
}
