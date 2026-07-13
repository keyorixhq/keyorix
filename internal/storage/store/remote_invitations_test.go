package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Project invitations ---

func TestRemoteStorage_CreateProjectInvitation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/invitations", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":                       1,
			"project_id":               10,
			"email":                    "alice@example.com",
			"role":                     "viewer",
			"state":                    "pending",
			"invited_by":               5,
			"validation_mode_at_invite": "email",
			"system_role":              "",
			"assignments_json":         "{}",
			"created_at":               now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	inv, err := rs.CreateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ProjectID: 10, Email: "alice@example.com", Role: "viewer",
		State: "pending", InvitedBy: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(1), inv.ID)
	assert.Equal(t, "alice@example.com", inv.Email)
	assert.Equal(t, "pending", inv.State)
	assert.Equal(t, "viewer", inv.Role)
}

func TestRemoteStorage_GetProjectInvitation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/invitations/1", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":                       1,
			"project_id":               10,
			"email":                    "alice@example.com",
			"role":                     "viewer",
			"state":                    "pending",
			"invited_by":               5,
			"validation_mode_at_invite": "email",
			"system_role":              "",
			"assignments_json":         "{}",
			"created_at":               now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	inv, err := rs.GetProjectInvitation(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), inv.ID)
	assert.Equal(t, "alice@example.com", inv.Email)
	assert.Equal(t, uint(10), inv.ProjectID)
}

func TestRemoteStorage_UpdateProjectInvitation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/invitations/1", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"updated": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	accepted := now
	updated, err := rs.UpdateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ID: 1, ProjectID: 10, Email: "alice@example.com",
		Role: "viewer", State: "accepted", InvitedBy: 5,
		AcceptedAt: &accepted,
	})
	require.NoError(t, err)
	assert.True(t, updated)
}

func TestRemoteStorage_UpdateProjectInvitation_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"updated": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	updated, err := rs.UpdateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ID: 1, State: "accepted",
	})
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestRemoteStorage_ListProjectInvitations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/invitations", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"invitations": []map[string]interface{}{
				{
					"id":                       1,
					"project_id":               10,
					"email":                    "alice@example.com",
					"role":                     "viewer",
					"state":                    "pending",
					"invited_by":               5,
					"validation_mode_at_invite": "email",
					"system_role":              "",
					"assignments_json":         "{}",
					"created_at":               now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListProjectInvitations(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(1), list[0].ID)
	assert.Equal(t, "alice@example.com", list[0].Email)
	assert.Equal(t, uint(10), list[0].ProjectID)
}

// --- Access requests ---

func TestRemoteStorage_CreateAccessRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":             50,
			"project_id":     10,
			"user_id":        3,
			"suggested_role": "editor",
			"granted_role":   "",
			"state":          "pending",
			"reason":         "need access",
			"resolved_by":    0,
			"created_at":     now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	req, err := rs.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: 10, UserID: 3, SuggestedRole: "editor",
		State: "pending", Reason: "need access",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(50), req.ID)
	assert.Equal(t, "pending", req.State)
	assert.Equal(t, "editor", req.SuggestedRole)
}

func TestRemoteStorage_GetAccessRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests/50", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id":             50,
			"project_id":     10,
			"user_id":        3,
			"suggested_role": "editor",
			"granted_role":   "",
			"state":          "pending",
			"reason":         "need access",
			"resolved_by":    0,
			"created_at":     now,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	req, err := rs.GetAccessRequest(context.Background(), 50)
	require.NoError(t, err)
	assert.Equal(t, uint(50), req.ID)
	assert.Equal(t, uint(10), req.ProjectID)
	assert.Equal(t, uint(3), req.UserID)
}

func TestRemoteStorage_UpdateAccessRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests/50", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"updated": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	resolvedAt := now
	updated, err := rs.UpdateAccessRequest(context.Background(), &models.AccessRequest{
		ID: 50, ProjectID: 10, UserID: 3, SuggestedRole: "editor",
		GrantedRole: "editor", State: "approved",
		ResolvedBy: 1, ResolvedAt: &resolvedAt,
	})
	require.NoError(t, err)
	assert.True(t, updated)
}

func TestRemoteStorage_UpdateAccessRequest_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"updated": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	updated, err := rs.UpdateAccessRequest(context.Background(), &models.AccessRequest{
		ID: 50, State: "rejected",
	})
	require.NoError(t, err)
	assert.False(t, updated)
}

func TestRemoteStorage_ListAccessRequests(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"access_requests": []map[string]interface{}{
				{
					"id":             50,
					"project_id":     10,
					"user_id":        3,
					"suggested_role": "editor",
					"granted_role":   "",
					"state":          "pending",
					"reason":         "need access",
					"resolved_by":    0,
					"created_at":     now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListAccessRequests(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(50), list[0].ID)
	assert.Equal(t, "pending", list[0].State)
	assert.Equal(t, "need access", list[0].Reason)
}

// --- Access request approvals ---

func TestRemoteStorage_CreateAccessRequestApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests/50/approvals", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateAccessRequestApproval(context.Background(), &models.AccessRequestApproval{
		RequestID:  50,
		ApproverID: 2,
	})
	require.NoError(t, err)
}

func TestRemoteStorage_ListAccessRequestApprovals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/access-requests/50/approvals", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"approvals": []map[string]interface{}{
				{
					"id":          1,
					"request_id":  50,
					"approver_id": 2,
					"created_at":  now,
				},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	list, err := rs.ListAccessRequestApprovals(context.Background(), 50)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, uint(1), list[0].ID)
	assert.Equal(t, uint(50), list[0].RequestID)
	assert.Equal(t, uint(2), list[0].ApproverID)
}
