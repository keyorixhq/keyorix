package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func membershipWireBody(id, projectID, userID uint) map[string]any {
	return map[string]any{
		"id":         id,
		"project_id": projectID,
		"user_id":    userID,
		"role":       "viewer",
		"state":      "active",
		"invited_by": uint(1),
		"invited_at": time.Now().UTC().Format(time.RFC3339),
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func membershipListBody(members []map[string]any) map[string]any {
	return map[string]any{"memberships": members}
}

func TestRemoteStorage_CreateProjectMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships", r.URL.Path)
		_, _ = w.Write(apiOK(membershipWireBody(1, 10, 5)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	m := &models.ProjectMembership{ProjectID: 10, UserID: 5, Role: "viewer", State: "active"}
	result, err := rs.CreateProjectMembership(context.Background(), m)
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, uint(10), result.ProjectID)
}

func TestRemoteStorage_GetProjectMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/7", r.URL.Path)
		_, _ = w.Write(apiOK(membershipWireBody(7, 10, 5)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetProjectMembership(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), result.ID)
}

func TestRemoteStorage_UpdateProjectMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/7", r.URL.Path)
		_, _ = w.Write(apiOK(membershipWireBody(7, 10, 5)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	m := &models.ProjectMembership{ID: 7, ProjectID: 10, UserID: 5, Role: "viewer", State: "active"}
	err = rs.UpdateProjectMembership(context.Background(), m)
	require.NoError(t, err)
}

func TestRemoteStorage_TransitionProjectMembershipState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/7/transition", r.URL.Path)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "provisioned", body["from_state"])
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	m := &models.ProjectMembership{ID: 7, ProjectID: 10, UserID: 5, Role: "viewer", State: "active"}
	matched, err := rs.TransitionProjectMembershipState(context.Background(), m, "provisioned")
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestRemoteStorage_TransitionProjectMembershipState_NotMatched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"matched": false}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	m := &models.ProjectMembership{ID: 7, State: "active"}
	matched, err := rs.TransitionProjectMembershipState(context.Background(), m, "provisioned")
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestRemoteStorage_ListProjectMemberships(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(membershipListBody([]map[string]any{membershipWireBody(1, 10, 5)})))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListProjectMemberships(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uint(1), results[0].ID)
}

func TestRemoteStorage_GetActiveProjectMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/active", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		assert.Equal(t, "5", r.URL.Query().Get("user_id"))
		_, _ = w.Write(apiOK(membershipWireBody(3, 10, 5)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetActiveProjectMembership(context.Background(), 10, 5)
	require.NoError(t, err)
	assert.Equal(t, uint(3), result.ID)
}

func TestRemoteStorage_ListStaleInvitedMemberships(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/stale", r.URL.Path)
		assert.NotEmpty(t, r.URL.Query().Get("before"))
		_, _ = w.Write(apiOK(membershipListBody([]map[string]any{membershipWireBody(2, 10, 5)})))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListStaleInvitedMemberships(context.Background(), time.Now())
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestRemoteStorage_ListUserProjectMemberships(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/by-user/5", r.URL.Path)
		_, _ = w.Write(apiOK(membershipListBody([]map[string]any{membershipWireBody(1, 10, 5)})))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListUserProjectMemberships(context.Background(), 5)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestRemoteStorage_CountProjectMembershipsByUsers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/project-memberships/counts", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]any{
			"5": map[string]any{"active": 2, "total": 3},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.CountProjectMembershipsByUsers(context.Background(), []uint{5})
	require.NoError(t, err)
	assert.NotNil(t, results)
}

func TestRemoteStorage_CountProjectMembershipsByUsers_Empty(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19998"))
	require.NoError(t, err)

	results, err := rs.CountProjectMembershipsByUsers(context.Background(), []uint{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestRemoteStorage_CreateProjectMembership_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   map[string]string{"code": "BAD_REQUEST", "message": "failed"},
		})
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateProjectMembership(context.Background(), &models.ProjectMembership{})
	assert.Error(t, err)
}
