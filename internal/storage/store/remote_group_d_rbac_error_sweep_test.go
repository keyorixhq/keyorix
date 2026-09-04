// remote_group_d_rbac_error_sweep_test.go covers remote_rbac.go's generic
// transport-error branches (the `if err != nil` guard right after each
// rs.client.Get/Post/Put/Delete call) that remote_rbac_test.go /
// remote_rbac_completeness_test.go exercise for the !resp.Success and
// decode-error branches but never for a raw 4xx/5xx transport failure.
// Split across two files (this one: Roles / RBAC assignment / permissions);
// see remote_group_d_rbac_error_sweep_2_test.go for Connect grants / groups /
// projects / environments.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CreateRole ---

func TestRemoteStorage_CreateRole_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	name, err := identity.NewFoldedName("admin")
	require.NoError(t, err)
	_, err = rs.CreateRole(context.Background(), name, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create role")
}

// --- GetRole ---

func TestRemoteStorage_GetRole_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "role not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRole(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get role")
}

// --- GetRoleByName ---

func TestRemoteStorage_GetRoleByName_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "role not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRoleByName(context.Background(), "admin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get role by name")
}

func TestRemoteStorage_GetRoleByName_BadJSON_GroupD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRoleByName(context.Background(), "admin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- UpdateRole ---

func TestRemoteStorage_UpdateRole_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateRole(context.Background(), &models.Role{ID: 5, Name: "editor"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update role")
}

// --- DeleteRole ---

func TestRemoteStorage_DeleteRole_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteRole(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete role")
}

// --- ListRoles ---

func TestRemoteStorage_ListRoles_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListRoles(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list roles")
}

// --- GetGroupRoleGrants ---

func TestRemoteStorage_GetGroupRoleGrants_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetGroupRoleGrants(context.Background(), 4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get group role grants")
}

// --- AssignRoleWithExpiry ---

func TestRemoteStorage_AssignRoleWithExpiry_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignRoleWithExpiry(context.Background(), 10, 1, corestorage.Scope{ProjectID: 5}, time.Now().Add(time.Hour))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role with expiry")
}

// --- AssignRoleToGroupWithExpiry ---

func TestRemoteStorage_AssignRoleToGroupWithExpiry_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignRoleToGroupWithExpiry(context.Background(), 3, 1, corestorage.Scope{ProjectID: 5}, time.Now().Add(time.Hour))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role to group with expiry")
}

// --- DeleteExpiredRoleGrants ---

func TestRemoteStorage_DeleteExpiredRoleGrants_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.DeleteExpiredRoleGrants(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to purge expired role grants")
}

// --- RemoveAllProjectRoleGrants ---

func TestRemoteStorage_RemoveAllProjectRoleGrants_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveAllProjectRoleGrants(context.Background(), 10, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove all project role grants")
}

// --- GetUserRoles ---

func TestRemoteStorage_GetUserRoles_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserRoles(context.Background(), 12)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}

// --- GetUserPermissions ---

func TestRemoteStorage_GetUserPermissions_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserPermissions(context.Background(), 12)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user permissions")
}

// --- ListPermissions ---

func TestRemoteStorage_ListPermissions_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListPermissions(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list permissions")
}

// --- GetPermission ---

func TestRemoteStorage_GetPermission_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetPermission(context.Background(), 9)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get permission")
}

// --- GetRolePermissions ---

func TestRemoteStorage_GetRolePermissions_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRolePermissions(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get role permissions")
}

// --- RemovePermissionFromRole ---

func TestRemoteStorage_RemovePermissionFromRole_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemovePermissionFromRole(context.Background(), 5, 9)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove permission from role")
}
