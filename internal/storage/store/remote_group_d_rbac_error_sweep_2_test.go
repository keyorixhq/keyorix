// remote_group_d_rbac_error_sweep_2_test.go continues
// remote_group_d_rbac_error_sweep_test.go's coverage of remote_rbac.go's
// generic transport-error branches: Connect ref-grants, group role
// assignments, and the project/environment catalog proxies, plus
// RemoveGlobalAdminRoleGuarded's !resp.Success branch (its transport-error
// and sentinel-translation branches are already covered by
// store_s17_remote_test.go).
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ListConnectRefGrantsByConnector ---

func TestRemoteStorage_ListConnectRefGrantsByConnector_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListConnectRefGrantsByConnector(context.Background(), "connector-a")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list connect ref-grants by connector")
}

// --- ListConnectRefGrants ---

func TestRemoteStorage_ListConnectRefGrants_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListConnectRefGrants(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list connect ref-grants")
}

// --- GetGroupRoles ---

func TestRemoteStorage_GetGroupRoles_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetGroupRoles(context.Background(), 4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get group roles")
}

// --- ListGroupRoleAssignments ---

func TestRemoteStorage_ListGroupRoleAssignments_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupRoleAssignments(context.Background(), 4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list group role assignments")
}

// --- AssignRoleToGroup ---

func TestRemoteStorage_AssignRoleToGroup_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignRoleToGroup(context.Background(), 8, 2, corestorage.Scope{ProjectID: 5})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role to group")
}

// --- RemoveRoleFromGroup ---

func TestRemoteStorage_RemoveRoleFromGroup_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveRoleFromGroup(context.Background(), 8, 2, corestorage.Scope{ProjectID: 5, EnvironmentID: 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove role from group")
}

// --- ListProjects ---

func TestRemoteStorage_ListProjects_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjects(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// --- ListProjectsWithCounts ---

func TestRemoteStorage_ListProjectsWithCounts_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectsWithCounts(context.Background(), false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects with counts")
}

// --- GetProject ---

func TestRemoteStorage_GetProject_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProject(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project")
}

// --- DeleteProject ---

func TestRemoteStorage_DeleteProject_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteProject(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete project")
}

// --- DeleteProjectIfEmpty ---

func TestRemoteStorage_DeleteProjectIfEmpty_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.DeleteProjectIfEmpty(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete project if empty")
}

// --- ListEnvironments ---

func TestRemoteStorage_ListEnvironments_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListEnvironments(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// --- listEnvironmentsByProject (via ListEnvironmentsByProject) ---

func TestRemoteStorage_ListEnvironmentsByProject_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListEnvironmentsByProject(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments by project")
}

// --- GetEnvironment ---

func TestRemoteStorage_GetEnvironment_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetEnvironment(context.Background(), 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get environment")
}

// --- DeleteEnvironment ---

func TestRemoteStorage_DeleteEnvironment_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteEnvironment(context.Background(), 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete environment")
}

// --- ListProjectMembers ---

func TestRemoteStorage_ListProjectMembers_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectMembers(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list project members")
}

// --- ListProjectRoleAssignments ---

func TestRemoteStorage_ListProjectRoleAssignments_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectRoleAssignments(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list project role assignments")
}

// --- ListProjectMachineRoleAssignments ---

func TestRemoteStorage_ListProjectMachineRoleAssignments_TransportError_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectMachineRoleAssignments(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list project machine role assignments")
}

// --- RemoveGlobalAdminRoleGuarded: !resp.Success branch ---
//
// store_s17_remote_test.go already covers the err != nil branch (both
// sentinel-translated and generic fallthrough, via non-2xx statuses). This
// covers the remaining case: a 2xx response body carrying success:false with
// neither sentinel error code set.
func TestRemoteStorage_RemoveGlobalAdminRoleGuarded_SuccessFalse_GroupD(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "UNEXPECTED", "something odd happened"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveGlobalAdminRoleGuarded(context.Background(), 10, 1, []uint{1, 2})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "remove global admin role failed")
}
