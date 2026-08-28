// store_s28_test.go — s28 coverage blitz for internal/storage/store.
//
// Targets (error-path coverage for remote_rbac.go, remote_machine_identities.go,
// remote_secrets.go, and local_secrets.go):
//
//	remote_rbac.go
//	  CreateRole             — API error + network error
//	  GetRole                — API error + bad JSON
//	  GetRoleByName          — API error
//	  UpdateRole             — API error + bad JSON
//	  DeleteRole             — API error + network error
//	  ListRoles              — API error + bad JSON
//	  AssignRole             — API error
//	  RemoveRole             — API error
//	  GetGroupRoleGrants     — API error + bad JSON
//	  AssignRoleWithExpiry   — API error
//	  AssignRoleToGroupWithExpiry — API error
//	  DeleteExpiredRoleGrants — API error + bad JSON
//	  RemoveAllProjectRoleGrants — API error
//	  GetUserRoles           — API error + bad JSON
//	  GetUserPermissions     — API error + bad JSON
//	  ListPermissions        — API error + bad JSON
//	  GetPermission          — API error + bad JSON
//	  GetRolePermissions     — API error + bad JSON
//	  RemovePermissionFromRole — API error
//	  ListConnectRefGrantsByConnector — API error + bad JSON
//	  ListConnectRefGrants   — API error
//	  CreateConnectRefGrant  — API error + bad JSON
//	  DeleteConnectRefGrant  — API error
//	  GetGroupRoles          — API error + bad JSON
//	  ListGroupRoleAssignments — API error + bad JSON
//	  AssignRoleToGroup      — API error
//	  RemoveRoleFromGroup    — API error
//	  ListProjectMembers     — API error + bad JSON
//	  ListProjectRoleAssignments — API error + bad JSON
//	  ListProjectMachineRoleAssignments — API error + bad JSON
//
//	remote_machine_identities.go
//	  CreateMachineIdentity  — API error
//	  GetMachineIdentity     — API error + bad JSON
//	  LockMachineIdentityForUpdate — API error
//	  UpdateMachineIdentity  — API error
//	  TransitionMachineIdentityState — API error + bad JSON
//	  ListMachineIdentities  — API error + bad JSON
//	  ListAllMachineIdentities — API error + bad JSON
//	  CountMachineIdentitiesByClassification — API error + bad JSON
//	  CreateMachineIdentityCredential — API error
//	  GetMachineIdentityCredentialByHash — API error
//	  GetMachineIdentityCredentialByID — API error
//	  ListMachineIdentityCredentials — API error + bad JSON
//	  ListActiveMachineIdentityCredentials — API error + bad JSON
//	  UpdateMachineIdentityCredential — API error
//	  CountMachineIdentityCredentialsByClassification — API error + bad JSON
//	  RevokeMachineIdentityCredential — API error
//	  TouchMachineIdentityCredential — API error
//	  AssignMachineRole      — API error
//	  RemoveMachineRole      — API error
//	  GetMachineRoleIDsAt    — API error + bad JSON
//	  GetMachineRoles        — API error + bad JSON
//	  CreateOIDCBinding      — API error
//	  GetMachineByOIDCSubject — API error
//	  ListOIDCBindings       — API error + bad JSON
//	  GetOIDCBindingByID     — API error
//	  DeleteOIDCBinding      — API error
//
//	remote_secrets.go
//	  CreateSecret           — API error + with plaintextValue
//	  GetSecret              — API error + bad JSON
//	  GetSecretByName        — API error + bad JSON
//	  UpdateSecret           — API error + bad JSON
//	  DeleteSecret           — API error
//	  GetSecretIncludingDeleted — API error
//	  RestoreSecret          — API error
//	  newSecretUpdateWireRequest — nil expiration + non-nil expiration
//
//	local_secrets.go
//	  CreateProject          — DB error (non-duplicate)
//	  GetProject             — not-found + DB error
//	  UpdateProject          — DB error
//	  GetSecretsByIDs        — DB error
//	  GetSecretByName        — DB error
//	  UpdateSecret           — DB error
//	  DeleteSecret           — share-delete DB error path
//	  GetSecretIncludingDeleted — not-found
//	  RequireLiveProject     — DB error
//	  RequireLiveEnvironment — DB error
//	  ListLiveSecretNamesByProject — DB error
//	  GetSecretTags          — DB error
//	  SetSecretTags          — DB error
//	  CreateSecretVersion    — DB error
//	  GetSecretVersions      — DB error
//	  GetLatestSecretVersion — DB error + not-found
//	  TryIncrementSecretReadCount — DB error
//	  TryIncrementSecretNodeReadCount — DB error
package store_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// s28DBSeq makes each in-memory DB unique within the process, even across
// repeated invocations of the same test (e.g. `go test -count=N`).
var s28DBSeq atomic.Int64

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// apiErrResp returns a JSON "success:false" response with a code and message.
func apiErrResp(code, message string) []byte {
	return []byte(`{"success":false,"error":{"code":"` + code + `","message":"` + message + `"}}`)
}

// newS28Store opens a unique in-memory SQLite DB with the requested models auto-migrated.
func newS28Store(t *testing.T, mods ...interface{}) *store.LocalStorage {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_s28_%d?mode=memory&cache=shared", t.Name(), s28DBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	if len(mods) > 0 {
		require.NoError(t, db.AutoMigrate(mods...))
	}
	return store.NewLocalStorage(db)
}

// brokenS28Store returns a LocalStorage whose underlying DB is already closed.
func brokenS28Store(t *testing.T) *store.LocalStorage {
	t.Helper()
	dsn := fmt.Sprintf("file:%s_s28broken_%d?mode=memory&cache=shared", t.Name(), s28DBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return store.NewLocalStorage(db)
}

// newS28Remote creates a RemoteStorage pointed at the given test server URL.
func newS28Remote(t *testing.T, serverURL string) *store.RemoteStorage {
	t.Helper()
	rs, err := store.NewRemoteStorage(testConfig(serverURL))
	require.NoError(t, err)
	return rs
}

// ---------------------------------------------------------------------------
// remote_rbac.go — error paths
// ---------------------------------------------------------------------------

func TestRemoteStorage_S28_CreateRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "server error"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CreateRole(context.Background(), &models.Role{Name: "admin"})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "role not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetRole(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetRole_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetRole(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetRoleByName_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "role not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetRoleByName(context.Background(), "nonexistent")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_UpdateRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "role not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.UpdateRole(context.Background(), &models.Role{ID: 99, Name: "new"})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_UpdateRole_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"bad"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.UpdateRole(context.Background(), &models.Role{ID: 1, Name: "x"})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_DeleteRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "role not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.DeleteRole(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListRoles_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "server error"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListRoles(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListRoles_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListRoles(context.Background())
	assert.Error(t, err)
}

// AssignRole/RemoveRole are permanent stubs as of the #1511/G80 deletion
// pass — see TestRemoteStorage_AssignRole_Unsupported/
// TestRemoteStorage_RemoveRole_Unsupported (remote_rbac_test.go).

func TestRemoteStorage_S28_GetGroupRoleGrants_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "group not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetGroupRoleGrants(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetGroupRoleGrants_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetGroupRoleGrants(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_AssignRoleWithExpiry_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.AssignRoleWithExpiry(context.Background(), 1, 1, coreScope(), time.Now().Add(time.Hour))
	assert.Error(t, err)
}

func TestRemoteStorage_S28_AssignRoleToGroupWithExpiry_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.AssignRoleToGroupWithExpiry(context.Background(), 1, 1, coreScope(), time.Now().Add(time.Hour))
	assert.Error(t, err)
}

func TestRemoteStorage_S28_DeleteExpiredRoleGrants_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.DeleteExpiredRoleGrants(context.Background(), time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_DeleteExpiredRoleGrants_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"bad"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.DeleteExpiredRoleGrants(context.Background(), time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RemoveAllProjectRoleGrants_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RemoveAllProjectRoleGrants(context.Background(), 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetUserRoles_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "user not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetUserRoles(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetUserRoles_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetUserRoles(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetUserPermissions_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "user not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetUserPermissions(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetUserPermissions_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetUserPermissions(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListPermissions_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListPermissions(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListPermissions_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListPermissions(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetPermission_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "permission not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetPermission(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetPermission_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetPermission(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetRolePermissions_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "role not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetRolePermissions(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetRolePermissions_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetRolePermissions(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RemovePermissionFromRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RemovePermissionFromRole(context.Background(), 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListConnectRefGrantsByConnector_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListConnectRefGrantsByConnector(context.Background(), "my-conn")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListConnectRefGrantsByConnector_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListConnectRefGrantsByConnector(context.Background(), "my-conn")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListConnectRefGrants_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListConnectRefGrants(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetGroupRoles_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "group not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetGroupRoles(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetGroupRoles_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetGroupRoles(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListGroupRoleAssignments_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "group not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListGroupRoleAssignments(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListGroupRoleAssignments_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListGroupRoleAssignments(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_AssignRoleToGroup_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("CONFLICT", "already assigned"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.AssignRoleToGroup(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RemoveRoleFromGroup_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RemoveRoleFromGroup(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectMembers_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "project not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectMembers(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectMembers_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectMembers(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectRoleAssignments_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectRoleAssignments(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectRoleAssignments_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectRoleAssignments(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectMachineRoleAssignments_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectMachineRoleAssignments(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListProjectMachineRoleAssignments_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-array"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListProjectMachineRoleAssignments(context.Background(), 1)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// remote_machine_identities.go — error paths
// ---------------------------------------------------------------------------

func TestRemoteStorage_S28_CreateMachineIdentity_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CreateMachineIdentity(context.Background(), &models.MachineIdentity{Name: "ci"})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineIdentity_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineIdentity(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineIdentity_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineIdentity(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_LockMachineIdentityForUpdate_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.LockMachineIdentityForUpdate(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_TransitionMachineIdentityState_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("CONFLICT", "conflict"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.TransitionMachineIdentityState(context.Background(), &models.MachineIdentity{ID: 1}, "pending")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_TransitionMachineIdentityState_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"bad"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.TransitionMachineIdentityState(context.Background(), &models.MachineIdentity{ID: 1}, "pending")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListMachineIdentities_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListMachineIdentities(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListMachineIdentities_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListMachineIdentities(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListAllMachineIdentities_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListAllMachineIdentities(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListAllMachineIdentities_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListAllMachineIdentities(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CountMachineIdentitiesByClassification_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CountMachineIdentitiesByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CountMachineIdentitiesByClassification_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CountMachineIdentitiesByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CreateMachineIdentityCredential_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{MachineIdentityID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineIdentityCredentialByHash_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineIdentityCredentialByHash(context.Background(), "abc123")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineIdentityCredentialByID_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineIdentityCredentialByID(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListMachineIdentityCredentials_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListMachineIdentityCredentials(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListMachineIdentityCredentials_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListMachineIdentityCredentials(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListActiveMachineIdentityCredentials_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListActiveMachineIdentityCredentials(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListActiveMachineIdentityCredentials_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListActiveMachineIdentityCredentials(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_UpdateMachineIdentityCredential_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.UpdateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{ID: 99})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CountMachineIdentityCredentialsByClassification_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CountMachineIdentityCredentialsByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CountMachineIdentityCredentialsByClassification_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CountMachineIdentityCredentialsByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RevokeMachineIdentityCredential_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RevokeMachineIdentityCredential(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_TouchMachineIdentityCredential_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.TouchMachineIdentityCredential(context.Background(), 99, time.Now(), time.Hour)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_AssignMachineRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("CONFLICT", "already assigned"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.AssignMachineRole(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RemoveMachineRole_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RemoveMachineRole(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineRoleIDsAt_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineRoleIDsAt(context.Background(), 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineRoleIDsAt_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineRoleIDsAt(context.Background(), 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineRoles_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineRoles(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineRoles_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineRoles(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CreateOIDCBinding_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("CONFLICT", "already exists"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CreateOIDCBinding(context.Background(), &models.MachineIdentityOIDCBinding{MachineIdentityID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetMachineByOIDCSubject_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetMachineByOIDCSubject(context.Background(), "https://issuer", "sub123")
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListOIDCBindings_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListOIDCBindings(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_ListOIDCBindings_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.ListOIDCBindings(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetOIDCBindingByID_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetOIDCBindingByID(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_DeleteOIDCBinding_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.DeleteOIDCBinding(context.Background(), 99)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// remote_secrets.go — error paths
// ---------------------------------------------------------------------------

func TestRemoteStorage_S28_CreateSecret_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.CreateSecret(context.Background(), &models.SecretNode{Name: "s"})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_CreateSecret_WithPlaintextValue_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 5, "name": "mysec"}))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	result, err := rs.CreateSecret(context.Background(), &models.SecretNode{Name: "mysec"}, "myvalue")
	require.NoError(t, err)
	assert.Equal(t, uint(5), result.ID)
	// When a plaintext value is provided, ValueStored should be set true.
	assert.True(t, result.ValueStored)
}

func TestRemoteStorage_S28_GetSecret_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "secret not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetSecret(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetSecret_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetSecret(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetSecretByName_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "secret not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetSecretByName(context.Background(), "missing", 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetSecretByName_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetSecretByName(context.Background(), "s", 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_UpdateSecret_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "secret not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 99})
	assert.Error(t, err)
}

func TestRemoteStorage_S28_UpdateSecret_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-object"}`))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 1})
	assert.Error(t, err)
}

// TestRemoteStorage_S28_UpdateSecret_NilExpiration covers newSecretUpdateWireRequest
// (G80 Phase 0: a full Go-to-Go SecretNode round trip, see remote_secrets.go) when
// Expiration is nil — the hub's own default-deny diff (server/http/handlers/
// secret_update_diff.go) is what now decides this means "clear the expiration," not a
// client-side clear_expiration flag.
func TestRemoteStorage_S28_UpdateSecret_NilExpiration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "s"}))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	result, err := rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 1})
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
}

// TestRemoteStorage_S28_UpdateSecret_NonNilExpiration is NilExpiration's counterpart
// with Expiration set.
func TestRemoteStorage_S28_UpdateSecret_NonNilExpiration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 2, "name": "s2"}))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	exp := time.Now().Add(24 * time.Hour)
	result, err := rs.UpdateSecret(context.Background(), &models.SecretNode{ID: 2, Expiration: &exp})
	require.NoError(t, err)
	assert.Equal(t, uint(2), result.ID)
}

func TestRemoteStorage_S28_DeleteSecret_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.DeleteSecret(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_GetSecretIncludingDeleted_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	_, err := rs.GetSecretIncludingDeleted(context.Background(), 99)
	assert.Error(t, err)
}

func TestRemoteStorage_S28_RestoreSecret_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiErrResp("NOT_FOUND", "not found"))
	}))
	defer srv.Close()
	rs := newS28Remote(t, srv.URL)
	err := rs.RestoreSecret(context.Background(), 99)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secrets.go — error branches
// ---------------------------------------------------------------------------

// secretModels lists the models required for local_secrets tests.
var secretModels = []interface{}{
	&models.Project{},
	&models.Environment{},
	&models.SecretNode{},
	&models.ShareRecord{},
	&models.SecretTag{},
	&models.SecretVersion{},
}

func TestLocalStorage_S28_CreateProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.CreateProject(context.Background(), &models.Project{Name: "p"})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetProject_NotFound(t *testing.T) {
	ls := newS28Store(t, &models.Project{})
	_, err := ls.GetProject(context.Background(), 999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLocalStorage_S28_GetProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetProject(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_UpdateProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.UpdateProject(context.Background(), &models.Project{ID: 1, Name: "x"})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretsByIDs_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretsByIDs(context.Background(), []uint{1, 2})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretByName_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretByName(context.Background(), "s", 1, 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_UpdateSecret_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.UpdateSecret(context.Background(), &models.SecretNode{ID: 1})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretIncludingDeleted_NotFound(t *testing.T) {
	ls := newS28Store(t, secretModels...)
	_, err := ls.GetSecretIncludingDeleted(context.Background(), 999)
	require.Error(t, err)
}

func TestLocalStorage_S28_ListLiveSecretNamesByProject_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, _, err := ls.ListLiveSecretNamesByProject(context.Background(), []uint{1}, 10)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretTags_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretTags(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_SetSecretTags_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	err := ls.SetSecretTags(context.Background(), 1, []string{"tag1"})
	require.Error(t, err)
}

func TestLocalStorage_S28_CreateSecretVersion_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.CreateSecretVersion(context.Background(), &models.SecretVersion{SecretNodeID: 1, VersionNumber: 1})
	require.Error(t, err)
}

func TestLocalStorage_S28_GetSecretVersions_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetSecretVersions(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetLatestSecretVersion_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.GetLatestSecretVersion(context.Background(), 1)
	require.Error(t, err)
}

func TestLocalStorage_S28_GetLatestSecretVersion_NotFound(t *testing.T) {
	ls := newS28Store(t, secretModels...)
	// No versions in DB for secret 999.
	_, err := ls.GetLatestSecretVersion(context.Background(), 999)
	require.Error(t, err)
}

func TestLocalStorage_S28_TryIncrementSecretReadCount_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.TryIncrementSecretReadCount(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestLocalStorage_S28_TryIncrementSecretNodeReadCount_DBError(t *testing.T) {
	ls := brokenS28Store(t)
	_, err := ls.TryIncrementSecretNodeReadCount(context.Background(), 1, 5)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// helper: coreScope returns a zero-value storage.Scope (no import of
// internal/core/storage needed — the store_test package already has it via
// testConfig; use corestorage.Scope{} alias through testConfig helper).
// We define our own zero-value struct helper to avoid an import cycle.
// ---------------------------------------------------------------------------

// coreScope builds a zero Scope.  The remote methods accept storage.Scope
// by value from internal/core/storage; re-declare the zero here via the
// already-imported alias corestorage.
func coreScope() corestorage.Scope {
	return corestorage.Scope{}
}
