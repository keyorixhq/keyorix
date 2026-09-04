// remote_group_f_users_error_sweep_test.go — closes the remaining coverage
// gaps in remote_users.go: primarily the !resp.Success branches for methods
// whose only existing error test used a 4xx/5xx status (which is consumed
// entirely by the transport-error branch in rs.client.X, never reaching
// !resp.Success — see remote_coverage_test.go's package doc), plus a handful
// of response-decode-error branches and the groupWire.toModel() DeletedAt
// branch and ListGroupMembersByGroupIDs's malformed-key `continue` branch
// that no existing test reaches.
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

// --- Users: !resp.Success branches ---

func TestRemoteStorage_CreateUser_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "CONFLICT", "user already exists"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateUser(context.Background(), &models.User{Username: "u1", Email: "u1@example.com"})
	assert.Error(t, err)
}

func TestRemoteStorage_GetUser_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUser(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_LockUserForUpdate_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.LockUserForUpdate(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserByEmail_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByEmail(context.Background(), "nobody@example.com")
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserByUsername_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByUsername(context.Background(), "nobody")
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserByExternalID_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByExternalID(context.Background(), "no-such-id")
	assert.Error(t, err)
}

func TestRemoteStorage_UpdateUser_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateUser(context.Background(), &models.User{ID: 999, Username: "ghost"})
	assert.Error(t, err)
}

func TestRemoteStorage_DeleteUser_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteUser(context.Background(), 999)
	assert.Error(t, err)
}

func TestRemoteStorage_RestoreUser_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreUser(context.Background(), 999)
	assert.Error(t, err)
}

// --- ListUsers ---

func TestRemoteStorage_ListUsers_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "INTERNAL", "db error"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListUsers(context.Background(), nil)
	assert.Error(t, err)
}

func TestRemoteStorage_ListUsers_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListUsers(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- ListUsersInStateBefore ---

func TestRemoteStorage_ListUsersInStateBefore_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListUsersInStateBefore(context.Background(), "invited", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_ListUsersInStateBefore_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "INTERNAL", "db error"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListUsersInStateBefore(context.Background(), "invited", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_ListUsersInStateBefore_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListUsersInStateBefore(context.Background(), "invited", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- GetUserGroups ---

func TestRemoteStorage_GetUserGroups_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserGroups(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserGroups_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserGroups(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- Groups: !resp.Success and decode-error branches ---

func TestRemoteStorage_CreateGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "CONFLICT", "group already exists"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateGroup(context.Background(), &models.Group{Name: "engineering"})
	assert.Error(t, err)
}

func TestRemoteStorage_GetGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetGroup(context.Background(), 999)
	assert.Error(t, err)
}

// GetGroup_DecodeErr also covers decodeGroupResponse's json.Unmarshal error
// branch shared by CreateGroup/GetGroup/UpdateGroup.
func TestRemoteStorage_GetGroup_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetGroup(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// GetGroup_WithDeletedAt exercises groupWire.toModel()'s `if w.DeletedAt != nil`
// branch — only reachable when the wire response carries a non-nil deleted_at.
func TestRemoteStorage_GetGroup_WithDeletedAt_G1(t *testing.T) {
	deletedAt := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wire := minimalGroupWire(5, "retired-group")
		wire["deleted_at"] = deletedAt.Format(time.RFC3339)
		_, _ = w.Write(apiOK(wire))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	group, err := rs.GetGroup(context.Background(), 5)
	require.NoError(t, err)
	assert.True(t, group.DeletedAt.Valid, "expected DeletedAt.Valid=true for a soft-deleted group")
	assert.WithinDuration(t, deletedAt, group.DeletedAt.Time, time.Second)
}

func TestRemoteStorage_UpdateGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateGroup(context.Background(), &models.Group{ID: 999, Name: "ghost"})
	assert.Error(t, err)
}

func TestRemoteStorage_DeleteGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteGroup(context.Background(), 999)
	assert.Error(t, err)
}

func TestRemoteStorage_RestoreGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreGroup(context.Background(), 999)
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroups_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "INTERNAL", "db error"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroups(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroups_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroups(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ListGroupsPage_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "INTERNAL", "db error"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListGroupsPage(context.Background(), 0, 10)
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroupsPage_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListGroupsPage(context.Background(), 0, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_AddUserToGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "CONFLICT", "already member"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AddUserToGroup(context.Background(), 1, 5, 0)
	assert.Error(t, err)
}

func TestRemoteStorage_RemoveUserFromGroup_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "membership not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveUserFromGroup(context.Background(), 1, 999, 0)
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroupMembers_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembers(context.Background(), 999)
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroupMembers_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembers(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- ListGroupMembersByGroupIDs ---

func TestRemoteStorage_ListGroupMembersByGroupIDs_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembersByGroupIDs(context.Background(), []uint{1, 2})
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroupMembersByGroupIDs_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "INTERNAL", "db error"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembersByGroupIDs(context.Background(), []uint{1, 2})
	assert.Error(t, err)
}

func TestRemoteStorage_ListGroupMembersByGroupIDs_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListGroupMembersByGroupIDs(context.Background(), []uint{1, 2})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ListGroupMembersByGroupIDs_MalformedKey exercises the `continue` branch hit
// when a response map key fails strconv.ParseUint — the malformed key's
// members are silently dropped rather than erroring the whole call, while a
// well-formed sibling key is still decoded normally.
func TestRemoteStorage_ListGroupMembersByGroupIDs_MalformedKey_G1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"not-a-uint": []interface{}{},
			"3":          []interface{}{minimalUserWire(10, "alice", "alice@example.com")},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.ListGroupMembersByGroupIDs(context.Background(), []uint{3})
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Len(t, result[3], 1)
	assert.Equal(t, "alice", result[3][0].Username)
}
