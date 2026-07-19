// remote_users_s36_test.go — error-path sweep for RemoteStorage user/group
// functions that had success tests but no !resp.Success test, leaving the
// error-return branch uncovered.
package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiErr(code, message string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"success": false,
		"error":   map[string]string{"code": code, "message": message},
	})
	return b
}

func errHandler(statusCode int, code, message string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write(apiErr(code, message))
	}
}

// --- LockUserForUpdate ---

func TestRemoteStorage_LockUserForUpdate_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.LockUserForUpdate(context.Background(), 999)
	assert.Error(t, err)
}

// --- GetUserByExternalID ---

func TestRemoteStorage_GetUserByExternalID_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserByExternalID(context.Background(), "no-such-id")
	assert.Error(t, err)
}

// --- DeleteUser ---

func TestRemoteStorage_DeleteUser_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteUser(context.Background(), 999)
	assert.Error(t, err)
}

// --- RestoreUser ---

func TestRemoteStorage_RestoreUser_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreUser(context.Background(), 999)
	assert.Error(t, err)
}

// --- GetUserGroups ---

func TestRemoteStorage_GetUserGroups_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "user not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetUserGroups(context.Background(), 1)
	assert.Error(t, err)
}

// --- UpdateGroup ---

func TestRemoteStorage_UpdateGroup_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateGroup(context.Background(), &models.Group{ID: 999, Name: "ghost"})
	assert.Error(t, err)
}

// --- DeleteGroup ---

func TestRemoteStorage_DeleteGroup_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteGroup(context.Background(), 999)
	assert.Error(t, err)
}

// --- RestoreGroup ---

func TestRemoteStorage_RestoreGroup_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "group not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreGroup(context.Background(), 999)
	assert.Error(t, err)
}

// --- RemoveUserFromGroup ---

func TestRemoteStorage_RemoveUserFromGroup_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "membership not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveUserFromGroup(context.Background(), 1, 999, 0)
	assert.Error(t, err)
}

// --- ListGroupsPage ---

func TestRemoteStorage_ListGroupsPage_Error_S36(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "BAD_REQUEST", "invalid parameters"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.ListGroupsPage(context.Background(), 0, 10)
	assert.Error(t, err)
}
