// remote_group_e_sharing_error_sweep_test.go — targeted coverage sweep for
// remote_sharing.go's transport-error (rs.client.X returns err != nil) and
// decode-error branches across UpdateShareRecord, DeleteShareRecord,
// ListSharesBySecret, ListSharesBySecretIDs, ListSharesByUser,
// ListSharesByOwner, ListSharesByGroup, and DeleteExpiredShareRecords, plus
// DeleteShareRecord's !resp.Success branch, none of which had a test — only
// their success paths did (see remote_sharing_test.go).
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

func TestRemoteStorage_UpdateShareRecord_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.UpdateShareRecord(context.Background(), &models.ShareRecord{ID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update share record")
}

func TestRemoteStorage_UpdateShareRecord_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateShareRecord(context.Background(), &models.ShareRecord{ID: 1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_DeleteShareRecord_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.DeleteShareRecord(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete share record")
}

// TestRemoteStorage_DeleteShareRecord_NotSuccess_S36 exercises the
// !resp.Success branch specifically: a 2xx round trip whose body says
// success:false. A non-2xx status does NOT reach this branch — makeRequest
// converts every 4xx/5xx into a non-nil transport error before resp is ever
// populated (see remote/client.go's own doc comment), so it would exercise
// the err != nil branch above instead.
func TestRemoteStorage_DeleteShareRecord_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiErr("INTERNAL_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteShareRecord(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete share record failed")
}

func TestRemoteStorage_ListSharesBySecret_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSharesBySecret(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares by secret")
}

func TestRemoteStorage_ListSharesBySecret_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-array"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesBySecret(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRemoteStorage_ListSharesBySecretIDs_PropagatesError_S36 exercises the
// "list shares by secret %d: %w" wrap-and-return that fails the WHOLE batch
// as soon as one underlying ListSharesBySecret call errors (by design — see
// the method's own doc comment on why partial/degrade-to-empty is wrong
// here).
func TestRemoteStorage_ListSharesBySecretIDs_PropagatesError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSharesBySecretIDs(context.Background(), []uint{1})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list shares by secret 1")
}

func TestRemoteStorage_ListSharesByUser_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSharesByUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares by user")
}

func TestRemoteStorage_ListSharesByUser_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ListSharesByOwner_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSharesByOwner(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares by owner")
}

func TestRemoteStorage_ListSharesByOwner_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByOwner(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ListSharesByGroup_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListSharesByGroup(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list shares by group")
}

func TestRemoteStorage_ListSharesByGroup_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-array"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSharesByGroup(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_DeleteExpiredShareRecords_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.DeleteExpiredShareRecords(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to purge expired share records")
}

func TestRemoteStorage_DeleteExpiredShareRecords_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.DeleteExpiredShareRecords(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}
