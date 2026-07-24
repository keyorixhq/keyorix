// remote_scheduler_lock_coverage_test.go — error-path coverage for the
// remote_scheduler_lock.go functions that have success tests in
// server/http/remote_storage_scheduler_lock_test.go but whose internal error
// branches (resp.Success==false, json.Unmarshal failure) are not reached by
// those integration tests because the real server only ever returns well-formed
// success responses.
//
// Uses the same apiNotOK pattern as remote_coverage_test.go — HTTP 200 with
// success:false is the only wire shape that exercises the !resp.Success branches
// in TryAcquireSchedulerLock and ReleaseSchedulerLock; 4xx/5xx responses are
// consumed by the HTTP client layer before the caller sees resp.
package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── TryAcquireSchedulerLock ──────────────────────────────────────────────────

// TestRemoteSched_TryAcquire_SuccessFalse exercises the !resp.Success branch.
func TestRemoteSched_TryAcquire_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiNotOK("LOCK_ERROR", "lock not available"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.TryAcquireSchedulerLock(context.Background(), 1, "holder-x", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire scheduler lock failed")
}

// TestRemoteSched_TryAcquire_MalformedData exercises the json.Unmarshal error
// branch: success:true but data is not a valid schedulerLockAcquireResponse.
func TestRemoteSched_TryAcquire_MalformedData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{
			"success": true,
			// "acquired" is a bool in the real struct; a nested object breaks Unmarshal.
			"data": map[string]any{"acquired": map[string]any{"nested": true}},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.TryAcquireSchedulerLock(context.Background(), 1, "holder-x", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRemoteSched_TryAcquire_HappyFalse verifies the acquired==false path: a
// well-formed response with acquired:false means another holder owns the lock.
func TestRemoteSched_TryAcquire_HappyFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{
			"success": true,
			"data":    map[string]any{"acquired": false},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 1, "holder-x", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired, "acquired:false in the wire response must propagate as false")
}

// TestRemoteSched_TryAcquire_NetworkError exercises the client.Post error path.
func TestRemoteSched_TryAcquire_NetworkError(t *testing.T) {
	// Use a server that immediately closes, then close it to force a network error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close() // Close immediately so the request fails

	rs, err := store.NewRemoteStorage(testConfig(srvURL))
	require.NoError(t, err)

	_, err = rs.TryAcquireSchedulerLock(context.Background(), 1, "holder-x", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire scheduler lock")
}

// ─── ReleaseSchedulerLock ────────────────────────────────────────────────────

// TestRemoteSched_Release_SuccessFalse exercises the !resp.Success branch.
func TestRemoteSched_Release_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(apiNotOK("RELEASE_ERROR", "release failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.ReleaseSchedulerLock(context.Background(), 1, "holder-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "release scheduler lock failed")
}

// TestRemoteSched_Release_NetworkError exercises the client.Post error path.
func TestRemoteSched_Release_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srvURL))
	require.NoError(t, err)

	err = rs.ReleaseSchedulerLock(context.Background(), 1, "holder-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to release scheduler lock")
}
