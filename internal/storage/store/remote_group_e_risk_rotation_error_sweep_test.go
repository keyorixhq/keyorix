// remote_group_e_risk_rotation_error_sweep_test.go — targeted coverage sweep
// for remote_risk_exceptions.go and remote_rotation_policies.go: transport-error
// (rs.client.X returns err != nil) and JSON-decode-error branches that had no
// test, plus the ListRotationPolicies query-builder branch only reachable when
// BOTH projectID and environmentID are non-nil.
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

// --- remote_risk_exceptions.go ---

func TestRemoteStorage_CreateRiskException_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateRiskException(context.Background(), &models.RiskException{
		Title: "test", Category: "mfa", Justification: "needed", CreatedBy: 1,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create risk exception")
}

func TestRemoteStorage_GetRiskException_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetRiskException(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get risk exception")
}

func TestRemoteStorage_ListRiskExceptions_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListRiskExceptions(context.Background(), false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list risk exceptions")
}

// TestRemoteStorage_ListRiskExceptions_NotSuccess_S36 exercises the
// !resp.Success branch specifically: a 2xx round trip whose body says
// success:false. A non-2xx status (errHandler) does NOT reach this branch —
// makeRequest converts every 4xx/5xx into a non-nil transport error before
// resp is ever populated (see remote/client.go's own doc comment), so it
// would exercise the err != nil branch above instead.
func TestRemoteStorage_ListRiskExceptions_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiErr("INTERNAL_ERROR", "db down"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListRiskExceptions(context.Background(), false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list risk exceptions failed")
}

func TestRemoteStorage_ListRiskExceptions_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListRiskExceptions(context.Background(), false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// --- remote_rotation_policies.go ---

func TestRemoteStorage_CreateRotationPolicy_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateRotationPolicy(context.Background(), &models.RotationPolicy{Name: "daily", IntervalDays: 1, CreatedBy: "admin"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create rotation policy")
}

func TestRemoteStorage_CreateRotationPolicy_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateRotationPolicy(context.Background(), &models.RotationPolicy{Name: "daily", IntervalDays: 1, CreatedBy: "admin"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetRotationPolicy_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetRotationPolicy(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get rotation policy")
}

func TestRemoteStorage_GetRotationPolicy_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetRotationPolicy(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ListRotationPolicies_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	pid := uint(1)
	_, err = rs.ListRotationPolicies(context.Background(), &pid, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list rotation policies")
}

func TestRemoteStorage_ListRotationPolicies_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-array"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	pid := uint(1)
	_, err = rs.ListRotationPolicies(context.Background(), &pid, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRemoteStorage_ListRotationPolicies_BothParams_S36 exercises the
// appendParam closure's "&key=val" (else) branch, only reached when a SECOND
// query parameter is appended after the first — i.e. both projectID and
// environmentID are non-nil. Every other existing test passes at most one.
func TestRemoteStorage_ListRotationPolicies_BothParams_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/rotation-policies", r.URL.Path)
		assert.Equal(t, "10", r.URL.Query().Get("project_id"))
		assert.Equal(t, "20", r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK([]map[string]any{}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	pid := uint(10)
	eid := uint(20)
	policies, err := rs.ListRotationPolicies(context.Background(), &pid, &eid)
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestRemoteStorage_UpdateRotationPolicy_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.UpdateRotationPolicy(context.Background(), &models.RotationPolicy{ID: 1, Name: "daily", IntervalDays: 1, CreatedBy: "admin"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update rotation policy")
}

func TestRemoteStorage_UpdateRotationPolicy_BadJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateRotationPolicy(context.Background(), &models.RotationPolicy{ID: 1, Name: "daily", IntervalDays: 1, CreatedBy: "admin"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_DeleteRotationPolicy_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.DeleteRotationPolicy(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete rotation policy")
}
