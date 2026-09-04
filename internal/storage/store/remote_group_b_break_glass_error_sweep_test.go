// remote_group_b_break_glass_error_sweep_test.go — closes the remaining
// uncovered branches in remote_break_glass.go: the transport-error branch of
// GetBreakGlassActivation, and the transport-error/!success/malformed-JSON
// branches of ListBreakGlassActivations and RevokeBreakGlassActivation that
// TestRemoteStorage_RevokeBreakGlassActivation_NotActive (remote_misc_test.go)
// and TestRemoteCov_GetBreakGlassActivation_NotSuccess
// (remote_coverage_policies_memberships_auth_test.go) don't reach: those exist
// but cover the httpErr.ErrorType==breakGlassNotActiveCode branch and
// GetBreakGlassActivation's !success branch respectively, not these.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteStorage_GetBreakGlassActivation_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetBreakGlassActivation(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get break-glass activation")
}

func TestRemoteStorage_ListBreakGlassActivations_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListBreakGlassActivations(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list break-glass activations")
}

func TestRemoteStorage_ListBreakGlassActivations_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListBreakGlassActivations(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list break-glass activations failed")
}

func TestRemoteStorage_ListBreakGlassActivations_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListBreakGlassActivations(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_RevokeBreakGlassActivation_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.RevokeBreakGlassActivation(context.Background(), 9, 1, 0, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke break-glass activation")
}

func TestRemoteStorage_RevokeBreakGlassActivation_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "revoke failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RevokeBreakGlassActivation(context.Background(), 9, 1, 0, time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke break-glass activation failed")
}
