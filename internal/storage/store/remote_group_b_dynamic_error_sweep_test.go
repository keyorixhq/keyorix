// remote_group_b_dynamic_error_sweep_test.go — closes the remaining uncovered
// branches in remote_dynamic.go: the transport-error branch on every method
// (remote_dynamic_test.go/remote_coverage_campaigns_dynamic_invitations_test.go
// only exercise the success and !resp.Success branches, not transport error),
// plus the !success/malformed-JSON branches of ListDynamicSecretConfigs,
// ListDynamicSecretLeases, and ListExpiredActiveLeases, which had no error-path
// tests at all before this file.
//
// GetDynamicSecretConfig's own validateEncryptedAdminDSNWireField error branch
// (remote_dynamic.go:229, `return nil, err`) is deliberately NOT covered here:
// validateEncryptedAdminDSNWireField is a documented permanent no-op ("_ =
// dsnEnc; return nil") -- it can never return a non-nil error through any
// caller-visible input, so that branch is dead code, not a reachable gap.
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

func TestRemoteStorage_GetDynamicSecretConfig_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretConfig(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get dynamic-secret config")
}

func TestRemoteStorage_ListDynamicSecretConfigs_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretConfigs(context.Background(), 1, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list dynamic-secret configs")
}

func TestRemoteStorage_ListDynamicSecretConfigs_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretConfigs(context.Background(), 1, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list dynamic-secret configs failed")
}

func TestRemoteStorage_ListDynamicSecretConfigs_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretConfigs(context.Background(), 1, 0)
	assert.Error(t, err)
}

func TestRemoteStorage_CountDynamicSecretConfigsByClassification_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountDynamicSecretConfigsByClassification(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count dynamic-secret configs by classification")
}

func TestRemoteStorage_GetDynamicSecretLease_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretLease(context.Background(), "lease-xyz")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get dynamic-secret lease")
}

func TestRemoteStorage_ListDynamicSecretLeases_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretLeases(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list dynamic-secret leases")
}

func TestRemoteStorage_ListDynamicSecretLeases_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretLeases(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list dynamic-secret leases failed")
}

func TestRemoteStorage_ListDynamicSecretLeases_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListDynamicSecretLeases(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_CountActiveLeases_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CountActiveLeases(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count active dynamic-secret leases")
}

func TestRemoteStorage_ListExpiredActiveLeases_TransportError_S36(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.ListExpiredActiveLeases(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list expired dynamic-secret leases")
}

func TestRemoteStorage_ListExpiredActiveLeases_NotSuccess_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListExpiredActiveLeases(context.Background(), time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list expired dynamic-secret leases failed")
}

func TestRemoteStorage_ListExpiredActiveLeases_MalformedJSON_S36(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListExpiredActiveLeases(context.Background(), time.Now())
	assert.Error(t, err)
}
