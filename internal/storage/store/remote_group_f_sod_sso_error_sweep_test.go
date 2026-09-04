// remote_group_f_sod_sso_error_sweep_test.go — closes the remaining coverage
// gaps in remote_sod.go and remote_sso.go: the transport-error (err != nil
// from rs.client.X) branch and the response-decode-error (json.Unmarshal on
// resp.Data) branch for every method in both files. The !resp.Success
// branches for these same methods are already covered by remote_coverage_test.go
// (apiNotOK, HTTP 200 + success:false) — this file deliberately does not
// duplicate those.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// badDataHandler returns an HTTP 200 envelope with success:true but a `data`
// value that cannot unmarshal into the target wire struct (a JSON string
// instead of an object), exercising the json.Unmarshal error branch without
// ever touching the transport-error or !resp.Success branches.
func badDataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":"not-an-object"}`))
	}
}

// --- remote_sod.go ---

func TestRemoteStorage_CreateSoDPolicy_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSoDPolicy(context.Background(), &models.SoDPolicy{Name: "x"})
	assert.Error(t, err)
}

func TestRemoteStorage_CreateSoDPolicy_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSoDPolicy(context.Background(), &models.SoDPolicy{Name: "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetSoDPolicy_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSoDPolicy(context.Background(), 5)
	assert.Error(t, err)
}

func TestRemoteStorage_GetSoDPolicy_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSoDPolicy(context.Background(), 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ListSoDPolicies_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSoDPolicies(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_ListSoDPolicies_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListSoDPolicies(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_DeleteSoDPolicy_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSoDPolicy(context.Background(), 999)
	assert.Error(t, err)
}

// --- remote_sso.go ---

func TestRemoteStorage_CreateSSOLoginState_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateSSOLoginState(context.Background(), &models.SSOLoginState{State: "s1", Provider: "oidc"})
	assert.Error(t, err)
}

func TestRemoteStorage_CreateSSOLoginState_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateSSOLoginState(context.Background(), &models.SSOLoginState{State: "s1", Provider: "oidc"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_ConsumeSSOLoginState_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeSSOLoginState(context.Background(), "no-such-state")
	assert.Error(t, err)
}

func TestRemoteStorage_ConsumeSSOLoginState_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeSSOLoginState(context.Background(), "some-state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}
