package share

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunListRemote_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"shares":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc, 5))
}

func TestRunListRemote_WithExpiry(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"shares":[
			{"ID":2,"SecretID":5,"OwnerID":1,"RecipientID":3,"IsGroup":false,"Permission":"write","CreatedAt":"2026-06-01T10:00:00Z","ExpiresAt":"2027-06-01T10:00:00Z"}
		]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runListRemote(rc, 5))
	assert.Equal(t, "/api/v1/secrets/5/shares", gotPath)
}

func TestRunSharedSecretsRemote_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runSharedSecretsRemote(rc))
}

func TestRunList_Remote_RoutesThroughRemoteClient(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"shares":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID := listSecretID
	defer func() { listSecretID = origID }()
	listSecretID = 9

	require.NoError(t, runList(nil, nil))
	assert.Equal(t, "/api/v1/secrets/9/shares", gotPath)
}

func TestRunSharedSecrets_Remote_RoutesThroughRemoteClient(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":1,"Name":"s","Type":"password","ProjectID":2,"EnvironmentID":1,"CreatedBy":"admin","CreatedAt":"2026-01-01T00:00:00Z"}
		]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	require.NoError(t, runSharedSecrets(nil, nil))
	assert.Equal(t, "/api/v1/shared-secrets", gotPath)
}

func TestRunGroupSharesRemote_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"shares":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runGroupSharesRemote(rc, 7))
}

func TestRunGroupSharesRemote_WithResults(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"shares":[
			{"ID":1,"SecretID":5,"OwnerID":1,"RecipientID":7,"IsGroup":true,"Permission":"read","CreatedAt":"2026-06-01T10:00:00Z"}
		]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	require.NoError(t, runGroupSharesRemote(rc, 7))
	assert.Equal(t, "/api/v1/groups/7/shares", gotPath)
}

// TestRunGroupShares_Remote_RoutesThroughRemoteClient is the regression test
// for #G66: previously runGroupShares had no remote-client branch at all and
// always read local embedded storage, silently ignoring a connected server.
func TestRunGroupShares_Remote_RoutesThroughRemoteClient(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"shares":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origID := groupSharesGroupID
	defer func() { groupSharesGroupID = origID }()
	groupSharesGroupID = 11

	require.NoError(t, runGroupShares(nil, nil))
	assert.Equal(t, "/api/v1/groups/11/shares", gotPath)
}

func TestRunUpdate_PermissionValidation(t *testing.T) {
	origPerm, origID := updatePermission, updateShareID
	defer func() { updatePermission = origPerm; updateShareID = origID }()
	updatePermission = "admin"
	updateShareID = 1

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid permission")
}

func TestRunUpdate_ClearExpiryWithExpires(t *testing.T) {
	origPerm, origID, origClear, origExpires := updatePermission, updateShareID, updateClearExpiry, updateExpires
	defer func() {
		updatePermission = origPerm
		updateShareID = origID
		updateClearExpiry = origClear
		updateExpires = origExpires
	}()
	updatePermission = "read"
	updateShareID = 1
	updateClearExpiry = true
	updateExpires = "2026-12-01T00:00:00Z"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--clear-expiry cannot be combined")
}

func TestRunUpdate_ClearExpiryWithTTL(t *testing.T) {
	origPerm, origID, origClear, origTTL := updatePermission, updateShareID, updateClearExpiry, updateTTL
	defer func() {
		updatePermission = origPerm
		updateShareID = origID
		updateClearExpiry = origClear
		updateTTL = origTTL
	}()
	updatePermission = "write"
	updateShareID = 1
	updateClearExpiry = true
	updateTTL = "24h"

	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--clear-expiry cannot be combined")
}
