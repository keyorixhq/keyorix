// remote_group_c_machine_identities_error_sweep_test.go — transport-error
// (err != nil from rs.client.X) and decode-error sweep for
// remote_machine_identities.go. store_s28_test.go already covers every
// !resp.Success branch (HTTP 200 + success:false body) for this file; per
// #501 any 4xx/5xx status collapses to a non-nil error at the client.Get/
// Post/Put/Delete call site itself (see remote/client.go's makeRequest), so
// errHandler's non-2xx status here specifically exercises the transport-
// error branch, not !resp.Success.
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

func TestRemoteStorage_CreateMachineIdentity_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateMachineIdentity(context.Background(), &models.MachineIdentity{Name: "ci"})
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineIdentity_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineIdentity(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_LockMachineIdentityForUpdate_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.LockMachineIdentityForUpdate(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_TransitionMachineIdentityState_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.TransitionMachineIdentityState(context.Background(), &models.MachineIdentity{ID: 1}, "pending")
	assert.Error(t, err)
}

func TestRemoteStorage_ListMachineIdentities_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListMachineIdentities(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListAllMachineIdentities_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAllMachineIdentities(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_CountMachineIdentitiesByClassification_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountMachineIdentitiesByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_CreateMachineIdentityCredential_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{MachineIdentityID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineIdentityCredentialByHash_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineIdentityCredentialByHash(context.Background(), "abc123")
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineIdentityCredentialByHash_BadJSON_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("not-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineIdentityCredentialByHash(context.Background(), "abc123")
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineIdentityCredentialByID_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineIdentityCredentialByID(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListMachineIdentityCredentials_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListMachineIdentityCredentials(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListActiveMachineIdentityCredentials_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListActiveMachineIdentityCredentials(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_UpdateMachineIdentityCredential_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{ID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_CountMachineIdentityCredentialsByClassification_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountMachineIdentityCredentialsByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteStorage_RevokeMachineIdentityCredential_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RevokeMachineIdentityCredential(context.Background(), 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_TouchMachineIdentityCredential_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.TouchMachineIdentityCredential(context.Background(), 1, time.Now(), time.Hour)
	assert.Error(t, err)
}

func TestRemoteStorage_AssignMachineRole_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignMachineRole(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_RemoveMachineRole_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveMachineRole(context.Background(), 1, 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineRoleIDsAt_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineRoleIDsAt(context.Background(), 1, coreScope())
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineRoles_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineRoles(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_CreateOIDCBinding_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateOIDCBinding(context.Background(), &models.MachineIdentityOIDCBinding{MachineIdentityID: 1})
	assert.Error(t, err)
}

func TestRemoteStorage_GetMachineByOIDCSubject_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMachineByOIDCSubject(context.Background(), "https://issuer", "sub123")
	assert.Error(t, err)
}

func TestRemoteStorage_ListOIDCBindings_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListOIDCBindings(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetOIDCBindingByID_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetOIDCBindingByID(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetOIDCBindingByID_BadJSON_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("not-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetOIDCBindingByID(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_DeleteOIDCBinding_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteOIDCBinding(context.Background(), 1)
	assert.Error(t, err)
}
