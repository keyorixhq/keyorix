// remote_group_f_webauthn_error_sweep_test.go — closes the remaining coverage
// gaps in remote_webauthn.go: the transport-error branch, the response-decode-error
// branch (including decodeWebAuthnCredentialResponse/decodeWebAuthnSessionResponse
// and their propagation sites), and ConsumeWebAuthnSession's !resp.Success branch
// (its only existing failure test uses a 4xx status, which is consumed entirely by
// the transport-error branch, never reaching !resp.Success).
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

// GetWebAuthnCredentialByCredID decode error: exercises
// decodeWebAuthnCredentialResponse's json.Unmarshal error branch.
func TestRemoteStorage_GetWebAuthnCredentialByCredID_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetWebAuthnCredentialByCredID(context.Background(), []byte{0x01}, 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetWebAuthnCredentialByCredID_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetWebAuthnCredentialByCredID(context.Background(), []byte{0x01}, 7)
	assert.Error(t, err)
}

// CreateWebAuthnSession decode error: exercises BOTH
// decodeWebAuthnSessionResponse's json.Unmarshal error branch AND
// CreateWebAuthnSession's own `if err != nil { return err }` propagation of it.
func TestRemoteStorage_CreateWebAuthnSession_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateWebAuthnSession(context.Background(), &models.WebAuthnSession{
		UserID: 7, TokenHash: "h", Purpose: "register",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_CreateWebAuthnSession_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateWebAuthnSession(context.Background(), &models.WebAuthnSession{
		UserID: 7, TokenHash: "h", Purpose: "register",
	})
	assert.Error(t, err)
}

func TestRemoteStorage_ListWebAuthnCredentials_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
}

func TestRemoteStorage_ListWebAuthnCredentials_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_UpdateWebAuthnCredential_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.UpdateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{ID: 999})
	assert.Error(t, err)
}

func TestRemoteStorage_AdvanceWebAuthnCredentialCounter_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	advanced, err := rs.AdvanceWebAuthnCredentialCounter(context.Background(),
		[]byte{0xBE, 0xEF}, 7, []byte(`{}`), 10, time.Now())
	assert.Error(t, err)
	assert.False(t, advanced)
}

func TestRemoteStorage_AdvanceWebAuthnCredentialCounter_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	advanced, err := rs.AdvanceWebAuthnCredentialCounter(context.Background(),
		[]byte{0xBE, 0xEF}, 7, []byte(`{}`), 10, time.Now())
	assert.Error(t, err)
	assert.False(t, advanced)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_CountWebAuthnCredentials_TransportErr_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	n, err := rs.CountWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
	assert.Zero(t, n)
}

func TestRemoteStorage_CountWebAuthnCredentials_DecodeErr_G1(t *testing.T) {
	srv := httptest.NewServer(badDataHandler())
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	n, err := rs.CountWebAuthnCredentials(context.Background(), 7)
	assert.Error(t, err)
	assert.Zero(t, n)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ConsumeWebAuthnSession's !resp.Success branch is unreachable via a 4xx/5xx
// status (that's consumed entirely by the transport-error branch above it —
// see TestRemoteStorage_ConsumeWebAuthnSession_Failure in remote_webauthn_test.go,
// which uses 422 and only ever exercises the transport-error branch). Only an
// HTTP 200 + success:false body reaches it.
func TestRemoteStorage_ConsumeWebAuthnSession_SuccessFalse_G1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusOK, "NOT_FOUND", "session not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeWebAuthnSession(context.Background(), "some-hash", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired webauthn session")
}
