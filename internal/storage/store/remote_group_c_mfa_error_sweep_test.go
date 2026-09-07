// remote_group_c_mfa_error_sweep_test.go — remaining uncovered branches in
// remote_memberships.go and remote_mfa.go: the transport-error (err != nil)
// branch for methods store_s28/remote_coverage_mfa_rbac_secrets_test.go only
// exercised with a 4xx/5xx status (which itself IS the transport-error
// branch, per #501 — see remote_group_c_machine_identities_error_sweep_test.go's
// package doc), the !resp.Success branch for methods that had no error test
// at all, and a couple of decode-error / success-only branches that were
// never reached.
package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- remote_memberships.go ---

func TestRemoteStorage_CreateProjectMembership_DuplicateActive_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"error":"DUPLICATE_ACTIVE_MEMBERSHIP","message":"already active"}`))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateProjectMembership(context.Background(), &models.ProjectMembership{ProjectID: 1, UserID: 1})
	assert.Error(t, err)
	assert.ErrorIs(t, err, corestorage.ErrDuplicateActiveMembership)
}

func TestRemoteStorage_GetProjectMembership_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProjectMembership(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListProjectMemberships_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectMemberships(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListProjectMemberships_BadJSON_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("bad"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListProjectMemberships(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetActiveProjectMembership_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveProjectMembership(context.Background(), 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_GetActiveProjectMembership_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveProjectMembership(context.Background(), 1, 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ListStaleInvitedMemberships_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListStaleInvitedMemberships(context.Background(), time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_ListUserProjectMemberships_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListUserProjectMemberships(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_CountProjectMembershipsByUsers_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountProjectMembershipsByUsers(context.Background(), []uint{1})
	assert.Error(t, err)
}

func TestRemoteStorage_CountProjectMembershipsByUsers_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountProjectMembershipsByUsers(context.Background(), []uint{1})
	assert.Error(t, err)
}

func TestRemoteStorage_CountProjectMembershipsByUsers_BadJSON_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK([]int{1, 2, 3}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountProjectMembershipsByUsers(context.Background(), []uint{1})
	assert.Error(t, err)
}

func TestRemoteStorage_CountProjectMembershipsByUsers_NullData_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.CountProjectMembershipsByUsers(context.Background(), []uint{1})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

// --- remote_mfa.go ---

func TestRemoteStorage_GetMFASecret_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetMFASecret(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_MarkTOTPStepUsed_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.MarkTOTPStepUsed(context.Background(), 1, 12345)
	assert.Error(t, err)
}

func TestRemoteStorage_MarkTOTPStepUsed_Success_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{"fresh": true}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	fresh, err := rs.MarkTOTPStepUsed(context.Background(), 1, 12345)
	require.NoError(t, err)
	assert.True(t, fresh)
}

func TestRemoteStorage_CountUnusedMFARecoveryCodes_TransportError_GroupC(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountUnusedMFARecoveryCodes(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_ConsumeMFAChallenge_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ConsumeMFAChallenge(context.Background(), "hash", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_GetActiveMFAChallenge_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveMFAChallenge(context.Background(), "hash", time.Now())
	assert.Error(t, err)
}

func TestRemoteStorage_IssueMFAChallenge_SuccessFalse_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL_ERROR", "failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.IssueMFAChallenge(context.Background(), 1)
	assert.Error(t, err)
}

// --- remote_mfa_stepup_grant.go ---

// TestRemoteStorage_GetActiveMFAStepUpGrant_DecodeError_GroupC targets
// decodeMFAStepUpGrantResponse's own parse-error branch specifically: the
// data field must be syntactically valid JSON (so the outer envelope parses
// and resp.Success is genuinely true) but the wrong shape for
// mfaStepUpGrantWire, unlike a malformed-envelope body (e.g. embedding
// literal `{bad json}` in "data"), which never reaches this function at all
// -- the outer json.Unmarshal in remote/client.go's makeRequest fails first
// and synthesizes a generic Success:false response instead.
func TestRemoteStorage_GetActiveMFAStepUpGrant_DecodeError_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK([]int{1, 2, 3}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetActiveMFAStepUpGrant(context.Background(), 1, models.MFAStepUpPurposeRestrictedSecretRead, time.Now().UTC())
	assert.Error(t, err)
}

// TestRemoteStorage_PruneMFAStepUpGrants_DecodeError_GroupC: same reasoning
// as above for PruneMFAStepUpGrants' own json.Unmarshal(resp.Data, &result)
// branch -- valid outer JSON, wrong-shaped data.
func TestRemoteStorage_PruneMFAStepUpGrants_DecodeError_GroupC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK([]int{1, 2, 3}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.PruneMFAStepUpGrants(context.Background(), time.Now().UTC())
	assert.Error(t, err)
}
