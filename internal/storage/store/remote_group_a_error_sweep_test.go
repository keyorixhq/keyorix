// remote_group_a_error_sweep_test.go — targeted coverage sweep for RemoteStorage
// RPC-client thin proxies in remote_access_activity.go,
// remote_access_review_campaigns.go, remote_audit.go, and remote_auth.go.
//
// Every method here follows the same three-branch shape: a transport-error
// branch (rs.client.X returns err != nil — exercised with errHandler, which
// writes a non-2xx status the HTTP client converts into a network-level
// error before resp.Success is ever inspected), a !resp.Success branch
// (exercised with apiNotOK, HTTP 200 + success:false), and — for methods that
// decode resp.Data into a typed struct — a JSON-decode-error branch
// (exercised with apiOK wrapping a JSON string, which cannot unmarshal into
// the target struct/slice type).
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

// ============================================================================
// remote_access_activity.go
// ============================================================================

func TestRemoteStorage_LastUserSecretActivity_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "not found"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.LastUserSecretActivity(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret activity")
}

func TestRemoteStorage_LastUserSecretActivity_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.LastUserSecretActivity(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRemoteStorage_LastUserSecretActivity_SkipsUnparseableUserID exercises
// decodeAccessActivityResponse's per-key strconv.ParseUint failure branch: a
// map key that isn't a valid uint is silently skipped rather than aborting
// the whole decode.
func TestRemoteStorage_LastUserSecretActivity_SkipsUnparseableUserID_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"activity": map[string]interface{}{
				"5":          time.Now().UTC().Format(time.RFC3339),
				"not-a-uint": time.Now().UTC().Format(time.RFC3339),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.LastUserSecretActivity(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	_, ok := result[5]
	assert.True(t, ok)
}

// ============================================================================
// remote_access_review_campaigns.go
// ============================================================================

func TestRemoteStorage_CreateAccessReviewCampaign_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create access-review campaign")
}

func TestRemoteStorage_GetAccessReviewCampaign_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "missing"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get access-review campaign")
}

func TestRemoteStorage_ListAccessReviewCampaigns_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewCampaigns(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list access-review campaigns")
}

func TestRemoteStorage_ListAccessReviewCampaigns_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewCampaigns(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list access-review campaigns failed")
}

func TestRemoteStorage_ListAccessReviewCampaigns_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewCampaigns(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetOpenAccessReviewCampaign_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetOpenAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get open access-review campaign")
}

func TestRemoteStorage_GetOpenAccessReviewCampaign_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "open lookup failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetOpenAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get open access-review campaign failed")
}

func TestRemoteStorage_GetOpenAccessReviewCampaign_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetOpenAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetLatestClosedAccessReviewCampaign_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get latest-closed access-review campaign")
}

func TestRemoteStorage_GetLatestClosedAccessReviewCampaign_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "closed lookup failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get latest-closed access-review campaign failed")
}

func TestRemoteStorage_GetLatestClosedAccessReviewCampaign_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetLatestClosedAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_CreateAccessReviewItems_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateAccessReviewItems(context.Background(), []*models.AccessReviewItem{
		{CampaignID: 1, PrincipalType: "user", PrincipalID: 3, Source: "role", AccessLevel: "read", EnvironmentID: 1, Decision: "pending"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create access-review items")
}

func TestRemoteStorage_CreateAccessReviewItems_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "create items failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateAccessReviewItems(context.Background(), []*models.AccessReviewItem{
		{CampaignID: 1, PrincipalType: "user", PrincipalID: 3, Source: "role", AccessLevel: "read", EnvironmentID: 1, Decision: "pending"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create access-review items failed")
}

func TestRemoteStorage_ListAccessReviewItems_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewItems(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list access-review items")
}

func TestRemoteStorage_CountPendingAccessReviewItems_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountPendingAccessReviewItems(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count pending access-review items")
}

func TestRemoteStorage_GetAccessReviewItem_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusNotFound, "NOT_FOUND", "missing"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewItem(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get access-review item")
}

func TestRemoteStorage_UpdateAccessReviewItem_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateAccessReviewItem(context.Background(), &models.AccessReviewItem{ID: 1, CampaignID: 1, Decision: "attested"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update access-review item")
}

// ============================================================================
// remote_audit.go
// ============================================================================

func TestRemoteStorage_LogAuditEvent_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.LogAuditEvent(context.Background(), &models.AuditEvent{EventType: "test.event"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to log audit event")
}

func TestRemoteStorage_GetAuditLogs_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.GetAuditLogs(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get audit logs")
}

func TestRemoteStorage_GetAuditLogs_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.GetAuditLogs(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_GetRBACAuditLogs_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.GetRBACAuditLogs(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get RBAC audit logs")
}

func TestRemoteStorage_GetRBACAuditLogs_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, _, err = rs.GetRBACAuditLogs(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// ============================================================================
// remote_auth.go
// ============================================================================

func TestRemoteStorage_GetSession_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSession(context.Background(), "tok")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get session")
}

func TestRemoteStorage_GetSession_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-a-session"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSession(context.Background(), "tok")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_DeleteSession_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSession(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete session")
}

func TestRemoteStorage_DeleteSessionsForUserExcept_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSessionsForUserExcept(context.Background(), 1, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete sessions for user")
}

func TestRemoteStorage_DeleteSessionsForUserExcept_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "delete except failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteSessionsForUserExcept(context.Background(), 1, 2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete sessions for user failed")
}

func TestRemoteStorage_RevokeAllPersonalAccessTokensForUser_TransportError_S1(t *testing.T) {
	srv := httptest.NewServer(errHandler(http.StatusBadRequest, "INTERNAL", "boom"))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to revoke personal access tokens for user")
}

func TestRemoteStorage_RevokeAllPersonalAccessTokensForUser_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "revoke all failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoke personal access tokens for user failed")
}

func TestRemoteStorage_RevokeAllPersonalAccessTokensForUser_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.RevokeAllPersonalAccessTokensForUser(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestRemoteStorage_CreateSetupToken_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "create setup token failed upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateSetupToken(context.Background(), minimalSetupToken())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create setup token failed")
}

func TestRemoteStorage_GetSetupTokenByHash_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "setup token not found upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetSetupTokenByHash(context.Background(), "deadbeef")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get setup token failed")
}

func TestRemoteStorage_SupersedeActiveSetupTokens_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "supersede failed upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.SupersedeActiveSetupTokens(context.Background(), "account_setup", "user@example.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "supersede setup tokens failed")
}

func TestRemoteStorage_MarkSetupTokenExpired_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "expire failed upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.MarkSetupTokenExpired(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expire setup token failed")
}

func TestRemoteStorage_CountSetupTokensSince_NotSuccess_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "count failed upstream"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountSetupTokensSince(context.Background(), "account_setup", "user@example.com", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count setup tokens failed")
}

func TestRemoteStorage_CountSetupTokensSince_DecodeError_S1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(apiOK("not-an-object"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountSetupTokensSince(context.Background(), "account_setup", "user@example.com", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}
