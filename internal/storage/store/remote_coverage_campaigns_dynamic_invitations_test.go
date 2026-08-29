// remote_coverage_campaigns_dynamic_invitations_test.go — error-path and
// malformed-JSON coverage for remote_access_review_campaigns.go,
// remote_dynamic.go, and remote_invitations.go.
//
// Every error path uses HTTP 200 + {"success":false,"error":{...}} because the
// remote client converts 4xx/5xx responses into a network-level error before
// the store's resp.Success check is ever reached (see remote/client.go:280).
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
// remote_access_review_campaigns.go — error paths
// ============================================================================

func TestRemoteCov_CreateAccessReviewCampaign_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create access-review campaign failed")
}

func TestRemoteCov_CreateAccessReviewCampaign_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad json}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{
		ProjectID: 1, Name: "Q1", State: "open", CreatedBy: 1, CreatedAt: time.Now(),
	})
	assert.Error(t, err)
}

func TestRemoteCov_GetAccessReviewCampaign_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "campaign not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewCampaign(context.Background(), 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get access-review campaign failed")
}

func TestRemoteCov_GetAccessReviewCampaign_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewCampaign(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteCov_CountPendingAccessReviewItems_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "count failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountPendingAccessReviewItems(context.Background(), 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count pending access-review items failed")
}

func TestRemoteCov_CountPendingAccessReviewItems_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountPendingAccessReviewItems(context.Background(), 10)
	assert.Error(t, err)
}

func TestRemoteCov_GetAccessReviewItem_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "item not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewItem(context.Background(), 55)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get access-review item failed")
}

func TestRemoteCov_GetAccessReviewItem_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessReviewItem(context.Background(), 55)
	assert.Error(t, err)
}

func TestRemoteCov_UpdateAccessReviewItem_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "item update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateAccessReviewItem(context.Background(), &models.AccessReviewItem{
		ID: 99, CampaignID: 10, Decision: "attested",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update access-review item failed")
}

func TestRemoteCov_UpdateAccessReviewItem_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateAccessReviewItem(context.Background(), &models.AccessReviewItem{
		ID: 99, CampaignID: 10, Decision: "attested",
	})
	assert.Error(t, err)
}

func TestRemoteCov_ListAccessReviewItems_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewItems(context.Background(), 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list access-review items failed")
}

func TestRemoteCov_ListAccessReviewItems_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessReviewItems(context.Background(), 10)
	assert.Error(t, err)
}

// ============================================================================
// remote_dynamic.go — error paths
// ============================================================================
// CreateDynamicSecretConfig error-path tests deleted -- #1580 liveness sweep,
// the method is now a hard stub (no HTTP call is ever made, so a
// server-error/malformed-JSON response is no longer a real scenario).
// TestRemoteStorage_CreateDynamicSecretConfig_Unsupported (remote_dynamic_test.go)
// covers the stub directly.

func TestRemoteCov_CountDynamicSecretConfigsByClassification_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "count failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountDynamicSecretConfigsByClassification(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count dynamic-secret configs by classification failed")
}

func TestRemoteCov_CountDynamicSecretConfigsByClassification_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountDynamicSecretConfigsByClassification(context.Background())
	assert.Error(t, err)
}

func TestRemoteCov_GetDynamicSecretConfig_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "config not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretConfig(context.Background(), 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get dynamic-secret config failed")
}

func TestRemoteCov_GetDynamicSecretConfig_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretConfig(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteCov_GetDynamicSecretLease_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "lease not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretLease(context.Background(), "lease-xyz")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get dynamic-secret lease failed")
}

func TestRemoteCov_GetDynamicSecretLease_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetDynamicSecretLease(context.Background(), "lease-xyz")
	assert.Error(t, err)
}

func TestRemoteCov_CountActiveLeases_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "count failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountActiveLeases(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count active dynamic-secret leases failed")
}

func TestRemoteCov_CountActiveLeases_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CountActiveLeases(context.Background(), 1)
	assert.Error(t, err)
}

// ============================================================================
// remote_invitations.go — error paths
// ============================================================================

func TestRemoteCov_CreateProjectInvitation_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("CONFLICT", "invitation already exists"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ProjectID: 10, Email: "bob@example.com", Role: "viewer",
		State: "pending", InvitedBy: 5,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create invitation failed")
}

func TestRemoteCov_CreateProjectInvitation_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ProjectID: 10, Email: "bob@example.com", Role: "viewer",
		State: "pending", InvitedBy: 5,
	})
	assert.Error(t, err)
}

func TestRemoteCov_GetProjectInvitation_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "invitation not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProjectInvitation(context.Background(), 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get invitation failed")
}

func TestRemoteCov_GetProjectInvitation_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetProjectInvitation(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteCov_UpdateProjectInvitation_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("CONFLICT", "already accepted"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ID: 1, State: "accepted",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update invitation failed")
}

func TestRemoteCov_UpdateProjectInvitation_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateProjectInvitation(context.Background(), &models.ProjectInvitation{
		ID: 1, State: "accepted",
	})
	assert.Error(t, err)
}

func TestRemoteCov_CreateAccessRequest_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "create access request failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: 10, UserID: 3, SuggestedRole: "editor", State: "pending",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create access request failed")
}

func TestRemoteCov_CreateAccessRequest_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: 10, UserID: 3, SuggestedRole: "editor", State: "pending",
	})
	assert.Error(t, err)
}

func TestRemoteCov_GetAccessRequest_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("NOT_FOUND", "request not found"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessRequest(context.Background(), 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get access request failed")
}

func TestRemoteCov_GetAccessRequest_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.GetAccessRequest(context.Background(), 50)
	assert.Error(t, err)
}

func TestRemoteCov_UpdateAccessRequest_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("CONFLICT", "update failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateAccessRequest(context.Background(), &models.AccessRequest{
		ID: 50, State: "approved",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update access request failed")
}

func TestRemoteCov_UpdateAccessRequest_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.UpdateAccessRequest(context.Background(), &models.AccessRequest{
		ID: 50, State: "approved",
	})
	assert.Error(t, err)
}

func TestRemoteCov_CreateAccessRequestApproval_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "approval create failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.CreateAccessRequestApproval(context.Background(), &models.AccessRequestApproval{
		RequestID: 50, ApproverID: 2,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "create access request approval failed")
}

func TestRemoteCov_ListAccessRequestApprovals_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiNotOK("INTERNAL", "list approvals failed"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessRequestApprovals(context.Background(), 50)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list access request approvals failed")
}

func TestRemoteCov_ListAccessRequestApprovals_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK("{bad}"))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = rs.ListAccessRequestApprovals(context.Background(), 50)
	assert.Error(t, err)
}
