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

// campaignWireData returns a minimal wire representation of an access-review campaign.
func campaignWireData(id uint, name, state string) map[string]interface{} {
	return map[string]interface{}{
		"id":         id,
		"project_id": uint(1),
		"name":       name,
		"state":      state,
		"created_by": uint(7),
		"created_at": time.Now().UTC().Format(time.RFC3339),
	}
}

// itemWireData returns a minimal wire representation of an access-review item.
func itemWireData(id, campaignID uint) map[string]interface{} {
	return map[string]interface{}{
		"id":             id,
		"campaign_id":    campaignID,
		"principal_type": "user",
		"principal_id":   uint(3),
		"principal_name": "alice",
		"source":         "role",
		"access_level":   "read",
		"environment_id": uint(1),
		"decision":       "pending",
	}
}

// --- CreateAccessReviewCampaign ---

func TestRemoteStorage_CreateAccessReviewCampaign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns", r.URL.Path)
		_, _ = w.Write(apiOK(campaignWireData(42, "Q1 review", "open")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	c := &models.AccessReviewCampaign{
		ProjectID: 1,
		Name:      "Q1 review",
		State:     "open",
		CreatedBy: 7,
		CreatedAt: time.Now(),
	}
	result, err := rs.CreateAccessReviewCampaign(context.Background(), c)
	require.NoError(t, err)
	assert.Equal(t, uint(42), result.ID)
	assert.Equal(t, "Q1 review", result.Name)
	assert.Equal(t, "open", result.State)
}

// --- GetAccessReviewCampaign ---

func TestRemoteStorage_GetAccessReviewCampaign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/42", r.URL.Path)
		_, _ = w.Write(apiOK(campaignWireData(42, "Q1 review", "open")))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetAccessReviewCampaign(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, uint(42), result.ID)
	assert.Equal(t, "Q1 review", result.Name)
}

// --- ListAccessReviewCampaigns ---

func TestRemoteStorage_ListAccessReviewCampaigns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"campaigns": []map[string]interface{}{
				campaignWireData(10, "Campaign A", "closed"),
				campaignWireData(11, "Campaign B", "open"),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListAccessReviewCampaigns(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, uint(10), results[0].ID)
	assert.Equal(t, "Campaign A", results[0].Name)
}

// --- GetOpenAccessReviewCampaign ---

func TestRemoteStorage_GetOpenAccessReviewCampaign_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/open", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"campaign": campaignWireData(77, "Open review", "open"),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetOpenAccessReviewCampaign(context.Background(), 5)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint(77), result.ID)
	assert.Equal(t, "open", result.State)
}

func TestRemoteStorage_GetOpenAccessReviewCampaign_None(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"campaign": nil,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetOpenAccessReviewCampaign(context.Background(), 5)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// --- GetLatestClosedAccessReviewCampaign ---

func TestRemoteStorage_GetLatestClosedAccessReviewCampaign_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/latest-closed", r.URL.Path)
		assert.Equal(t, "3", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"campaign": campaignWireData(55, "Old review", "closed"),
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetLatestClosedAccessReviewCampaign(context.Background(), 3)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint(55), result.ID)
	assert.Equal(t, "closed", result.State)
}

func TestRemoteStorage_GetLatestClosedAccessReviewCampaign_None(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"campaign": nil,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetLatestClosedAccessReviewCampaign(context.Background(), 3)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// --- CreateAccessReviewItems ---

func TestRemoteStorage_CreateAccessReviewItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/10/items", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	items := []*models.AccessReviewItem{
		{
			CampaignID:    10,
			PrincipalType: "user",
			PrincipalID:   3,
			PrincipalName: "alice",
			Source:        "role",
			AccessLevel:   "read",
			EnvironmentID: 1,
			Decision:      "pending",
		},
	}
	err = rs.CreateAccessReviewItems(context.Background(), items)
	require.NoError(t, err)
}

func TestRemoteStorage_CreateAccessReviewItems_Empty(t *testing.T) {
	// Empty slice is a no-op — no HTTP call is made.
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.CreateAccessReviewItems(context.Background(), nil)
	require.NoError(t, err)
}

// --- ListAccessReviewItems ---

func TestRemoteStorage_ListAccessReviewItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/10/items", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"items": []map[string]interface{}{
				itemWireData(1, 10),
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	results, err := rs.ListAccessReviewItems(context.Background(), 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, uint(1), results[0].ID)
	assert.Equal(t, uint(10), results[0].CampaignID)
	assert.Equal(t, "user", results[0].PrincipalType)
}

// --- CountPendingAccessReviewItems ---

func TestRemoteStorage_CountPendingAccessReviewItems(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/10/items/pending-count", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"count": 5,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.CountPendingAccessReviewItems(context.Background(), 10)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

// --- GetAccessReviewItem ---

func TestRemoteStorage_GetAccessReviewItem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/items/99", r.URL.Path)
		_, _ = w.Write(apiOK(itemWireData(99, 10)))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	result, err := rs.GetAccessReviewItem(context.Background(), 99)
	require.NoError(t, err)
	assert.Equal(t, uint(99), result.ID)
	assert.Equal(t, uint(10), result.CampaignID)
}

// --- UpdateAccessReviewItem ---

func TestRemoteStorage_UpdateAccessReviewItem_Updated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/system/access-review-campaigns/items/99", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"updated": true,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	item := &models.AccessReviewItem{
		ID:            99,
		CampaignID:    10,
		PrincipalType: "user",
		PrincipalID:   3,
		PrincipalName: "alice",
		Source:        "role",
		AccessLevel:   "read",
		EnvironmentID: 1,
		Decision:      "attested",
		DecidedBy:     7,
	}
	updated, err := rs.UpdateAccessReviewItem(context.Background(), item)
	require.NoError(t, err)
	assert.True(t, updated)
}

func TestRemoteStorage_UpdateAccessReviewItem_NotUpdated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(apiOK(map[string]interface{}{
			"updated": false,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	item := &models.AccessReviewItem{
		ID:            99,
		CampaignID:    10,
		PrincipalType: "user",
		Decision:      "attested",
	}
	updated, err := rs.UpdateAccessReviewItem(context.Background(), item)
	require.NoError(t, err)
	assert.False(t, updated)
}
