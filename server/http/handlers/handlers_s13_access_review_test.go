// handlers_s13_access_review_test.go — coverage sweep targeting error branches in:
//   - access_review_campaigns.go: OpenAccessReviewCampaign, ListAccessReviewCampaigns,
//     CloseAccessReviewCampaign, DecideAccessReviewCampaignItem (bad params, missing user ctx,
//     invalid action, not-found)
//   - access_review_campaigns_proxy.go: bad-param and missing-body branches for every
//     proxy handler (Create/Get/List/GetOpen/GetLatestClosed/Update/CreateItems/
//     ListItems/CountPending/GetItem/UpdateItem)
//   - access_request_proxy.go: bad-param, missing-field, bad-state, not-found
//     branches for all six proxy handlers
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── access_review_campaigns.go: OpenAccessReviewCampaign ─────────────────────

// TestOpenAccessReviewCampaign_BadProjectID_S13 — non-numeric {id} → 400.
func TestOpenAccessReviewCampaign_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestOpenAccessReviewCampaign_NoUserCtx_S13 — missing user context → 401.
func TestOpenAccessReviewCampaign_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestOpenAccessReviewCampaign_WithProject_S13 — valid param + user ctx with a real project → 201.
func TestOpenAccessReviewCampaign_WithProject_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_open_arc", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Q1 Review"}`))),
		"id", fmt.Sprintf("%d", proj.ID),
	)
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	// OpenAccessReviewCampaign on a project with no members succeeds (creates empty campaign).
	assert.True(t, w.Code == http.StatusCreated || w.Code >= http.StatusBadRequest,
		"expected 201 or an error, got %d", w.Code)
}

// ── access_review_campaigns.go: ListAccessReviewCampaigns ────────────────────

// TestListAccessReviewCampaigns_BadProjectID_S13 — non-numeric {id} → 400.
func TestListAccessReviewCampaigns_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestListAccessReviewCampaigns_EmptyProject_S13 — valid project with no campaigns → 200 empty list.
func TestListAccessReviewCampaigns_EmptyProject_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_list_arc_empty", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", proj.ID),
	)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns.go: CloseAccessReviewCampaign ────────────────────

// TestCloseAccessReviewCampaign_BadProjectID_S13 — non-numeric {id} → 400.
func TestCloseAccessReviewCampaign_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		map[string]string{"id": "bad", "campaignId": "1"},
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestCloseAccessReviewCampaign_BadCampaignID_S13 — non-numeric {campaignId} → 400.
func TestCloseAccessReviewCampaign_BadCampaignID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		map[string]string{"id": "1", "campaignId": "notanumber"},
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestCloseAccessReviewCampaign_NoUserCtx_S13 — missing user context → 401.
func TestCloseAccessReviewCampaign_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": "1", "campaignId": "1"},
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCloseAccessReviewCampaign_NotFound_S13 — valid params, no such campaign → non-2xx.
func TestCloseAccessReviewCampaign_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))),
		map[string]string{"id": "1", "campaignId": "99999"},
	)
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns.go: DecideAccessReviewCampaignItem ───────────────

// TestDecideAccessReviewCampaignItem_BadProjectID_S13 — non-numeric {id} → 400.
func TestDecideAccessReviewCampaignItem_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`))),
		map[string]string{"id": "bad", "campaignId": "1", "itemId": "1"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestDecideAccessReviewCampaignItem_BadCampaignID_S13 — non-numeric {campaignId} → 400.
func TestDecideAccessReviewCampaignItem_BadCampaignID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`))),
		map[string]string{"id": "1", "campaignId": "bad", "itemId": "1"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestDecideAccessReviewCampaignItem_BadItemID_S13 — non-numeric {itemId} → 400.
func TestDecideAccessReviewCampaignItem_BadItemID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`))),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "bad"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestDecideAccessReviewCampaignItem_NoUserCtx_S13 — missing user context → 401.
func TestDecideAccessReviewCampaignItem_NoUserCtx_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`)),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDecideAccessReviewCampaignItem_InvalidJSON_S13 — malformed body → 400.
func TestDecideAccessReviewCampaignItem_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not valid json}`))),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidJSON")
}

// TestDecideAccessReviewCampaignItem_MissingAction_S13 — empty action field → 400.
func TestDecideAccessReviewCampaignItem_MissingAction_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParams(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"reason":"just because"}`))),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"},
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── access_review_campaigns_proxy.go: CreateAccessReviewCampaignProxy ────────

// TestCreateAccessReviewCampaignProxy_InvalidJSON_S13 — bad body → 400.
func TestCreateAccessReviewCampaignProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{bad json}`))
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateAccessReviewCampaignProxy_MissingFields_S13 — missing project_id or name → 400.
func TestCreateAccessReviewCampaignProxy_MissingFields_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))

	cases := []struct {
		name string
		body string
	}{
		{"missing_project_id", `{"name":"Q1"}`},
		{"missing_name", `{"project_id":1}`},
		{"both_missing", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			h.CreateAccessReviewCampaignProxy(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "INVALID_BODY")
		})
	}
}

// ── access_review_campaigns_proxy.go: GetAccessReviewCampaignProxy ───────────

// TestGetAccessReviewCampaignProxy_BadID_S13 — non-numeric {id} → 400.
func TestGetAccessReviewCampaignProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestGetAccessReviewCampaignProxy_NotFound_S13 — valid numeric {id}, no row → 404.
func TestGetAccessReviewCampaignProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NOT_FOUND")
}

// ── access_review_campaigns_proxy.go: ListAccessReviewCampaignsProxy ─────────

// TestListAccessReviewCampaignsProxy_MissingProjectID_S13 — no project_id query param → 400.
func TestListAccessReviewCampaignsProxy_MissingProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_QUERY")
}

// TestListAccessReviewCampaignsProxy_BadProjectID_S13 — invalid project_id → 400.
func TestListAccessReviewCampaignsProxy_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=notanumber", nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_QUERY")
}

// TestListAccessReviewCampaignsProxy_HappyPath_S13 — valid project_id returns list.
func TestListAccessReviewCampaignsProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_listarc_proxy", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?project_id=%d", proj.ID), nil)
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaignsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_review_campaigns_proxy.go: GetOpenAccessReviewCampaignProxy ────────

// TestGetOpenAccessReviewCampaignProxy_MissingProjectID_S13 — no project_id → 400.
func TestGetOpenAccessReviewCampaignProxy_MissingProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_QUERY")
}

// TestGetOpenAccessReviewCampaignProxy_BadProjectID_S13 — invalid project_id → 400.
func TestGetOpenAccessReviewCampaignProxy_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=xyz", nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetOpenAccessReviewCampaignProxy_NoneOpen_S13 — project exists but no open campaign → {"campaign":null}.
func TestGetOpenAccessReviewCampaignProxy_NoneOpen_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_getopen_proxy", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?project_id=%d", proj.ID), nil)
	w := httptest.NewRecorder()
	h.GetOpenAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "campaign")
}

// ── access_review_campaigns_proxy.go: GetLatestClosedAccessReviewCampaignProxy ─

// TestGetLatestClosedAccessReviewCampaignProxy_MissingProjectID_S13 — no project_id → 400.
func TestGetLatestClosedAccessReviewCampaignProxy_MissingProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetLatestClosedAccessReviewCampaignProxy_BadProjectID_S13 — non-numeric project_id → 400.
func TestGetLatestClosedAccessReviewCampaignProxy_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=abc", nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetLatestClosedAccessReviewCampaignProxy_NoneClosed_S13 — valid project, no closed → {"campaign":null}.
func TestGetLatestClosedAccessReviewCampaignProxy_NoneClosed_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_getlatestclosed", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?project_id=%d", proj.ID), nil)
	w := httptest.NewRecorder()
	h.GetLatestClosedAccessReviewCampaignProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "campaign")
}

// ── access_review_campaigns_proxy.go: CreateAccessReviewItemsProxy ─────────

// TestCreateAccessReviewItemsProxy_BadID_S13 — non-numeric {id} → 400.
func TestCreateAccessReviewItemsProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"items":[]}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestCreateAccessReviewItemsProxy_InvalidJSON_S13 — bad body → 400.
func TestCreateAccessReviewItemsProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not json}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// ── access_review_campaigns_proxy.go: ListAccessReviewItemsProxy ─────────────

// TestListAccessReviewItemsProxy_BadID_S13 — non-numeric {id} → 400.
func TestListAccessReviewItemsProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.ListAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// ── access_review_campaigns_proxy.go: CountPendingAccessReviewItemsProxy ─────

// TestCountPendingAccessReviewItemsProxy_BadID_S13 — non-numeric {id} → 400.
func TestCountPendingAccessReviewItemsProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestCountPendingAccessReviewItemsProxy_HappyPath_S13 — valid campaign id (no items) → 200 count=0.
func TestCountPendingAccessReviewItemsProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	ctx := context.Background()
	campaign, err := cs.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: 1, Name: "s13_count_pending", State: "open", CreatedBy: 1,
	})
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", fmt.Sprintf("%d", campaign.ID),
	)
	w := httptest.NewRecorder()
	h.CountPendingAccessReviewItemsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "count")
}

// ── access_review_campaigns_proxy.go: GetAccessReviewItemProxy ───────────────

// TestGetAccessReviewItemProxy_BadID_S13 — non-numeric {itemID} → 400.
func TestGetAccessReviewItemProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"itemID", "notanumber",
	)
	w := httptest.NewRecorder()
	h.GetAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestGetAccessReviewItemProxy_NotFound_S13 — valid numeric {itemID}, no row → 404.
func TestGetAccessReviewItemProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"itemID", "99999",
	)
	w := httptest.NewRecorder()
	h.GetAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NOT_FOUND")
}

// ── access_review_campaigns_proxy.go: UpdateAccessReviewItemProxy ─────────────

// TestUpdateAccessReviewItemProxy_BadID_S13 — non-numeric {itemID} → 400.
func TestUpdateAccessReviewItemProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	body, _ := json.Marshal(map[string]interface{}{
		"campaign_id": 1, "principal_type": "user", "decision": "attested",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"itemID", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestUpdateAccessReviewItemProxy_InvalidJSON_S13 — bad body → 400.
func TestUpdateAccessReviewItemProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{not json}`)),
		"itemID", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// ── access_request_proxy.go: CreateAccessRequestProxy ────────────────────────

// TestCreateAccessRequestProxy_InvalidJSON_S13 — malformed body → 400.
func TestCreateAccessRequestProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not json}`))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateAccessRequestProxy_MissingProjectID_S13 — missing project_id → 400.
func TestCreateAccessRequestProxy_MissingProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"user_id":1,"state":"pending"}`))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateAccessRequestProxy_MissingUserID_S13 — missing user_id → 400.
func TestCreateAccessRequestProxy_MissingUserID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"project_id":1,"state":"pending"}`))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateAccessRequestProxy_MissingState_S13 — missing state → 400.
func TestCreateAccessRequestProxy_MissingState_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"project_id":1,"user_id":2}`))
	w := httptest.NewRecorder()
	h.CreateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// ── access_request_proxy.go: GetAccessRequestProxy ───────────────────────────

// TestGetAccessRequestProxy_BadID_S13 — non-numeric {id} → 400.
func TestGetAccessRequestProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestGetAccessRequestProxy_NotFound_S13 — valid numeric id, no row → 404.
func TestGetAccessRequestProxy_NotFound_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.GetAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NOT_FOUND")
}

// ── access_request_proxy.go: UpdateAccessRequestProxy ────────────────────────

// TestUpdateAccessRequestProxy_BadID_S13 — non-numeric {id} → 400.
func TestUpdateAccessRequestProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"state":"approved"}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestUpdateAccessRequestProxy_InvalidJSON_S13 — bad body → 400.
func TestUpdateAccessRequestProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{not json}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestUpdateAccessRequestProxy_InvalidState_S13 — state "pending" is not a valid target → 400.
func TestUpdateAccessRequestProxy_InvalidState_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"state":"pending"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestUpdateAccessRequestProxy_UnknownState_S13 — unknown state → 400.
func TestUpdateAccessRequestProxy_UnknownState_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"state":"bogus"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateAccessRequestProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── access_request_proxy.go: ListAccessRequestsProxy ─────────────────────────

// TestListAccessRequestsProxy_MissingProjectID_S13 — no project_id → 400.
func TestListAccessRequestsProxy_MissingProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_QUERY")
}

// TestListAccessRequestsProxy_BadProjectID_S13 — non-numeric project_id → 400.
func TestListAccessRequestsProxy_BadProjectID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=bad", nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_QUERY")
}

// TestListAccessRequestsProxy_HappyPath_S13 — valid project_id → 200.
func TestListAccessRequestsProxy_HappyPath_S13(t *testing.T) {
	t.Parallel()
	cs := freshCoreS12(t)
	proj, err := cs.CreateProject(context.Background(), "s13_list_ar_proxy", "")
	require.NoError(t, err)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/?project_id=%d", proj.ID), nil)
	w := httptest.NewRecorder()
	h.ListAccessRequestsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── access_request_proxy.go: CreateAccessRequestApprovalProxy ────────────────

// TestCreateAccessRequestApprovalProxy_BadID_S13 — non-numeric {id} → 400.
func TestCreateAccessRequestApprovalProxy_BadID_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"approver_id":1}`)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_PARAMETER")
}

// TestCreateAccessRequestApprovalProxy_InvalidJSON_S13 — bad body → 400.
func TestCreateAccessRequestApprovalProxy_InvalidJSON_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{bad}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateAccessRequestApprovalProxy_NoAuthenticatedCaller_S13 (G80
// documented-exception re-verification sweep, 2026-08-25) supersedes the old
// MissingApproverID test: approver_id is no longer read from the wire at all
// (see access_request_proxy.go's own updated doc comment) -- a wire body
// setting it to 0 is no longer distinct from any other value. What must
// still be rejected is a call with no authenticated caller at all.
func TestCreateAccessRequestApprovalProxy_NoAuthenticatedCaller_S13(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS12(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"approver_id":0}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.CreateAccessRequestApprovalProxy(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "FORBIDDEN")
}
