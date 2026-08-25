// access_review_campaigns_proxy_r128_test.go — regression tests for the r128
// security fixes in access_review_campaigns_proxy.go:
//
//	ARC-003: CreateAccessReviewCampaignProxy must ignore caller-supplied lifecycle
//	         state and always create an open campaign.
//	ARC-004: CreateAccessReviewItemsProxy must strip decision fields from each
//	         incoming item, forcing every new item to "pending".
//	ARC-005: UpdateAccessReviewItemProxy must reject self-certification
//	         (decided_by == principal_id for user-type items) and must reject a
//	         zero decided_by.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ARC-003: CreateAccessReviewCampaignProxy lifecycle-state stripping ────────

// TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128 pins ARC-003:
// a body carrying state="closed" must be persisted as state="open".
func TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	now := time.Now()
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":        42,
		"name":              "ARC-003 closed-state injection attempt",
		"state":             "closed",
		"closed_by":         99,
		"closed_at":         now,
		"forced_incomplete": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)

	// The returned campaign must carry the normalised lifecycle fields.
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data should be an object")
	assert.Equal(t, "open", data["state"], "state must be forced to open")
	// closed_by is omitempty — absent in response when zero is correct.
	if v, present := data["closed_by"]; present {
		assert.EqualValues(t, 0, v, "closed_by must be zero when present")
	}
	assert.Nil(t, data["closed_at"], "closed_at must be nil")
	assert.False(t, data["forced_incomplete"].(bool), "forced_incomplete must be false")
}

// TestCreateAccessReviewCampaignProxy_IgnoresForcedIncomplete_R128 pins ARC-003
// for forced_incomplete only: even without state="closed", forced_incomplete must
// be stripped.
func TestCreateAccessReviewCampaignProxy_IgnoresForcedIncomplete_R128(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{
		"project_id":        43,
		"name":              "ARC-003 forced-incomplete injection",
		"forced_incomplete": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/access-review-campaigns", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateAccessReviewCampaignProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)

	data := resp.Data.(map[string]interface{})
	assert.Equal(t, "open", data["state"])
	assert.False(t, data["forced_incomplete"].(bool))
}

// ── ARC-004: CreateAccessReviewItemsProxy decision-field stripping ────────────

// TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128 pins ARC-004:
// items submitted with decision/decided_by/decided_at pre-set must be stored as
// "pending" with no decided_by or decided_at.
func TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "arc004-proj"}
	require.NoError(t, db.Create(proj).Error)
	campaign := &models.AccessReviewCampaign{
		ProjectID: proj.ID,
		Name:      "ARC-004 test",
		State:     "open",
		CreatedBy: 1,
	}
	require.NoError(t, db.Create(campaign).Error)

	decidedAt := time.Now()
	body, _ := json.Marshal(map[string]interface{}{
		"items": []map[string]interface{}{
			{
				"principal_type": "user",
				"principal_id":   5,
				"principal_name": "alice",
				"access_level":   "read",
				"environment_id": 1,
				// Pre-supplied decision fields — must be stripped.
				"decision":   "attested",
				"decided_by": 9,
				"decided_at": decidedAt,
			},
		},
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", campaign.ID),
			bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", campaign.ID),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateAccessReviewItemsProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)

	// Verify the persisted item has decision="pending" and zero decided_by.
	var items []models.AccessReviewItem
	require.NoError(t, db.Where("campaign_id = ?", campaign.ID).Find(&items).Error)
	require.Len(t, items, 1)
	assert.Equal(t, "pending", items[0].Decision, "decision must be forced to pending")
	assert.EqualValues(t, 0, items[0].DecidedBy, "decided_by must be zeroed")
	assert.Nil(t, items[0].DecidedAt, "decided_at must be nil")
}

// ── ARC-005: UpdateAccessReviewItemProxy self-certification rejection ─────────

// TestUpdateAccessReviewItemProxy_RejectsSelfCertification_R128 pins ARC-005.
//
// G80 documented-exception re-verification sweep (2026-08-25): the
// self-certification check is now anchored to the AUTHENTICATED caller
// (requestActorKindAndID(r)), not the wire's decided_by — decided_by is
// ignored entirely. withUserCtx (UserID=1) authenticates the caller AS the
// item's own principal (principal_id: 1) to trigger a genuine
// self-certification, matching what the check now actually guards against;
// the wire's decided_by=7 is deliberately different from 1 to prove it has
// no effect on the outcome.
func TestUpdateAccessReviewItemProxy_RejectsSelfCertification_R128(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{
		"principal_type": "user",
		"principal_id":   1,
		"decision":       "attest",
		"decided_by":     7,
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/access-review-campaigns/items/1",
			bytes.NewReader(body)),
		"itemID", "1",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "FORBIDDEN", resp.Error.Code)
}

// TestUpdateAccessReviewItemProxy_AllowsNonSelfCertification_R128 pins ARC-005:
// a request where the AUTHENTICATED caller != principal_id is accepted (403
// not raised). withUserCtx (UserID=1) authenticates as a genuinely different
// reviewer than the item's principal (3) -- the wire's decided_by is now
// ignored, so this exercises the real check, not the pre-sweep wire-trusting
// one.
func TestUpdateAccessReviewItemProxy_AllowsNonSelfCertification_R128(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "arc005-allow-proj"}
	require.NoError(t, db.Create(proj).Error)
	campaign := &models.AccessReviewCampaign{
		ProjectID: proj.ID,
		Name:      "ARC-005 allow test",
		State:     "open",
		CreatedBy: 1,
	}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID:    campaign.ID,
		PrincipalType: "user",
		PrincipalID:   3,
		Decision:      "pending",
	}
	require.NoError(t, db.Create(item).Error)

	body, _ := json.Marshal(map[string]interface{}{
		"id":             item.ID,
		"campaign_id":    campaign.ID,
		"principal_type": "user",
		"principal_id":   3,
		"decision":       "attest",
		// decided_by (4) differs from principal_id (3) — independence check passes.
		"decided_by": 4,
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", item.ID),
			bytes.NewReader(body)),
		"itemID", fmt.Sprintf("%d", item.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestUpdateAccessReviewItemProxy_RejectsZeroDecidedBy_R128 pins ARC-005:
// a request with decided_by == 0 must return 403.
func TestUpdateAccessReviewItemProxy_RejectsZeroDecidedBy_R128(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{
		"principal_type": "user",
		"principal_id":   5,
		"decision":       "attest",
		// decided_by absent (zero) → rejected.
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/access-review-campaigns/items/1",
			bytes.NewReader(body)),
		"itemID", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "FORBIDDEN", resp.Error.Code)
}

// TestUpdateAccessReviewItemProxy_SelfCertNonUserType_R128 pins ARC-005:
// the self-certification check is type-scoped to "user" — a non-user item
// (e.g. "group") with principal_id == decided_by must NOT be blocked here
// (that check lives in core.DecideAccessReviewItem on the decision path).
func TestUpdateAccessReviewItemProxy_SelfCertNonUserType_R128(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "arc005-group-proj"}
	require.NoError(t, db.Create(proj).Error)
	campaign := &models.AccessReviewCampaign{
		ProjectID: proj.ID,
		Name:      "ARC-005 group type test",
		State:     "open",
		CreatedBy: 1,
	}
	require.NoError(t, db.Create(campaign).Error)
	item := &models.AccessReviewItem{
		CampaignID:    campaign.ID,
		PrincipalType: "group",
		PrincipalID:   7,
		Decision:      "pending",
	}
	require.NoError(t, db.Create(item).Error)

	// decided_by == principal_id but principal_type is "group", not "user" —
	// ARC-005 proxy check doesn't block this (the deeper group-membership check
	// runs inside core.DecideAccessReviewItem on the human-facing path).
	body, _ := json.Marshal(map[string]interface{}{
		"id":             item.ID,
		"campaign_id":    campaign.ID,
		"principal_type": "group",
		"principal_id":   7,
		"decision":       "attest",
		"decided_by":     7,
	})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut,
			fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", item.ID),
			bytes.NewReader(body)),
		"itemID", fmt.Sprintf("%d", item.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateAccessReviewItemProxy(w, req)

	// Should reach storage (200 or 500), NOT 403.
	assert.NotEqual(t, http.StatusForbidden, w.Code)
}
