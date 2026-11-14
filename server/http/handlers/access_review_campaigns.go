// access_review_campaigns.go — endpoints for periodic access-review campaigns
// (ISO 27001 A.5.18). All are project-scoped; gets need roles.read and mutations
// roles.assign (wired in router.go).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// campaignStatusForError maps a core error to an HTTP status (shared shape). Every status
// is decided by a sentinel, never by the text of the message (which embeds the translated
// "Validation error" prefix): a missing target is 404, a refused request (a missing id, an
// unknown action or source, a closed campaign, an item already decided, items still
// pending) is core.ErrValidation, 400.
func campaignStatusForError(err error) int {
	switch {
	case errors.Is(err, core.ErrAccessReviewNotFound):
		return http.StatusNotFound
	case errors.Is(err, core.ErrValidation):
		return http.StatusBadRequest
	case errors.Is(err, core.ErrPermissionDenied):
		// The independent-reviewer refusals (your own access, a group you belong to, a
		// machine identity you provisioned, a machine caller) answer 400 on this route
		// since they were worded "... an independent reviewer is required"; the
		// standalone attest/revoke endpoints answer the same refusals 403. Kept as it
		// was (an answer for AUTHZ-CORE-WAIVERS-1 / the admin, not a typing matter).
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// sendCampaignError classifies err via campaignStatusForError and writes the
// response. The message is only echoed back for the recognized, deliberately
// user-facing outcomes above; the unclassified/500 fallback is assumed to be a
// raw error from a lower layer (storage, etc.), so it is logged server-side
// and replaced with a generic client-safe message (backlog #116).
func sendCampaignError(w http.ResponseWriter, context string, err error) {
	if sendStorageUnavailable(w, err) {
		return
	}
	msg := err.Error()
	status := campaignStatusForError(err)
	if status == http.StatusInternalServerError {
		log.Printf("Error %s: %v", context, err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, status, nil)
}

// OpenAccessReviewCampaign handles POST /api/v1/projects/{id}/access-review/campaigns.
func (h *CatalogHandler) OpenAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)
	result, err := h.coreService.OpenAccessReviewCampaign(r.Context(), userCtx.UserID, machineID(r), uint(projectID), body.Name)
	if err != nil {
		if sendAuditUnavailable(w, err) {
			return
		}
		sendCampaignError(w, "opening access-review campaign", err)
		return
	}
	sendCreated(w, map[string]any{"campaign": result.Campaign, "progress": result.Progress}, "Campaign opened")
}

// ListAccessReviewCampaigns handles GET /api/v1/projects/{id}/access-review/campaigns.
func (h *CatalogHandler) ListAccessReviewCampaigns(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaigns, err := h.coreService.ListAccessReviewCampaigns(r.Context(), uint(projectID))
	if err != nil {
		// 503 on a storage read fault; any other error is logged and answered 500.
		sendCampaignError(w, "listing access-review campaigns", err)
		return
	}
	sendSuccess(w, map[string]any{"campaigns": campaigns, "count": len(campaigns)}, "")
}

// GetAccessReviewCampaign handles GET /api/v1/projects/{id}/access-review/campaigns/{campaignId}.
func (h *CatalogHandler) GetAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	detail, err := h.coreService.GetAccessReviewCampaign(r.Context(), uint(projectID), uint(campaignID))
	if err != nil {
		sendCampaignError(w, "getting access-review campaign", err)
		return
	}
	sendSuccess(w, map[string]any{
		"campaign": detail.Campaign, "items": detail.Items, "progress": detail.Progress,
	}, "")
}

// DecideAccessReviewCampaignItem handles
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide.
func (h *CatalogHandler) DecideAccessReviewCampaignItem(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	itemID, err := strconv.ParseUint(chi.URLParam(r, "itemId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid item ID", http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Action == "" {
		sendError(w, "ValidationError", "action is required (attest|revoke)", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DecideAccessReviewItem(r.Context(), userCtx.UserID, uint(projectID), uint(campaignID), uint(itemID), body.Action, body.Reason); err != nil {
		sendCampaignError(w, "deciding access-review campaign item", err)
		return
	}
	sendSuccess(w, nil, "Decision recorded")
}

// CloseAccessReviewCampaign handles
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close.
func (h *CatalogHandler) CloseAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	campaignID, err := strconv.ParseUint(chi.URLParam(r, "campaignId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidCampaignID, http.StatusBadRequest, nil)
		return
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	result, err := h.coreService.CloseAccessReviewCampaign(r.Context(), userCtx.UserID, machineID(r), uint(projectID), uint(campaignID), body.Force)
	if err != nil {
		if sendAuditUnavailable(w, err) {
			return
		}
		sendCampaignError(w, "closing access-review campaign", err)
		return
	}
	sendSuccess(w, map[string]any{"campaign": result.Campaign, "progress": result.Progress}, "Campaign closed")
}
