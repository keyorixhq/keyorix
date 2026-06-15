package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// DashboardHandler handles dashboard HTTP requests.
type DashboardHandler struct {
	coreService *core.KeyorixCore
}

// NewDashboardHandler constructs a DashboardHandler.
func NewDashboardHandler(coreService *core.KeyorixCore) *DashboardHandler {
	return &DashboardHandler{coreService: coreService}
}

// GetStats handles GET /api/v1/dashboard/stats
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	stats, err := h.coreService.GetDashboardStats(r.Context(), userCtx.UserID, userCtx.Username)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch dashboard stats", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, stats, "")
}

// GetCompliancePosture handles GET /api/v1/compliance/posture — the deployment-wide
// controls-posture snapshot for auditors (gated by system.read in the router).
func (h *DashboardHandler) GetCompliancePosture(w http.ResponseWriter, r *http.Request) {
	posture, err := h.coreService.GetCompliancePosture(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to compute compliance posture", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, posture, "")
}

// VerifyComplianceEvidence handles POST /api/v1/compliance/evidence/verify — checks
// a previously-exported evidence pack against its detached signature. The pack bytes
// are base64-encoded in the request so arbitrary JSON can ride in a JSON envelope.
func (h *DashboardHandler) VerifyComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DataB64   string `json:"data_b64"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	data, err := base64.StdEncoding.DecodeString(body.DataB64)
	if err != nil {
		sendError(w, "InvalidParameter", "data_b64 must be base64-encoded", http.StatusBadRequest, nil)
		return
	}
	result := h.coreService.VerifyEvidenceSignature(data, body.Signature)
	sendSuccess(w, result, "")
}

// GetComplianceControls handles GET /api/v1/compliance/controls — the control
// matrix mapping each enforced control to its ISO 27001 / SOC 2 / NIS2 / DORA
// references with a live status; gated by system.read in the router.
func (h *DashboardHandler) GetComplianceControls(w http.ResponseWriter, r *http.Request) {
	controls, err := h.coreService.GetComplianceControls(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to evaluate compliance controls", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, controls, "")
}

// GetComplianceEvidence handles GET /api/v1/compliance/evidence — the auditor
// evidence pack (posture + supporting records); gated by system.read in the router.
func (h *DashboardHandler) GetComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	evidence, err := h.coreService.GenerateComplianceEvidence(r.Context())
	if err != nil {
		sendError(w, "InternalServerError", "Failed to assemble compliance evidence", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, evidence, "")
}

// GetActivity handles GET /api/v1/dashboard/activity
func (h *DashboardHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 10

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("pageSize"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	feed, err := h.coreService.GetActivityFeed(r.Context(), userCtx.UserID, userCtx.Username, page, pageSize)
	if err != nil {
		sendError(w, "InternalServerError", "Failed to fetch activity feed", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, feed, "")
}
