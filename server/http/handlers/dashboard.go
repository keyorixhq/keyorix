package handlers

import (
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
