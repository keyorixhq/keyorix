// users_list.go — ListUsers and SearchUsers handlers.
//
// Handles GET /api/v1/users (paginated + filtered) and GET /api/v1/users/search.
// For CRUD operations see users_crud.go.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListUsers serves user list from core.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	filter := &storage.UserFilter{Page: page, PageSize: pageSize}
	if u := strings.TrimSpace(r.URL.Query().Get("username")); u != "" {
		filter.Username = &u
	}
	if e := strings.TrimSpace(r.URL.Query().Get("email")); e != "" {
		filter.Email = &e
	}
	if a := r.URL.Query().Get("is_active"); a != "" {
		v := a == "true" || a == "1"
		filter.IsActive = &v
	}

	users, total, err := h.coreService.ListUsers(r.Context(), filter)
	if err != nil {
		log.Printf("Error listing users: %v", err)
		sendError(w, "InternalError", "Failed to list users", http.StatusInternalServerError, nil)
		return
	}

	out := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		out = append(out, userToAPIResponse(u))
	}
	totalPages := int64(0)
	if pageSize > 0 {
		totalPages = (total + int64(pageSize) - 1) / int64(pageSize)
	}
	sendSuccess(w, map[string]interface{}{
		"users":       out,
		"page":        page,
		"page_size":   pageSize,
		"total":       total,
		"total_pages": totalPages,
	}, "")
}

// SearchUsers handles GET /api/v1/users/search?q=<query>
func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		sendError(w, "BadRequest", "query parameter 'q' is required", http.StatusBadRequest, nil)
		return
	}

	filter := &storage.UserFilter{Search: &q, Page: 1, PageSize: 10}
	users, _, err := h.coreService.ListUsers(r.Context(), filter)
	if err != nil {
		log.Printf("Error searching users: %v", err)
		sendError(w, "InternalError", "Failed to search users", http.StatusInternalServerError, nil)
		return
	}

	type userResult struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	results := make([]userResult, 0, len(users))
	for _, u := range users {
		results = append(results, userResult{ID: u.ID, Username: u.Username, Email: u.Email})
	}
	sendSuccess(w, map[string]interface{}{"users": results}, "")
}
