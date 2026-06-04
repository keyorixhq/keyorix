package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// ListProjectMembers handles GET /api/v1/projects/{id}/members
func (h *CatalogHandler) ListProjectMembers(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	members, err := h.coreService.ListProjectMembers(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"members": members}, "")
}

// AddProjectMember handles POST /api/v1/projects/{id}/members
func (h *CatalogHandler) AddProjectMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		UserID uint   `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 || body.Role == "" {
		sendError(w, "ValidationError", "user_id and role are required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.AddProjectMember(r.Context(), uint(id), body.UserID, body.Role); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "unknown role") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, nil, "Member added")
}

// UpdateProjectMember handles PUT /api/v1/projects/{id}/members/{userId}
func (h *CatalogHandler) UpdateProjectMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Role == "" {
		sendError(w, "ValidationError", "role is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.SetProjectMemberRole(r.Context(), uint(id), uint(userID), body.Role); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown role") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Member role updated")
}

// RemoveProjectMember handles DELETE /api/v1/projects/{id}/members/{userId}
func (h *CatalogHandler) RemoveProjectMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RemoveProjectMember(r.Context(), uint(id), uint(userID)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not a member") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Member removed")
}
