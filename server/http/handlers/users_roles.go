package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

type updateUserRolesRequest struct {
	RoleIDs []uint `json:"role_ids" validate:"required,min=1"`
}

type apiRole struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// GetUserRolesForUser handles GET /api/v1/users/{id}/roles
func GetUserRolesForUser(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userIDStr := chi.URLParam(r, "id")
	if _, err := strconv.ParseUint(userIDStr, 10, 32); err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	// Mock: all users start with the "user" role assigned
	roles := []apiRole{
		{ID: 2, Name: "user"},
	}
	sendSuccess(w, map[string]interface{}{"roles": roles}, "")
}

// UpdateUserRoles handles PUT /api/v1/users/{id}/roles
func UpdateUserRoles(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userIDStr := chi.URLParam(r, "id")
	if _, err := strconv.ParseUint(userIDStr, 10, 32); err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	var req updateUserRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	sendSuccess(w, map[string]interface{}{"role_ids": req.RoleIDs}, "Roles updated successfully")
}
