package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// User represents a user in the system
type User struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// Role represents a role in the system
type Role struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

// UserRole represents a user-role assignment
type UserRole struct {
	UserID    uint   `json:"user_id"`
	RoleID    uint   `json:"role_id"`
	Username  string `json:"username"`
	RoleName  string `json:"role_name"`
	CreatedAt string `json:"created_at"`
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email       *string `json:"email,omitempty" validate:"omitempty,email"`
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
	Active      *bool   `json:"active,omitempty"`
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Name        string   `json:"name" validate:"required,min=3,max=50"`
	Description string   `json:"description" validate:"required,min=1,max=200"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Description *string   `json:"description,omitempty" validate:"omitempty,min=1,max=200"`
	Permissions *[]string `json:"permissions,omitempty" validate:"omitempty,min=1"`
}

// AssignRoleRequest represents a request to assign a role to a user
type AssignRoleRequest struct {
	UserID uint `json:"user_id" validate:"required"`
	RoleID uint `json:"role_id" validate:"required"`
}

// RemoveRoleRequest represents a request to remove a role from a user
type RemoveRoleRequest struct {
	UserID uint `json:"user_id" validate:"required"`
	RoleID uint `json:"role_id" validate:"required"`
}

var validator = validation.NewValidator()

// ListUsers handles GET /api/v1/users
func ListUsers(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse pagination parameters
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

	// Mock data for demonstration
	users := []User{
		{
			ID:          1,
			Username:    "admin",
			Email:       "admin@keyorix.com",
			DisplayName: "System Administrator",
			Active:      true,
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		},
		{
			ID:          2,
			Username:    "user1",
			Email:       "user1@keyorix.com",
			DisplayName: "Regular User",
			Active:      true,
			CreatedAt:   "2024-01-02T00:00:00Z",
			UpdatedAt:   "2024-01-02T00:00:00Z",
		},
	}

	response := map[string]interface{}{
		"users":       users,
		"page":        page,
		"page_size":   pageSize,
		"total":       len(users),
		"total_pages": 1,
	}

	sendSuccess(w, response, "")
}

// CreateUser handles POST /api/v1/users
func CreateUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Mock response
	user := User{
		ID:          3,
		Username:    req.Username,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Active:      true,
		CreatedAt:   "2024-01-03T00:00:00Z",
		UpdatedAt:   "2024-01-03T00:00:00Z",
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, user, "User created successfully")
}

// GetUser handles GET /api/v1/users/{id}
func GetUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	// Mock response
	if id == 1 {
		user := User{
			ID:          1,
			Username:    "admin",
			Email:       "admin@keyorix.com",
			DisplayName: "System Administrator",
			Active:      true,
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		}
		sendSuccess(w, user, "")
	} else {
		sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
	}
}

// UpdateUser handles PUT /api/v1/users/{id}
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Mock response
	user := User{
		ID:          uint(id),
		Username:    "admin",
		Email:       "admin@keyorix.com",
		DisplayName: "System Administrator",
		Active:      true,
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-03T00:00:00Z",
	}

	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Active != nil {
		user.Active = *req.Active
	}

	sendSuccess(w, user, "User updated successfully")
}

// DeleteUser handles DELETE /api/v1/users/{id}
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	_, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListRoles handles GET /api/v1/roles
func ListRoles(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Mock data
	roles := []Role{
		{
			ID:          1,
			Name:        "admin",
			Description: "System administrator with full access",
			Permissions: []string{"secrets.read", "secrets.write", "secrets.delete", "users.read", "users.write", "roles.read", "roles.write", "audit.read", "system.read"},
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		},
		{
			ID:          2,
			Name:        "user",
			Description: "Regular user with limited access",
			Permissions: []string{"secrets.read", "secrets.write"},
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		},
	}

	response := map[string]interface{}{
		"roles": roles,
		"total": len(roles),
	}

	sendSuccess(w, response, "")
}

// CreateRole handles POST /api/v1/roles
func CreateRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Mock response
	role := Role{
		ID:          3,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		CreatedAt:   "2024-01-03T00:00:00Z",
		UpdatedAt:   "2024-01-03T00:00:00Z",
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, role, "Role created successfully")
}

// GetRole handles GET /api/v1/roles/{id}
func GetRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid role ID", http.StatusBadRequest, nil)
		return
	}

	// Mock response
	if id == 1 {
		role := Role{
			ID:          1,
			Name:        "admin",
			Description: "System administrator with full access",
			Permissions: []string{"secrets.read", "secrets.write", "secrets.delete", "users.read", "users.write", "roles.read", "roles.write", "audit.read", "system.read"},
			CreatedAt:   "2024-01-01T00:00:00Z",
			UpdatedAt:   "2024-01-01T00:00:00Z",
		}
		sendSuccess(w, role, "")
	} else {
		sendError(w, "NotFound", "Role not found", http.StatusNotFound, nil)
	}
}

// UpdateRole handles PUT /api/v1/roles/{id}
func UpdateRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid role ID", http.StatusBadRequest, nil)
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Mock response
	role := Role{
		ID:          uint(id),
		Name:        "admin",
		Description: "System administrator with full access",
		Permissions: []string{"secrets.read", "secrets.write", "secrets.delete", "users.read", "users.write", "roles.read", "roles.write", "audit.read", "system.read"},
		CreatedAt:   "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-03T00:00:00Z",
	}

	if req.Description != nil {
		role.Description = *req.Description
	}
	if req.Permissions != nil {
		role.Permissions = *req.Permissions
	}

	sendSuccess(w, role, "Role updated successfully")
}

// DeleteRole handles DELETE /api/v1/roles/{id}
func DeleteRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	_, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid role ID", http.StatusBadRequest, nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AssignRole handles POST /api/v1/user-roles
func AssignRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Mock response
	userRole := UserRole{
		UserID:    req.UserID,
		RoleID:    req.RoleID,
		Username:  "user1",
		RoleName:  "admin",
		CreatedAt: "2024-01-03T00:00:00Z",
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, userRole, "Role assigned successfully")
}

// RemoveRole handles DELETE /api/v1/user-roles
func RemoveRole(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var req RemoveRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetUserRoles handles GET /api/v1/user-roles/user/{userId}
func GetUserRoles(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userIDStr := chi.URLParam(r, "userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}

	// Mock response
	userRoles := []UserRole{
		{
			UserID:    uint(userID),
			RoleID:    1,
			Username:  "admin",
			RoleName:  "admin",
			CreatedAt: "2024-01-01T00:00:00Z",
		},
	}

	response := map[string]interface{}{
		"user_roles": userRoles,
		"user_id":    userID,
		"total":      len(userRoles),
	}

	sendSuccess(w, response, "")
}

// Helper functions are now in helpers.go
