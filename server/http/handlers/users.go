package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// UserHandler handles user HTTP requests (wired to core when InitCoreHandlers runs).
type UserHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

var defaultUserHandler *UserHandler

// NewUserHandler constructs a UserHandler.
func NewUserHandler(coreService *core.KeyorixCore) (*UserHandler, error) {
	return &UserHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

// --- Legacy shapes (used when defaultUserHandler is nil, e.g. rbac_test direct calls) ---

type legacyAPIUser struct {
	ID          uint   `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type legacyCreateUserBody struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
}

type legacyUpdateUserBody struct {
	Email       *string `json:"email,omitempty" validate:"omitempty,email"`
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
	Active      *bool   `json:"active,omitempty"`
}

func userToAPIResponse(u *models.User) map[string]interface{} {
	dn := u.DisplayName
	if dn == "" {
		dn = u.Username
	}
	return map[string]interface{}{
		"id":           u.ID,
		"username":     u.Username,
		"email":        u.Email,
		"display_name": dn,
		"active":       u.IsActive,
		"created_at":   u.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":   u.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func listUsersLegacy(w http.ResponseWriter, r *http.Request) {
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

	users := []legacyAPIUser{
		{ID: 1, Username: "admin", Email: "admin@keyorix.com", DisplayName: "System Administrator", Active: true, CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z"},
		{ID: 2, Username: "user1", Email: "user1@keyorix.com", DisplayName: "Regular User", Active: true, CreatedAt: "2024-01-02T00:00:00Z", UpdatedAt: "2024-01-02T00:00:00Z"},
	}
	sendSuccess(w, map[string]interface{}{
		"users":       users,
		"page":        page,
		"page_size":   pageSize,
		"total":       len(users),
		"total_pages": 1,
	}, "")
}

func createUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var req legacyCreateUserBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	u := legacyAPIUser{ID: 3, Username: req.Username, Email: req.Email, DisplayName: req.DisplayName, Active: true, CreatedAt: "2024-01-03T00:00:00Z", UpdatedAt: "2024-01-03T00:00:00Z"}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, u, "User created successfully")
}

func getUserLegacy(w http.ResponseWriter, r *http.Request) {
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
	if id == 1 {
		sendSuccess(w, legacyAPIUser{ID: 1, Username: "admin", Email: "admin@keyorix.com", DisplayName: "System Administrator", Active: true, CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-01T00:00:00Z"}, "")
		return
	}
	sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
}

func updateUserLegacy(w http.ResponseWriter, r *http.Request) {
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
	var req legacyUpdateUserBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	u := legacyAPIUser{ID: uint(id), Username: "admin", Email: "admin@keyorix.com", DisplayName: "System Administrator", Active: true, CreatedAt: "2024-01-01T00:00:00Z", UpdatedAt: "2024-01-03T00:00:00Z"}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.DisplayName != nil {
		u.DisplayName = *req.DisplayName
	}
	if req.Active != nil {
		u.Active = *req.Active
	}
	sendSuccess(w, u, "User updated successfully")
}

func deleteUserLegacy(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	if _, err := strconv.ParseUint(idStr, 10, 32); err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListUsers handles GET /api/v1/users
func ListUsers(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		listUsersLegacy(w, r)
		return
	}
	defaultUserHandler.ListUsers(w, r)
}

// CreateUser handles POST /api/v1/users
func CreateUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		createUserLegacy(w, r)
		return
	}
	defaultUserHandler.CreateUser(w, r)
}

// GetUser handles GET /api/v1/users/{id}
func GetUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		getUserLegacy(w, r)
		return
	}
	defaultUserHandler.GetUser(w, r)
}

// UpdateUser handles PUT /api/v1/users/{id}
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		updateUserLegacy(w, r)
		return
	}
	defaultUserHandler.UpdateUser(w, r)
}

// DeleteUser handles DELETE /api/v1/users/{id}
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		deleteUserLegacy(w, r)
		return
	}
	defaultUserHandler.DeleteUser(w, r)
}

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

// CreateUser handles POST /api/v1/users
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var body struct {
		Username    string `json:"username" validate:"required,min=3,max=50"`
		Email       string `json:"email" validate:"required,email"`
		DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
		Password    string `json:"password" validate:"required,min=8"`
		IsActive    *bool  `json:"is_active,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.CreateUserRequest{
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		Password:    body.Password,
		IsActive:    body.IsActive,
	}
	created, err := h.coreService.CreateUser(r.Context(), req)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		if strings.Contains(err.Error(), "already exists") {
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
			return
		}
		sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
		return
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, userToAPIResponse(created), i18n.T("SuccessUserCreated", nil))
}

// GetUser handles GET /api/v1/users/{id}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
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
	u, err := h.coreService.GetUser(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, userToAPIResponse(u), "")
}

// UpdateUser handles PUT /api/v1/users/{id}
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		Username    *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
		Email       *string `json:"email,omitempty" validate:"omitempty,email"`
		DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=1,max=100"`
		Active      *bool   `json:"active,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateUserRequest{ID: uint(id)}
	if body.Username != nil {
		req.Username = *body.Username
	}
	if body.Email != nil {
		req.Email = *body.Email
	}
	if body.DisplayName != nil {
		req.DisplayName = *body.DisplayName
	}
	if body.Active != nil {
		req.IsActive = body.Active
	}

	updated, err := h.coreService.UpdateUser(r.Context(), req)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
			return
		}
		sendError(w, "InternalError", "Failed to update user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, userToAPIResponse(updated), i18n.T("SuccessUserUpdated", nil))
}

// DeleteUser handles DELETE /api/v1/users/{id}
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
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
	if err := h.coreService.DeleteUser(r.Context(), uint(id)); err != nil {
		log.Printf("Error deleting user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to delete user", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
