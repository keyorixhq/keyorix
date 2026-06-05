// users_crud.go — CreateUser, GetUser, UpdateUser, DeleteUser, RestoreUser handlers.
//
// Handles core user lifecycle operations.
// For list/search see users_list.go.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/middleware"
)

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
		// Password is optional when DeliverSetupLink is set — the user sets their own
		// password via the setup link (ADR-028) instead of the admin choosing one.
		Password string `json:"password" validate:"omitempty,min=8"`
		IsActive *bool  `json:"is_active,omitempty"`
		// DeliverSetupLink provisions an account_setup link instead of an admin-set
		// password: the account is created in pending_first_login state and a setup
		// link is delivered (or returned for out-of-band relay).
		DeliverSetupLink bool `json:"deliver_setup_link,omitempty"`
		// GenerateOneTimePassword provisions a server-generated initial password instead
		// of an admin-set one or a setup link: the account is created in
		// password_reset_required state and the password is returned once for the admin
		// to relay out-of-band (ADR-028 Part E). The user must change it on first login.
		GenerateOneTimePassword bool `json:"generate_one_time_password,omitempty"`
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

	// The three credential modes are mutually exclusive: admin-set password, setup
	// link, or generated one-time password.
	if body.DeliverSetupLink && body.GenerateOneTimePassword {
		sendError(w, "ValidationError", "Choose either deliver_setup_link or generate_one_time_password, not both", http.StatusBadRequest, nil)
		return
	}

	// One-time-password path (ADR-028 Part E): server generates the initial password,
	// returns it once for out-of-band relay, and forces a change on first login.
	if body.GenerateOneTimePassword {
		created, otp, err := h.coreService.CreateUserWithOneTimePassword(r.Context(), req, userCtx.UserID)
		if err != nil {
			log.Printf("Error creating user with one-time password: %v", err)
			if strings.Contains(err.Error(), "already exists") {
				sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
				return
			}
			sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{
			"user":              userToAPIResponse(created),
			"one_time_password": otp,
		}, i18n.T("SuccessUserCreated", nil))
		return
	}

	// Setup-link provisioning path (ADR-028): no admin password; deliver a link.
	if body.DeliverSetupLink {
		created, prov, err := h.coreService.CreateUserWithSetupLink(r.Context(), req, userCtx.UserID)
		if err != nil {
			log.Printf("Error creating user with setup link: %v", err)
			if strings.Contains(err.Error(), "already exists") {
				sendError(w, "ConflictError", "User already exists", http.StatusConflict, nil)
				return
			}
			if errors.Is(err, core.ErrSetupBaseURLRequired) {
				sendError(w, "ConfigError", err.Error(), http.StatusBadRequest, nil)
				return
			}
			sendError(w, "InternalError", "Failed to create user", http.StatusInternalServerError, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{
			"user":       userToAPIResponse(created),
			"setup_link": prov,
		}, i18n.T("SuccessUserCreated", nil))
		return
	}

	// Classic path: the admin supplies the initial password.
	if body.Password == "" {
		sendError(w, "ValidationError", "Password is required unless deliver_setup_link or generate_one_time_password is set", http.StatusBadRequest, nil)
		return
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

// RestoreUser handles POST /api/v1/users/{id}/restore
func (h *UserHandler) RestoreUser(w http.ResponseWriter, r *http.Request) {
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
	if err := h.coreService.RestoreUser(r.Context(), uint(id)); err != nil {
		log.Printf("Error restoring user: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found or not soft-deleted", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to restore user", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "User restored successfully")
}

// accountStateAction is the shared handler body for the admin account-state
// transitions (ADR-025). transition performs the state change.
func (h *UserHandler) accountStateAction(w http.ResponseWriter, r *http.Request, okMessage string, transition func(ctx context.Context, adminID, userID uint) error) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	// A global admin must not suspend / lock themselves out of admin access.
	if uint(id) == admin.UserID {
		sendError(w, "BadRequest", "Cannot change your own account state", http.StatusBadRequest, nil)
		return
	}
	if err := transition(r.Context(), admin.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, okMessage)
}

// SuspendUser handles POST /api/v1/users/{id}/suspend.
func (h *UserHandler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User suspended", h.coreService.SuspendUser)
}

// ReactivateUser handles POST /api/v1/users/{id}/reactivate.
func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "User reactivated", h.coreService.ReactivateUser)
}

// RequirePasswordReset handles POST /api/v1/users/{id}/require-password-reset.
func (h *UserHandler) RequirePasswordReset(w http.ResponseWriter, r *http.Request) {
	h.accountStateAction(w, r, "Password reset required", h.coreService.RequirePasswordReset)
}

// ResendSetupLink handles POST /api/v1/users/{id}/resend-setup-link (ADR-028). It
// reissues the user's account_setup link (superseding any prior one) and re-delivers
// it, returning the delivery outcome — including the link itself in out-of-band mode.
func (h *UserHandler) ResendSetupLink(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	res, err := h.coreService.ResendAccountSetupLink(r.Context(), uint(id), admin.UserID)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "limit") || strings.Contains(msg, "wait"):
			status = http.StatusTooManyRequests
		case strings.Contains(msg, "base_url") || strings.Contains(msg, "suspended"):
			status = http.StatusBadRequest
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, res, "Setup link resent")
}
