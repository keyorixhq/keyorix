package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

type updateUserRolesRequest struct {
	RoleIDs []uint `json:"role_ids" validate:"omitempty"`
	// ProjectID/EnvironmentID scope the replacement (0 = global). Only the
	// user's roles at this exact scope are replaced; others are left intact.
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

type apiRole struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}

// UsersRolesHandler handles user role management HTTP requests.
type UsersRolesHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewUsersRolesHandler creates a new UsersRolesHandler.
func NewUsersRolesHandler(coreService *core.KeyorixCore) *UsersRolesHandler {
	return &UsersRolesHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

// GetUserRolesForUser handles GET /api/v1/users/{id}/roles
func (h *UsersRolesHandler) GetUserRolesForUser(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	roles, err := h.coreService.GetUserRolesByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting roles for user %d: %v", userID, err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get user roles", http.StatusInternalServerError, nil)
		}
		return
	}

	apiRoles := make([]apiRole, 0, len(roles))
	for _, role := range roles {
		apiRoles = append(apiRoles, apiRole{ID: role.ID, Name: role.Name})
	}
	sendSuccess(w, map[string]interface{}{"roles": apiRoles}, "")
}

// apiUserMembership is one row of a user's project-assignments view (ADR-025).
type apiUserMembership struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
	Role        string `json:"role"`
	State       string `json:"state"`
}

// GetUserMembershipsForUser handles GET /api/v1/users/{id}/memberships (ADR-025) —
// the user's project memberships with project name, role, and lifecycle state,
// powering the per-user assignments table on the detail page.
func (h *UsersRolesHandler) GetUserMembershipsForUser(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	memberships, err := h.coreService.ListUserProjectMemberships(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting memberships for user %d: %v", userID, err)
		sendError(w, "InternalError", "Failed to get user memberships", http.StatusInternalServerError, nil)
		return
	}

	// Resolve project names once for the rows.
	nameByID := map[uint]string{}
	if projects, perr := h.coreService.ListProjects(r.Context()); perr == nil {
		for _, p := range projects {
			nameByID[p.ID] = p.Name
		}
	} else {
		log.Printf("Error listing projects for membership names: %v", perr)
	}

	out := make([]apiUserMembership, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, apiUserMembership{
			ProjectID:   m.ProjectID,
			ProjectName: nameByID[m.ProjectID],
			Role:        m.Role,
			State:       m.State,
		})
	}
	sendSuccess(w, map[string]interface{}{"memberships": out}, "")
}

// UpdateUserRoles handles PUT /api/v1/users/{id}/roles — full role replacement.
func (h *UsersRolesHandler) UpdateUserRoles(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	var req updateUserRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&req); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	if len(req.RoleIDs) > 0 {
		allRoles, err := h.coreService.Storage().ListRoles(r.Context())
		if err != nil {
			log.Printf("Error listing roles for validation: %v", err)
			sendError(w, "InternalError", "Failed to validate role IDs", http.StatusInternalServerError, nil)
			return
		}
		existingIDs := make(map[uint]bool, len(allRoles))
		for _, role := range allRoles {
			existingIDs[role.ID] = true
		}
		for _, id := range req.RoleIDs {
			if !existingIDs[id] {
				sendError(w, "NotFound", fmt.Sprintf("Role ID %d does not exist", id), http.StatusBadRequest, nil)
				return
			}
		}
	}

	scope := core.Scope{ProjectID: req.ProjectID, EnvironmentID: req.EnvironmentID}
	if err := h.coreService.SetUserRoles(r.Context(), userID, req.RoleIDs, scope); err != nil {
		log.Printf("Error setting roles for user %d: %v", userID, err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to update user roles", http.StatusInternalServerError, nil)
		}
		return
	}

	roles, err := h.coreService.GetUserRolesByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error fetching updated roles for user %d: %v", userID, err)
		sendError(w, "InternalError", "Roles updated but failed to retrieve updated list", http.StatusInternalServerError, nil)
		return
	}

	apiRoles := make([]apiRole, 0, len(roles))
	for _, role := range roles {
		apiRoles = append(apiRoles, apiRole{ID: role.ID, Name: role.Name})
	}
	sendSuccess(w, map[string]interface{}{"roles": apiRoles}, "Roles updated successfully")
}
