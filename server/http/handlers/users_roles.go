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
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	roles, err := h.coreService.GetUserRolesByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting roles for user %d: %v", userID, err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
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

// canReadRBACStateFor reports whether actor may view TARGET user's RBAC state
// (effective permissions or project memberships): either the actor IS the target
// (own-profile read), or the actor holds roles.read (global scope) — the same
// admin-tier gate GetUserRolesForUser already requires for a user's role list
// (#141), and the tier this codebase treats as "may manage/inspect access" rather
// than the much broader, nearly-universally-held users.read. G84.
func (h *UsersRolesHandler) canReadRBACStateFor(r *http.Request, actor *middleware.UserContext, targetUserID uint) bool {
	if actor.UserID == targetUserID {
		return true
	}
	allowed, err := h.coreService.AuthorizePrincipal(r.Context(), actor.ActorKind(), actor.PrincipalID(), "roles.read", core.Scope{})
	if err != nil {
		log.Printf("Error checking roles.read for RBAC-state read (actor=%d target=%d): %v", actor.UserID, targetUserID, err)
		return false
	}
	return allowed
}

// apiPermission is one entry in a user's effective-permission view.
type apiPermission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// GetUserPermissionsForUser handles GET /api/v1/users/{id}/permissions — the user's
// effective permission set (the de-duplicated union across all assigned roles). The
// "what can this user do" view for the dashboard and access reviews.
//
// This discloses a TARGET user's full effective RBAC state, which is a much bigger
// disclosure than the route's group-level users.read gate implies (users.read is held
// by nearly every seeded role, so it lets any project member reconnoiter an arbitrary
// other user's complete permission set — privilege-escalation targeting material).
// Require self OR roles.read: the same roles.read tier GetUserRolesForUser already
// requires for the sibling roles-list view (#141), which restricts this data to the
// personas that actually manage access (system_admin/system_auditor/project_admin).
func (h *UsersRolesHandler) GetUserPermissionsForUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	if !h.canReadRBACStateFor(r, actor, userID) {
		sendError(w, "Forbidden", "You may not view another user's permissions", http.StatusForbidden, nil)
		return
	}

	perms, err := h.coreService.GetUserPermissionsByID(r.Context(), userID)
	if err != nil {
		log.Printf("Error getting permissions for user %d: %v", userID, err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
		} else {
			sendError(w, "InternalError", "Failed to get user permissions", http.StatusInternalServerError, nil)
		}
		return
	}

	apiPerms := make([]apiPermission, 0, len(perms))
	for _, p := range perms {
		apiPerms = append(apiPerms, apiPermission{Name: p.Name, Description: p.Description, Resource: p.Resource, Action: p.Action})
	}
	sendSuccess(w, map[string]interface{}{"permissions": apiPerms}, "")
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
//
// Same disclosure class as GetUserPermissionsForUser above (G84): the group-wide
// users.read gate lets any project member enumerate an arbitrary other user's full
// project-membership/role footprint. Same fix — self OR roles.read.
func (h *UsersRolesHandler) GetUserMembershipsForUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	userID, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}

	if !h.canReadRBACStateFor(r, actor, userID) {
		sendError(w, "Forbidden", "You may not view another user's memberships", http.StatusForbidden, nil)
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
func (h *UsersRolesHandler) UpdateUserRoles(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
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
	if err := h.coreService.SetUserRoles(r.Context(), actor.UserID, userID, req.RoleIDs, scope); err != nil {
		log.Printf("Error setting roles for user %d: %v", userID, err)
		if strings.Contains(err.Error(), errNotFound) {
			sendError(w, "NotFound", errUserNotFound, http.StatusNotFound, nil)
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
