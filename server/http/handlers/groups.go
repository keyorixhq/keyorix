package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// GroupHandler handles group HTTP requests.
type GroupHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

var defaultGroupHandler *GroupHandler

// NewGroupHandler constructs a GroupHandler.
func NewGroupHandler(coreService *core.KeyorixCore) (*GroupHandler, error) {
	return &GroupHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

func groupToAPIResponse(g *models.Group) map[string]interface{} {
	return map[string]interface{}{
		"id":          g.ID,
		"name":        g.Name,
		"description": g.Description,
	}
}

// ListGroups handles GET /api/v1/groups
func (h *GroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	groups, err := h.coreService.ListGroups(r.Context())
	if err != nil {
		log.Printf("Error listing groups: %v", err)
		sendError(w, "InternalError", "Failed to list groups", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupToAPIResponse(g))
	}
	sendSuccess(w, map[string]interface{}{
		"groups": out,
		"total":  len(out),
	}, "")
}

// CreateGroup handles POST /api/v1/groups
func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name        string `json:"name" validate:"required,min=1,max=255"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	created, err := h.coreService.CreateGroup(r.Context(), &core.CreateGroupRequest{
		Name:        body.Name,
		Description: body.Description,
	})
	if err != nil {
		log.Printf("Error creating group: %v", err)
		if strings.Contains(err.Error(), "unique") || strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			sendError(w, "ConflictError", "Group name already exists", http.StatusConflict, nil)
			return
		}
		sendError(w, "InternalError", "Failed to create group", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, groupToAPIResponse(created), "Group created successfully")
}

// GetGroup handles GET /api/v1/groups/{id}
func (h *GroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	g, err := h.coreService.GetGroup(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting group: %v", err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), i18n.T("ErrorGroupNotFound", nil)) {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to get group", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, groupToAPIResponse(g), "")
}

// UpdateGroup handles PUT /api/v1/groups/{id}
func (h *GroupHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Name        string `json:"name" validate:"omitempty,min=1,max=255"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&body); err != nil {
		sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	updated, err := h.coreService.UpdateGroup(r.Context(), &core.UpdateGroupRequest{
		ID:          uint(id),
		Name:        body.Name,
		Description: body.Description,
	})
	if err != nil {
		log.Printf("Error updating group: %v", err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), i18n.T("ErrorGroupNotFound", nil)) {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to update group", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, groupToAPIResponse(updated), "Group updated successfully")
}

// DeleteGroup handles DELETE /api/v1/groups/{id}
func (h *GroupHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteGroup(r.Context(), uint(id)); err != nil {
		log.Printf("Error deleting group: %v", err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), i18n.T("ErrorGroupNotFound", nil)) {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to delete group", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetGroupMembers handles GET /api/v1/groups/{id}/members
func (h *GroupHandler) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	members, err := h.coreService.GetGroupMembers(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing group members: %v", err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), i18n.T("ErrorGroupNotFound", nil)) {
			sendError(w, "NotFound", "Group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to list group members", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(members))
	for _, u := range members {
		out = append(out, userToAPIResponse(u))
	}
	sendSuccess(w, map[string]interface{}{
		"members": out,
		"total":   len(out),
	}, "")
}

// AddGroupMember handles POST /api/v1/groups/{id}/members
func (h *GroupHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	groupID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		UserID uint `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 {
		sendError(w, "ValidationError", "user_id is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.AddUserToGroup(r.Context(), body.UserID, uint(groupID)); err != nil {
		log.Printf("Error adding group member: %v", err)
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "User or group not found", http.StatusNotFound, nil)
			return
		}
		sendError(w, "InternalError", "Failed to add group member", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"group_id": uint(groupID),
		"user_id":  body.UserID,
	}, "Member added to group")
}

// RemoveGroupMember handles DELETE /api/v1/groups/{id}/members/{userId}
func (h *GroupHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	idStr := chi.URLParam(r, "id")
	groupID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	userIDStr := chi.URLParam(r, "userId")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RemoveUserFromGroup(r.Context(), uint(userID), uint(groupID)); err != nil {
		log.Printf("Error removing group member: %v", err)
		sendError(w, "InternalError", "Failed to remove group member", http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// InitCoreHandlers wires user and group HTTP handlers to the application core.
// It returns the same instances used by package-level user handlers (ListUsers, etc.).
func InitCoreHandlers(cs *core.KeyorixCore) (*UserHandler, *GroupHandler, error) {
	uh, err := NewUserHandler(cs)
	if err != nil {
		return nil, nil, err
	}
	gh, err := NewGroupHandler(cs)
	if err != nil {
		return nil, nil, err
	}
	defaultUserHandler = uh
	defaultGroupHandler = gh
	return uh, gh, nil
}
