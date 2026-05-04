// groups_handler.go — GroupHandler struct, constructor, and group CRUD.
//
// ListGroups, CreateGroup, GetGroup, UpdateGroup, DeleteGroup.
// For member operations and InitCoreHandlers see groups_members.go.
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
	sendSuccess(w, map[string]interface{}{"groups": out, "total": len(out)}, "")
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
