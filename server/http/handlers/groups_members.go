// groups_members.go — Group membership handlers and InitCoreHandlers.
//
// GetGroupMembers, AddGroupMember, RemoveGroupMember, InitCoreHandlers.
// For group CRUD see groups_handler.go.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

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
		if strings.Contains(err.Error(), "not found") {
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
	sendSuccess(w, map[string]interface{}{"members": out, "total": len(out)}, "")
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
	sendSuccess(w, map[string]interface{}{"group_id": uint(groupID), "user_id": body.UserID}, "Member added to group")
}

// RemoveGroupMember handles DELETE /api/v1/groups/{id}/members/{userId}
func (h *GroupHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
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
// Returns the same instances used by package-level user handlers (ListUsers, etc.).
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
