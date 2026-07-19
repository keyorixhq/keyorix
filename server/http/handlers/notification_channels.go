// notification_channels.go — CRUD endpoints for runtime-managed outbound
// notification channels (webhook/slack/teams/email). All routes require the
// system.write permission (admin only).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// NotificationChannelHandler serves the notification-channel CRUD endpoints.
type NotificationChannelHandler struct {
	coreService *core.KeyorixCore
}

// NewNotificationChannelHandler constructs a NotificationChannelHandler.
func NewNotificationChannelHandler(coreService *core.KeyorixCore) *NotificationChannelHandler {
	return &NotificationChannelHandler{coreService: coreService}
}

// channelToAPI converts a NotificationChannel model to the API wire shape.
func channelToAPI(ch *models.NotificationChannel) map[string]interface{} {
	return map[string]interface{}{
		"id":         ch.ID,
		"name":       ch.Name,
		"type":       ch.Type,
		"enabled":    ch.Enabled,
		"url":        ch.URL,
		"email":      ch.Email,
		"events":     ch.Events,
		"created_by": ch.CreatedBy,
		"created_at": ch.CreatedAt,
		"updated_at": ch.UpdatedAt,
	}
}

// List handles GET /api/v1/notification-channels.
func (h *NotificationChannelHandler) List(w http.ResponseWriter, r *http.Request) {
	channels, err := h.coreService.ListNotificationChannels(r.Context())
	if err != nil {
		log.Printf("Error listing notification channels: %v", err)
		sendError(w, "InternalError", "Failed to list notification channels", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(channels))
	for _, ch := range channels {
		out = append(out, channelToAPI(ch))
	}
	sendSuccess(w, map[string]interface{}{"channels": out}, "")
}

// Create handles POST /api/v1/notification-channels.
func (h *NotificationChannelHandler) Create(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled *bool  `json:"enabled"`
		URL     string `json:"url"`
		Email   string `json:"email"`
		Events  string `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	ch := &models.NotificationChannel{
		Name:   body.Name,
		Type:   body.Type,
		URL:    body.URL,
		Email:  body.Email,
		Events: body.Events,
	}
	if body.Enabled != nil {
		ch.Enabled = *body.Enabled
	} else {
		ch.Enabled = true
	}
	created, err := h.coreService.CreateNotificationChannel(r.Context(), ch, u.Username)
	if err != nil {
		if isValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error creating notification channel: %v", err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendCreated(w, channelToAPI(created), "")
}

// Get handles GET /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	ch, err := h.coreService.GetNotificationChannel(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "Notification channel not found", http.StatusNotFound, nil)
			return
		}
		log.Printf("Error getting notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to get notification channel", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, channelToAPI(ch), "")
}

// Update handles PUT /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	updated, err := h.coreService.UpdateNotificationChannel(r.Context(), id, body)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "Notification channel not found", http.StatusNotFound, nil)
			return
		}
		if isValidationError(err) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		log.Printf("Error updating notification channel %d: %v", id, err)
		sendError(w, "InternalError", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, channelToAPI(updated), "")
}

// Delete handles DELETE /api/v1/notification-channels/{id}.
func (h *NotificationChannelHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := h.coreService.DeleteNotificationChannel(r.Context(), id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			sendError(w, "NotFound", "Notification channel not found", http.StatusNotFound, nil)
			return
		}
		log.Printf("Error deleting notification channel %d: %v", id, err)
		sendError(w, "InternalError", "Failed to delete notification channel", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"id": id, "deleted": true}, "")
}

// isValidationError reports whether the error comes from the core validation layer
// (as opposed to a storage/infrastructure error). Validation messages are
// short, human-readable strings crafted in validateNotificationChannel; they are
// safe to send back to the client verbatim.
func isValidationError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "notification channel") ||
		strings.HasPrefix(msg, "invalid notification")
}
