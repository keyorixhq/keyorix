// secret_version_comments.go — HTTP handlers for secret version comments.
//
// Three endpoints:
//
//	POST   /api/v1/secrets/{id}/versions/{versionId}/comments
//	GET    /api/v1/secrets/{id}/versions/{versionId}/comments
//	DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}
package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// SecretVersionCommentHandler handles secret version comment requests.
type SecretVersionCommentHandler struct {
	coreService *core.KeyorixCore
}

// NewSecretVersionCommentHandler creates a new SecretVersionCommentHandler.
func NewSecretVersionCommentHandler(coreService *core.KeyorixCore) *SecretVersionCommentHandler {
	return &SecretVersionCommentHandler{coreService: coreService}
}

// createVersionCommentRequest is the JSON body for POST .../comments.
type createVersionCommentRequest struct {
	Comment string `json:"comment"`
}

// CreateComment handles POST /api/v1/secrets/{id}/versions/{versionId}/comments.
func (h *SecretVersionCommentHandler) CreateComment(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secretID, ok := mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	versionID, ok := mustParseUintParam(w, r, "versionId", "InvalidParameter", "Invalid version ID")
	if !ok {
		return
	}

	var body createVersionCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}

	if body.Comment == "" {
		sendError(w, "ValidationError", "comment is required", http.StatusBadRequest, nil)
		return
	}

	comment, err := h.coreService.CreateSecretVersionComment(r.Context(), core.CreateVersionCommentRequest{
		SecretID:  secretID,
		VersionID: versionID,
		Comment:   body.Comment,
		UserID:    userCtx.UserID,
		Username:  userCtx.Username,
	})
	if err != nil {
		log.Printf("Error creating version comment: %v", err)
		sendError(w, "InternalError", "Failed to create comment", http.StatusInternalServerError, nil)
		return
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"comment": comment}, "Comment created successfully")
}

// ListComments handles GET /api/v1/secrets/{id}/versions/{versionId}/comments.
func (h *SecretVersionCommentHandler) ListComments(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	_, ok = mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	versionID, ok := mustParseUintParam(w, r, "versionId", "InvalidParameter", "Invalid version ID")
	if !ok {
		return
	}

	comments, err := h.coreService.ListSecretVersionComments(r.Context(), versionID)
	if err != nil {
		log.Printf("Error listing version comments: %v", err)
		sendError(w, "InternalError", "Failed to list comments", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, map[string]interface{}{"comments": comments, "total": len(comments)}, "")
}

// DeleteComment handles DELETE /api/v1/secrets/{id}/versions/{versionId}/comments/{commentId}.
func (h *SecretVersionCommentHandler) DeleteComment(w http.ResponseWriter, r *http.Request) {
	_, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	_, ok = mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}
	_, ok = mustParseUintParam(w, r, "versionId", "InvalidParameter", "Invalid version ID")
	if !ok {
		return
	}
	commentID, ok := mustParseUintParam(w, r, "commentId", "InvalidParameter", "Invalid comment ID")
	if !ok {
		return
	}

	if err := h.coreService.DeleteSecretVersionComment(r.Context(), commentID); err != nil {
		log.Printf("Error deleting version comment: %v", err)
		sendError(w, "InternalError", "Failed to delete comment", http.StatusInternalServerError, nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
