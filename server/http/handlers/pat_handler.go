// pat_handler.go — HTTP handlers for self-service Personal Access Tokens (ADR-027).
//
// Routes (all under /api/v1/auth/tokens, authenticated, self-scoped):
//
//	GET    /auth/tokens        — list the caller's tokens (never returns the secret)
//	POST   /auth/tokens        — create a token (returns the raw token once)
//	DELETE /auth/tokens/{id}   — revoke one of the caller's tokens (204 No Content)
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// PATHandler handles personal-access-token HTTP requests.
type PATHandler struct {
	coreService *core.KeyorixCore
}

// NewPATHandler constructs a PATHandler.
func NewPATHandler(coreService *core.KeyorixCore) *PATHandler {
	return &PATHandler{coreService: coreService}
}

// patResponse is the safe DTO — omits TokenHash; carries only the display prefix.
type patResponse struct {
	ID          uint    `json:"id"`
	Name        string  `json:"name"`
	TokenPrefix string  `json:"token_prefix"`
	Revoked     bool    `json:"revoked"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   *string `json:"expires_at"`
	LastUsedAt  *string `json:"last_used_at"`
}

func toPATResponse(t *models.PersonalAccessToken) patResponse {
	resp := patResponse{
		ID:          t.ID,
		Name:        t.Name,
		TokenPrefix: t.TokenPrefix,
		Revoked:     t.Revoked,
		CreatedAt:   t.CreatedAt.UTC().Format(time.RFC3339),
	}
	if t.ExpiresAt != nil {
		v := t.ExpiresAt.UTC().Format(time.RFC3339)
		resp.ExpiresAt = &v
	}
	if t.LastUsedAt != nil {
		v := t.LastUsedAt.UTC().Format(time.RFC3339)
		resp.LastUsedAt = &v
	}
	return resp
}

// ListPATs handles GET /auth/tokens.
func (h *PATHandler) ListPATs(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	tokens, err := h.coreService.ListOwnPATs(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list tokens", http.StatusInternalServerError, nil)
		return
	}
	out := make([]patResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toPATResponse(t))
	}
	sendSuccess(w, out, "")
}

type createPATRequestBody struct {
	Name      string  `json:"name"`
	ExpiresAt *string `json:"expires_at"` // RFC3339; omit/null for a non-expiring token
}

// CreatePAT handles POST /auth/tokens. The raw token is returned exactly once.
func (h *PATHandler) CreatePAT(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body createPATRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	var expiresAt *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *body.ExpiresAt)
		if err != nil {
			sendError(w, "BadRequest", "Invalid expires_at (want RFC3339)", http.StatusBadRequest, nil)
			return
		}
		expiresAt = &t
	}

	result, err := h.coreService.CreateOwnPAT(r.Context(), userCtx.UserID, body.Name, expiresAt)
	if err != nil {
		sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
		return
	}

	resp := toPATResponse(result.Token)
	w.WriteHeader(http.StatusCreated)
	// The plaintext token is included once here and never again.
	sendSuccess(w, map[string]interface{}{
		"token": result.PlainToken,
		"pat":   resp,
	}, "Token created — copy it now, it will not be shown again")
}

// RevokePAT handles DELETE /auth/tokens/{id}.
func (h *PATHandler) RevokePAT(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		sendError(w, "BadRequest", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RevokeOwnPAT(r.Context(), userCtx.UserID, uint(id)); err != nil {
		sendError(w, "NotFound", "Token not found", http.StatusNotFound, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
