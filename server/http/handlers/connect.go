// connect.go — HTTP handlers for Keyorix Connect (ADR-043): list configured
// external-store connectors and proxy an authorized, audited read-through of a
// secret. Both are gated by secrets.read in the router; values are never persisted.
package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ConnectHandler serves the /connect federation endpoints.
type ConnectHandler struct {
	coreService *core.KeyorixCore
}

// NewConnectHandler creates a connect handler.
func NewConnectHandler(coreService *core.KeyorixCore) *ConnectHandler {
	return &ConnectHandler{coreService: coreService}
}

// ListConnectors returns the configured connector names (discovery).
func (h *ConnectHandler) ListConnectors(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"connectors": h.coreService.ConnectConnectorNames()}, "")
}

// GetSecret proxies a read-through of ?ref=… from the named connector.
func (h *ConnectHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	name := chi.URLParam(r, "name")
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		sendError(w, "InvalidParameter", "ref query parameter is required", http.StatusBadRequest, nil)
		return
	}
	value, err := h.coreService.ReadFederatedSecret(r.Context(), userCtx.UserID, name, ref)
	if err != nil {
		// Unknown connector / disabled is a client error; backend failures surface as
		// a bad gateway since the upstream store is external.
		sendError(w, "ConnectError", err.Error(), http.StatusBadGateway, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"connector": name,
		"ref":       ref,
		"value":     value,
	}, "")
}
