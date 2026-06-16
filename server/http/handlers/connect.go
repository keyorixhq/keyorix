// connect.go — HTTP handlers for Keyorix Connect (ADR-043): list configured
// external-store connectors and proxy an authorized, audited read-through of a
// secret. Both are gated by connect.read in the router (ADR-044); values are never
// persisted.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

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

// ListRefGrants returns all per-reference grants (ADR-045) for management.
func (h *ConnectHandler) ListRefGrants(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	grants, err := h.coreService.ListConnectRefGrants(r.Context())
	if err != nil {
		sendError(w, "ConnectError", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(grants))
	for _, g := range grants {
		out = append(out, map[string]interface{}{
			"id":         g.ID,
			"role_id":    g.RoleID,
			"connector":  g.Connector,
			"ref_prefix": g.RefPrefix,
			"created_at": g.CreatedAt,
		})
	}
	sendSuccess(w, map[string]interface{}{"grants": out}, "")
}

// CreateRefGrant adds a per-reference grant (ADR-045).
func (h *ConnectHandler) CreateRefGrant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		RoleID    uint   `json:"role_id"`
		Connector string `json:"connector"`
		RefPrefix string `json:"ref_prefix"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidParameter", "invalid JSON body", http.StatusBadRequest, nil)
		return
	}
	g, err := h.coreService.CreateConnectRefGrant(r.Context(), userCtx.UserID, body.RoleID, body.Connector, body.RefPrefix)
	if err != nil {
		sendError(w, "ConnectError", err.Error(), http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"id":         g.ID,
		"role_id":    g.RoleID,
		"connector":  g.Connector,
		"ref_prefix": g.RefPrefix,
	}, "Connect ref-grant created")
}

// DeleteRefGrant removes a per-reference grant by id.
func (h *ConnectHandler) DeleteRefGrant(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		sendError(w, "InvalidParameter", "invalid grant id", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteConnectRefGrant(r.Context(), userCtx.UserID, uint(id)); err != nil {
		sendError(w, "ConnectError", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"id": id}, "Connect ref-grant deleted")
}
