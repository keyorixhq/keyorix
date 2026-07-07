// connect_grants_proxy.go — server-side endpoints backing RemoteStorage's
// ListConnectRefGrantsByConnector/ListConnectRefGrants/CreateConnectRefGrant/
// DeleteConnectRefGrant (Keyorix Connect per-reference grants, ADR-045; backlog
// #527).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) runs the
// SAME core.KeyorixCore as any other node. Its ReadFederatedSecret (the HTTP
// GetSecret handler and gRPC ConnectService.ReadSecret both call it unconditionally)
// calls connectRefAllowed (internal/core/connect.go), which calls
// ListConnectRefGrantsByConnector on EVERY federated read — regardless of whether
// the connector actually has any ref-grants configured. Before this fix, RemoteStorage
// hard-stubbed all four of these primitives, so connectRefAllowed failed closed and
// EVERY Keyorix Connect read failed on EVERY connector on any storage.type: remote
// node with Connect configured.
//
// These four routes (registered in server/http/router.go under
// /api/v1/system/connect-grants, gated on the existing system.read/system.write RBAC
// permissions — the SAME credential a RemoteStorage client already needs for every
// other proxied call, e.g. full user CRUD and the #510 setup-tokens proxy, so this
// introduces no new privilege class) are thin passthroughs onto the SAME
// storage.Storage primitives internal/core/connect.go already uses against a local
// backend — no Connect POLICY decision (role resolution, prefix/glob matching,
// expiry) is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore. This mirrors setup_tokens_proxy.go (#510) exactly.
//
// Response envelope: like setup_tokens_proxy.go/login_attempts_proxy.go, these do
// NOT use the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// connectRefGrantProxyWire mirrors models.ConnectRefGrant's fields exactly
// (snake_case) — the wire shape internal/storage/store/remote_rbac.go's
// connectRefGrantWire sends/expects, following setup_tokens_proxy.go's
// setupTokenProxyWire pattern (#510).
type connectRefGrantProxyWire struct {
	ID        uint       `json:"id"`
	RoleID    uint       `json:"role_id"`
	Connector string     `json:"connector"`
	RefPrefix string     `json:"ref_prefix"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func newConnectRefGrantProxyWire(g *models.ConnectRefGrant) connectRefGrantProxyWire {
	return connectRefGrantProxyWire{
		ID:        g.ID,
		RoleID:    g.RoleID,
		Connector: g.Connector,
		RefPrefix: g.RefPrefix,
		ExpiresAt: g.ExpiresAt,
		CreatedAt: g.CreatedAt,
	}
}

func connectRefGrantsProxyWireList(grants []*models.ConnectRefGrant) []connectRefGrantProxyWire {
	out := make([]connectRefGrantProxyWire, 0, len(grants))
	for _, g := range grants {
		out = append(out, newConnectRefGrantProxyWire(g))
	}
	return out
}

// ListConnectRefGrantsByConnectorProxy handles GET
// /api/v1/system/connect-grants/by-connector/{connector} — the exact filtered lookup
// connectRefAllowed performs on every federated read.
func (h *AuthHandler) ListConnectRefGrantsByConnectorProxy(w http.ResponseWriter, r *http.Request) {
	connector := chi.URLParam(r, "connector")
	if connector == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "connector is required")
		return
	}
	grants, err := h.coreService.Storage().ListConnectRefGrantsByConnector(r.Context(), connector)
	if err != nil {
		log.Printf("connect-grants proxy: list by connector failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, connectRefGrantsProxyWireList(grants))
}

// ListConnectRefGrantsProxy handles GET /api/v1/system/connect-grants.
func (h *AuthHandler) ListConnectRefGrantsProxy(w http.ResponseWriter, r *http.Request) {
	grants, err := h.coreService.Storage().ListConnectRefGrants(r.Context())
	if err != nil {
		log.Printf("connect-grants proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, connectRefGrantsProxyWireList(grants))
}

// connectRefGrantCreateBody is the wire body for POST /api/v1/system/connect-grants.
// The server assigns ID/CreatedAt, so the body carries only the mutable fields.
type connectRefGrantCreateBody struct {
	RoleID    uint       `json:"role_id"`
	Connector string     `json:"connector"`
	RefPrefix string     `json:"ref_prefix"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreateConnectRefGrantProxy handles POST /api/v1/system/connect-grants. The caller
// (the downstream server's own core.KeyorixCore.CreateConnectRefGrant) has already
// validated the role and connector exist; this is a raw persist, no policy decision.
func (h *AuthHandler) CreateConnectRefGrantProxy(w http.ResponseWriter, r *http.Request) {
	var body connectRefGrantCreateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.RoleID == 0 || body.Connector == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "role_id and connector are required")
		return
	}
	created, err := h.coreService.Storage().CreateConnectRefGrant(r.Context(), &models.ConnectRefGrant{
		RoleID:    body.RoleID,
		Connector: body.Connector,
		RefPrefix: body.RefPrefix,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		log.Printf("connect-grants proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newConnectRefGrantProxyWire(created))
}

// DeleteConnectRefGrantProxy handles DELETE /api/v1/system/connect-grants/{id}.
func (h *AuthHandler) DeleteConnectRefGrantProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid grant id")
		return
	}
	if err := h.coreService.Storage().DeleteConnectRefGrant(r.Context(), uint(id)); err != nil {
		log.Printf("connect-grants proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}
