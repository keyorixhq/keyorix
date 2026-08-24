// connect_grants_proxy.go — server-side endpoints backing RemoteStorage's
// ListConnectRefGrantsByConnector/ListConnectRefGrants (Keyorix Connect
// per-reference grants, ADR-045; backlog #527). (CreateConnectRefGrantProxy/
// DeleteConnectRefGrantProxy were deleted — G80 liveness sweep found no live
// caller for either; see docs/g80-remediation-notes.md.)
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
// These two routes (registered in server/http/router.go under
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
	"log"
	"net/http"
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

