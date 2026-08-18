// connector_project_bindings_proxy.go — server-side endpoints backing
// RemoteStorage's GetConnectorProjectBinding/CreateConnectorProjectBinding
// (ADR-082 branch 2). See connect_grants_proxy.go's package doc (backlog #527) for
// why a downstream Keyorix server booted with storage.type: remote needs a real
// server endpoint here rather than a stub: the calling boot-time resolution logic
// (server/main.go) treats any error from these primitives as an unresolvable
// connector and fails boot, so a stub would fail boot on every connector on every
// remote-storage node with Connect configured — the exact failure shape #527 fixed
// once already for ConnectRefGrant.
//
// These routes (registered in server/http/router.go under
// /api/v1/system/connector-project-bindings, gated on the existing system.write RBAC
// permission — the same credential a RemoteStorage client already needs for every
// other proxied call, so this introduces no new privilege class) are thin
// passthroughs onto the SAME storage.Storage primitives server/main.go's boot-time
// resolution already uses against a local backend — no policy decision (which
// project a name resolves to, whether a mismatch is a rename) is made here.
//
// Response envelope: like connect_grants_proxy.go, these do NOT use the package's
// generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// connectorProjectBindingProxyWire mirrors models.ConnectorProjectBinding's fields
// exactly (snake_case) — the wire shape
// internal/storage/store/remote_connector_project_bindings.go's
// connectorProjectBindingWire sends/expects.
type connectorProjectBindingProxyWire struct {
	ID          uint      `json:"id"`
	Connector   string    `json:"connector"`
	ProjectID   uint      `json:"project_id"`
	ProjectName string    `json:"project_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func newConnectorProjectBindingProxyWire(b *models.ConnectorProjectBinding) connectorProjectBindingProxyWire {
	return connectorProjectBindingProxyWire{
		ID:          b.ID,
		Connector:   b.Connector,
		ProjectID:   b.ProjectID,
		ProjectName: b.ProjectName,
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
	}
}

// isConnectorProjectBindingNotFound reports whether err is the "not found"
// sentinel LocalStorage's GetConnectorProjectBinding uses.
func isConnectorProjectBindingNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// GetConnectorProjectBindingProxy handles GET
// /api/v1/system/connector-project-bindings/{connector}.
func (h *AuthHandler) GetConnectorProjectBindingProxy(w http.ResponseWriter, r *http.Request) {
	connector := chi.URLParam(r, "connector")
	if connector == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "connector is required")
		return
	}
	binding, err := h.coreService.Storage().GetConnectorProjectBinding(r.Context(), connector)
	if err != nil {
		if isConnectorProjectBindingNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "connector project binding not found")
			return
		}
		log.Printf("connector-project-bindings proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newConnectorProjectBindingProxyWire(binding))
}

// connectorProjectBindingCreateBody is the wire body for POST
// /api/v1/system/connector-project-bindings. The server assigns ID/CreatedAt/
// UpdatedAt, so the body carries only the fields the caller has already resolved.
type connectorProjectBindingCreateBody struct {
	Connector   string `json:"connector"`
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`
}

// CreateConnectorProjectBindingProxy handles POST
// /api/v1/system/connector-project-bindings. The caller (the downstream server's
// own boot-time resolution) has already resolved the connector's project: name to
// an ID; this is a raw persist, no re-resolution.
func (h *AuthHandler) CreateConnectorProjectBindingProxy(w http.ResponseWriter, r *http.Request) {
	var body connectorProjectBindingCreateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Connector == "" || body.ProjectID == 0 || body.ProjectName == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "connector, project_id, and project_name are required")
		return
	}
	created, err := h.coreService.Storage().CreateConnectorProjectBinding(r.Context(), &models.ConnectorProjectBinding{
		Connector:   body.Connector,
		ProjectID:   body.ProjectID,
		ProjectName: body.ProjectName,
	})
	if err != nil {
		log.Printf("connector-project-bindings proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newConnectorProjectBindingProxyWire(created))
}
