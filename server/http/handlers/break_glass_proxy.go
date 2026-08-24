// break_glass_proxy.go — server-side endpoints backing RemoteStorage's
// break-glass storage primitives (finding #519): GetBreakGlassActivation/
// ListBreakGlassActivations/RevokeBreakGlassActivation. (CreateBreakGlassActivationProxy/
// UpdateBreakGlassActivationProxy were deleted — G80 liveness sweep found no live
// caller for either; see docs/g80-remediation-notes.md.)
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its break-glass storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/break-glass, gated on the existing system.read/system.write RBAC
// permissions — the SAME credential a RemoteStorage client already needs for every
// other proxied call, e.g. full user CRUD, project-invitation CRUD (#507),
// project-membership CRUD (#511), so this introduces no new privilege class).
// Mirrors project_memberships_proxy.go/invitations_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/break_glass.go already uses against a local backend — NO
// break-glass POLICY decision (policy-enabled check, project-affiliation check,
// emergency-role containment checks, TTL clamping, the actual JIT role grant) is
// made here; all of that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend. The
// existing human-facing /api/v1/projects/{id}/break-glass routes
// (server/http/handlers/break_glass.go, CatalogHandler.ActivateBreakGlass/
// ListBreakGlassActivations/RevokeBreakGlass) are NOT reused for this proxy: they
// run this server's OWN core.ActivateBreakGlass/RevokeBreakGlass against the HTTP
// caller's own identity, which is the wrong semantics for a raw storage-primitive
// passthrough whose caller already ran all of that on the downstream side.
//
// Atomicity note — the critical property for this subsystem (docs/security/
// BUGS.md #104, PR #670): RevokeBreakGlassActivation is a single conditional
// `UPDATE ... WHERE id = ? AND state = 'active'` (not a read-then-write) —
// RevokeBreakGlassActivationProxy calls that same primitive directly, so a
// losing racer against a concurrent revoke gets storage.ErrBreakGlassNotActive
// rather than silently double-revoking.
//
// Response envelope: like project_memberships_proxy.go/invitations_proxy.go,
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses (its APIResponse/APIError
// types).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// breakGlassActivationProxyWire mirrors models.BreakGlassActivation's fields
// exactly (snake_case) — a GORM model with no json tags of its own beyond the
// struct-literal defaults, so — matching membershipProxyWire's/
// invitationProxyWire's reasoning — every field is named explicitly here rather
// than relying on a direct marshal of the model.
type breakGlassActivationProxyWire struct {
	ID            uint       `json:"id"`
	ProjectID     uint       `json:"project_id"`
	UserID        uint       `json:"user_id"`
	RoleID        uint       `json:"role_id"`
	RoleName      string     `json:"role_name"`
	Justification string     `json:"justification"`
	State         string     `json:"state"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedBy     uint       `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

func newBreakGlassActivationProxyWire(a *models.BreakGlassActivation) breakGlassActivationProxyWire {
	return breakGlassActivationProxyWire{
		ID:            a.ID,
		ProjectID:     a.ProjectID,
		UserID:        a.UserID,
		RoleID:        a.RoleID,
		RoleName:      a.RoleName,
		Justification: a.Justification,
		State:         a.State,
		ExpiresAt:     a.ExpiresAt,
		CreatedAt:     a.CreatedAt,
		RevokedBy:     a.RevokedBy,
		RevokedAt:     a.RevokedAt,
	}
}

func (w breakGlassActivationProxyWire) toModel() *models.BreakGlassActivation {
	return &models.BreakGlassActivation{
		ID:            w.ID,
		ProjectID:     w.ProjectID,
		UserID:        w.UserID,
		RoleID:        w.RoleID,
		RoleName:      w.RoleName,
		Justification: w.Justification,
		State:         w.State,
		ExpiresAt:     w.ExpiresAt,
		CreatedAt:     w.CreatedAt,
		RevokedBy:     w.RevokedBy,
		RevokedAt:     w.RevokedAt,
	}
}

// breakGlassContainmentAdminRoleNames mirrors internal/core's unexported
// installAdminRoleNames (rbac_management.go) — duplicated here because this
// handler cannot call KeyorixCore's unexported containment logic directly and
// there is no exported equivalent. Keep in sync if that list ever changes.
var breakGlassContainmentAdminRoleNames = []string{"super_admin", "admin", "system_admin"}

// breakGlassNotActiveCode is the machine-readable error code
// RevokeBreakGlassActivationProxy returns when the conditional
// `WHERE state = 'active'` update matches no row (storage.ErrBreakGlassNotActive,
// local_break_glass.go) — the wire-level signal RemoteStorage.
// RevokeBreakGlassActivation uses to reconstruct that sentinel.
const breakGlassNotActiveCode = "BREAK_GLASS_NOT_ACTIVE"

// GetBreakGlassActivationProxy handles GET /api/v1/system/break-glass/{id}.
func (h *CatalogHandler) GetBreakGlassActivationProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidActivationID)
		return
	}
	a, err := h.coreService.Storage().GetBreakGlassActivation(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "break-glass activation not found")
			return
		}
		log.Printf("break-glass proxy: get activation failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newBreakGlassActivationProxyWire(a))
}

// ListBreakGlassActivationsProxy handles GET
// /api/v1/system/break-glass?project_id=X.
func (h *CatalogHandler) ListBreakGlassActivationsProxy(w http.ResponseWriter, r *http.Request) {
	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id query parameter is required")
		return
	}
	projectID, err := strconv.ParseUint(projectIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return
	}
	rows, err := h.coreService.Storage().ListBreakGlassActivations(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("break-glass proxy: list activations failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]breakGlassActivationProxyWire, 0, len(rows))
	for _, a := range rows {
		wire = append(wire, newBreakGlassActivationProxyWire(a))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"activations": wire})
}

// breakGlassRevokeProxyRequest is RevokeBreakGlassActivationProxy's request body.
type breakGlassRevokeProxyRequest struct {
	RevokedBy uint      `json:"revoked_by"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevokeBreakGlassActivationProxy handles POST
// /api/v1/system/break-glass/{id}/revoke. Calls storage.RevokeBreakGlassActivation
// DIRECTLY — the SAME single conditional `UPDATE ... WHERE id = ? AND
// state = 'active'` local_break_glass.go's RevokeBreakGlassActivation performs —
// rather than a client-side "GET, check state, then PUT" sequence, which would
// reopen the exact double-revoke TOCTOU race that conditional write exists to
// close. One HTTP round trip maps to one atomic server-side conditional UPDATE.
func (h *CatalogHandler) RevokeBreakGlassActivationProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidActivationID)
		return
	}
	var body breakGlassRevokeProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.RevokedBy == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "revoked_by is required")
		return
	}
	if err := h.coreService.Storage().RevokeBreakGlassActivation(r.Context(), uint(id), body.RevokedBy, body.RevokedAt); err != nil {
		if errors.Is(err, coreStorage.ErrBreakGlassNotActive) {
			writeRemoteAPIError(w, http.StatusConflict, breakGlassNotActiveCode, coreStorage.ErrBreakGlassNotActive.Error())
			return
		}
		log.Printf("break-glass proxy: revoke activation failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"revoked": true})
}
