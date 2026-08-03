// break_glass_proxy.go — server-side endpoints backing RemoteStorage's
// break-glass storage primitives (finding #519): CreateBreakGlassActivation/
// GetBreakGlassActivation/ListBreakGlassActivations/UpdateBreakGlassActivation/
// RevokeBreakGlassActivation.
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
// BUGS.md #104, PR #670): local_break_glass.go's CreateBreakGlassActivation relies
// on a REAL DB-level partial unique index (uniq_break_glass_active_project_user,
// ensureBreakGlassActiveIndex) scoped to state='active' to reject a second
// concurrent active activation for the same (project_id, user_id) — an
// `INSERT ... ON CONFLICT DO NOTHING` whose RowsAffected==0 is translated to
// storage.ErrBreakGlassAlreadyActive. CreateBreakGlassActivationProxy calls that
// SAME storage.Storage primitive directly against this server's own database, so
// that guarantee is a property of the upstream's own database and survives this
// HTTP hop unchanged — NOT a client-side "GET then POST" sequence, which would
// reopen exactly the TOCTOU race #104 closed. Similarly, RevokeBreakGlassActivation
// is a single conditional `UPDATE ... WHERE id = ? AND state = 'active'` (not a
// read-then-write) — RevokeBreakGlassActivationProxy calls that same primitive
// directly, so a losing racer against a concurrent revoke gets
// storage.ErrBreakGlassNotActive rather than silently double-revoking. Only
// UpdateBreakGlassActivationProxy is a plain unconditional Save (matching
// local_break_glass.go's own UpdateBreakGlassActivation semantics exactly — there
// is no conditional write to preserve there, mirroring
// UpdateDynamicSecretConfigProxy's precedent).
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

// breakGlassAlreadyActiveCode is the machine-readable error code
// CreateBreakGlassActivationProxy returns when the upstream's own DB-level
// partial-unique-index rejection (storage.ErrBreakGlassAlreadyActive,
// local_break_glass.go) fires — the wire-level signal
// RemoteStorage.CreateBreakGlassActivation uses to reconstruct the same sentinel
// core.ActivateBreakGlass's errors.Is check depends on, so that check-and-translate
// behavior is preserved across this HTTP hop and not silently downgraded to an
// opaque "failed to create activation" error.
const breakGlassAlreadyActiveCode = "BREAK_GLASS_ALREADY_ACTIVE"

// breakGlassNotActiveCode is the machine-readable error code
// RevokeBreakGlassActivationProxy returns when the conditional
// `WHERE state = 'active'` update matches no row (storage.ErrBreakGlassNotActive,
// local_break_glass.go) — the wire-level signal RemoteStorage.
// RevokeBreakGlassActivation uses to reconstruct that sentinel.
const breakGlassNotActiveCode = "BREAK_GLASS_NOT_ACTIVE"

// CreateBreakGlassActivationProxy handles POST /api/v1/system/break-glass. See
// the package doc for why this persists the caller's already-fully-built
// activation row as-is (a raw storage-layer create backed by a real DB-level
// unique-index race gate), not a re-run of ActivateBreakGlass's own business
// logic.
func (h *CatalogHandler) CreateBreakGlassActivationProxy(w http.ResponseWriter, r *http.Request) {
	var body breakGlassActivationProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.ProjectID == 0 || body.UserID == 0 || body.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id, user_id, and state are required")
		return
	}
	created, err := h.coreService.Storage().CreateBreakGlassActivation(r.Context(), body.toModel())
	if err != nil {
		if errors.Is(err, coreStorage.ErrBreakGlassAlreadyActive) {
			writeRemoteAPIError(w, http.StatusConflict, breakGlassAlreadyActiveCode, coreStorage.ErrBreakGlassAlreadyActive.Error())
			return
		}
		log.Printf("break-glass proxy: create activation failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newBreakGlassActivationProxyWire(created))
}

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

// UpdateBreakGlassActivationProxy handles PUT /api/v1/system/break-glass/{id}. A
// raw persist (storage.Storage.UpdateBreakGlassActivation is an unconditional
// full-row Save, matching LocalStorage's own semantics exactly — the actual
// atomicity guarantee for this subsystem lives in CreateBreakGlassActivation's
// unique-index insert and RevokeBreakGlassActivation's conditional update, both
// proxied separately below).
func (h *CatalogHandler) UpdateBreakGlassActivationProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidActivationID)
		return
	}
	var body breakGlassActivationProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateBreakGlassActivation(r.Context(), body.toModel()); err != nil {
		log.Printf("break-glass proxy: update activation failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
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
