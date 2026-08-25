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
// break-glass ACTIVATION policy decision (policy-enabled check, project-
// affiliation check, emergency-role containment checks, TTL clamping, the
// actual JIT role grant) is made here; all of that stays entirely in the
// CALLING server's own internal/core.KeyorixCore, exactly as it does against a
// local backend. The existing human-facing /api/v1/projects/{id}/break-glass
// routes (server/http/handlers/break_glass.go, CatalogHandler.ActivateBreakGlass/
// ListBreakGlassActivations/RevokeBreakGlass) are NOT reused for this proxy: they
// run this server's OWN core.ActivateBreakGlass/RevokeBreakGlass against the HTTP
// caller's own identity, which is the wrong semantics for a raw storage-primitive
// passthrough whose caller already ran all of that on the downstream side.
//
// One exception: RevokeBreakGlassActivationProxy is NOT a thin passthrough (see
// its own doc). A prior version of this comment claimed the role-removal
// side effect of a revoke "travels through its own separate proxied call
// chain" — that claim was false (the chain's wire route was never registered,
// #1511) and the raw passthrough it justified left revoked activations with a
// still-live role grant and no audit trail. The handler now performs the
// state guard + role removal + audit inline itself.
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
	"github.com/keyorixhq/keyorix/internal/core"
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
// /api/v1/system/break-glass/{id}/revoke.
//
// FALSE justification, found and fixed (G80 documented-exception re-verification
// sweep): this handler used to call storage.RevokeBreakGlassActivation ALONE, on
// the theory that the offsetting role-removal effect "travels through its own
// separate proxied call chain" (core.RevokeBreakGlass's own RemoveUserRole step).
// That chain does not exist end-to-end: core.RevokeBreakGlass's RemoveUserRole
// call, for a project-scoped role, resolves to RemoteStorage.RemoveRole POSTing
// to /api/v1/rbac/remove-role — a route that was never registered
// (remote_wire_route_coverage_test.go's knownMissingRoutes, #1511). Under
// storage.type: remote, that means core.RevokeBreakGlass could never actually
// complete a revoke with a live role grant at all; this raw proxy — independently
// reachable by anyone holding system.write, per #1542's router-group reasoning —
// was the ONLY path that succeeded, and it left the emergency role grant LIVE in
// user_roles (the table RBAC actually reads) while reporting the activation
// revoked, with no audit event. Fixed by making the proxy self-contained: it now
// performs the same effects core.RevokeBreakGlass would (state guard, role
// removal, conditional revoke, audit), inline, with no new wire hop — mirroring
// the precedent this same #1542 campaign already set for
// AssignRoleWithExpiryProxy/RemoveAllProjectRoleGrantsProxy on this same
// route group's gate (RequireNodeCredentialOrPermission at the time; that
// OR-arm is since removed — ADR-085, Accepted, 2026-08-25). It deliberately
// does NOT call
// core.RevokeBreakGlass directly: that function wraps storage.ErrBreakGlassNotActive
// in a new plain-text error rather than propagating it via %w, which would break
// this route's wire contract (breakGlassNotActiveCode, which
// RemoteStorage.RevokeBreakGlassActivation's client depends on to reconstruct the
// sentinel) — the raw conditional-UPDATE call and its existing error translation
// are kept exactly as they were; only the missing role-removal and audit steps
// were added around it.
//
// The missing /api/v1/rbac/remove-role route itself (#1511) is a separate,
// broader fix — internal/core.RemoveUserRole's OTHER project-scoped callers (SSO
// deprovisioning, project-member removal, access-review revocation, invitation
// cleanup, the direct RBAC handler, the gRPC role service) are equally affected
// under storage.type: remote — tracked there, not fixed here.
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
	// G80 documented-exception re-verification sweep (2026-08-25): this
	// handler was already touched by this same campaign (the FIXED entry
	// above, "actually revoke role") but kept trusting the wire's
	// revoked_by for the role-removal actor, the persisted RevokedBy, and the
	// audit event -- a non-repudiation break letting any system.write holder
	// revoke an emergency access grant while attributing it to an arbitrary
	// user ID. Revocation authority here is a human decision, same as
	// CreateInvitationProxy's actorID(r) fix.
	revokedBy := actorID(r)
	if revokedBy == 0 {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "revoking a break-glass activation requires an attributable, authenticated human caller")
		return
	}

	activation, err := h.coreService.Storage().GetBreakGlassActivation(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "break-glass activation not found")
			return
		}
		log.Printf("break-glass proxy: revoke activation: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}

	// Fast-path guard BEFORE touching the role grant, mirroring core.RevokeBreakGlass's
	// own ordering: without this, a stale/duplicate revoke replayed against an
	// ALREADY-revoked activation would still remove RoleID from UserID even if that
	// same role had since been re-granted for an unrelated, legitimate reason — the
	// conditional UPDATE below only protects the STATE TRANSITION from a concurrent
	// double-revoke race, not this sequential case.
	if activation.State != core.BreakGlassActive {
		writeRemoteAPIError(w, http.StatusConflict, breakGlassNotActiveCode, coreStorage.ErrBreakGlassNotActive.Error())
		return
	}

	// Remove the grant early — best-effort, mirroring core.RevokeBreakGlass: it may
	// already be gone (auto-expired, or a racing revoke's own removal already ran);
	// only a genuine storage failure aborts here, since proceeding to mark the
	// record revoked while removal itself failed would leave the grant LIVE in
	// user_roles but reported revoked everywhere else.
	scope := coreStorage.Scope{ProjectID: activation.ProjectID}
	if err := h.coreService.RemoveUserRole(r.Context(), revokedBy, activation.UserID, activation.RoleID, scope); err != nil && !errors.Is(err, coreStorage.ErrRoleNotAssigned) {
		log.Printf("break-glass proxy: revoke activation: role removal failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}

	if err := h.coreService.Storage().RevokeBreakGlassActivation(r.Context(), uint(id), revokedBy, body.RevokedAt); err != nil {
		if errors.Is(err, coreStorage.ErrBreakGlassNotActive) {
			writeRemoteAPIError(w, http.StatusConflict, breakGlassNotActiveCode, coreStorage.ErrBreakGlassNotActive.Error())
			return
		}
		log.Printf("break-glass proxy: revoke activation failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	h.coreService.LogBreakGlassRevoked(r.Context(), revokedBy, activation.ProjectID, activation.ID, activation.UserID, activation.RoleID, activation.RoleName)
	writeRemoteAPISuccess(w, map[string]bool{"revoked": true})
}
