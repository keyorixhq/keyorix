// misc_remote_proxy.go — server-side endpoints backing four unrelated
// RemoteStorage storage-primitive gaps grouped under finding #531 (a grab-bag of
// small, low-to-moderate-severity fixes filed together for convenience — each
// sub-fix below is independent):
//
//  1. Dormant-access activity lookup (LastUserSecretActivity/
//     LastUserRoleManagementActivity/LastUserSecretDeletionActivity/
//     LastUserSecretReadActivity/LastUserSecretWriteActivity,
//     internal/storage/store/remote_access_activity.go): registered under
//     /api/v1/system/access-activity, gated system.read.
//  2. GetSecretIncludingDeleted (internal/storage/store/remote_secrets.go):
//     registered under /api/v1/system/secrets/{id}/including-deleted, gated
//     system.read — unblocks ScopeFromDeletedSecretParam ahead of POST
//     /secrets/{id}/restore, which 404'd on every request under
//     storage.type: remote.
//  3. ListSharesByOwner and ListSharesByUser (internal/storage/store/
//     remote_sharing.go): registered under /api/v1/system/shares/by-owner/
//     {ownerID} and /api/v1/system/shares/by-user/{userID}, gated system.read
//     — both halves core.ListSharesByUser (backing GET /api/v1/shares and
//     gRPC ShareService.ListShares) needs. ListSharesByOwner hard-failed with
//     no fallback; ListSharesByUser 404'd against a human-facing route
//     (/api/v1/users/{id}/shares) that was never registered at all — see
//     remote_sharing.go's doc for why that route could never have existed.
//  4. CreateUserWithRoleGrants (internal/storage/store/remote_users.go):
//     registered under /api/v1/system/users/with-role-grants, gated
//     system.write — the ONE atomic primitive in this file (see its own doc
//     below): preserves ADR-028's all-or-nothing create-user+role-grants
//     transaction across the storage.type: remote HTTP hop, the same
//     "new atomic primitive, not a naive multi-call proxy" pattern established
//     by AdvanceWebAuthnCredentialCounter (#517) and
//     TransitionMachineIdentityState (#518).
//
// Every handler here is a thin passthrough onto the identical storage.Storage
// primitive the local (LocalStorage-backed) path already uses — no POLICY
// decision (which activity counts as "dormant", the restore scope check, the
// role-grant validation/escalation ceiling) is made here; that stays entirely
// in the CALLING server's own internal/core.KeyorixCore, exactly as it does
// against a local backend. All four reuse the SAME system.read/system.write
// RBAC tier every other RemoteStorage proxy already needs — no new privilege
// class.
//
// Response envelope: like every other proxy in this package, these do NOT use
// the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- 1. Access-activity proxy (UserHandler) ---

// accessActivityKindToMethod maps the route's static "kind" segment to the
// storage.Storage method it backs. A single handler function serves all five
// GET routes (they differ only in which underlying event-type bucket the
// LocalStorage-backed upstream queries), keeping this file from repeating the
// same query-param parsing/response-encoding boilerplate five times.
type accessActivityLookup func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error)

var accessActivityLookups = map[string]accessActivityLookup{
	"secret": func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error) {
		return h.coreService.Storage().LastUserSecretActivity(r.Context(), projectID)
	},
	"role-management": func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error) {
		return h.coreService.Storage().LastUserRoleManagementActivity(r.Context(), projectID)
	},
	"secret-deletion": func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error) {
		return h.coreService.Storage().LastUserSecretDeletionActivity(r.Context(), projectID)
	},
	"secret-read": func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error) {
		return h.coreService.Storage().LastUserSecretReadActivity(r.Context(), projectID)
	},
	"secret-write": func(h *UserHandler, r *http.Request, projectID uint) (map[uint]time.Time, error) {
		return h.coreService.Storage().LastUserSecretWriteActivity(r.Context(), projectID)
	},
}

// accessActivityProxy handles GET /api/v1/system/access-activity/{kind}, where
// kind is one of secret/role-management/secret-deletion/secret-read/secret-write
// (registered as five separate static routes in router.go — chi has no
// wildcard-segment dispatch here, so the kind is baked into which route matched,
// not parsed from the path; this shared function is called once per route with
// its own kind literal).
func (h *UserHandler) accessActivityProxy(w http.ResponseWriter, r *http.Request, kind string) {
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
	lookup := accessActivityLookups[kind]
	activity, err := lookup(h, r, uint(projectID))
	if err != nil {
		log.Printf("access-activity proxy: %s lookup failed: %v", kind, err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make(map[string]time.Time, len(activity))
	for userID, t := range activity {
		wire[strconv.FormatUint(uint64(userID), 10)] = t
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"activity": wire})
}

// LastUserSecretActivityProxy handles GET /api/v1/system/access-activity/secret.
func (h *UserHandler) LastUserSecretActivityProxy(w http.ResponseWriter, r *http.Request) {
	h.accessActivityProxy(w, r, "secret")
}

// LastUserRoleManagementActivityProxy handles GET
// /api/v1/system/access-activity/role-management.
func (h *UserHandler) LastUserRoleManagementActivityProxy(w http.ResponseWriter, r *http.Request) {
	h.accessActivityProxy(w, r, "role-management")
}

// LastUserSecretDeletionActivityProxy handles GET
// /api/v1/system/access-activity/secret-deletion.
func (h *UserHandler) LastUserSecretDeletionActivityProxy(w http.ResponseWriter, r *http.Request) {
	h.accessActivityProxy(w, r, "secret-deletion")
}

// LastUserSecretReadActivityProxy handles GET
// /api/v1/system/access-activity/secret-read.
func (h *UserHandler) LastUserSecretReadActivityProxy(w http.ResponseWriter, r *http.Request) {
	h.accessActivityProxy(w, r, "secret-read")
}

// LastUserSecretWriteActivityProxy handles GET
// /api/v1/system/access-activity/secret-write.
func (h *UserHandler) LastUserSecretWriteActivityProxy(w http.ResponseWriter, r *http.Request) {
	h.accessActivityProxy(w, r, "secret-write")
}

// --- 2. GetSecretIncludingDeleted proxy (SecretHandler) ---

// GetSecretIncludingDeletedProxy handles GET
// /api/v1/system/secrets/{id}/including-deleted. Calls
// storage.Storage.GetSecretIncludingDeleted directly (an Unscoped lookup that
// reaches a soft-deleted row) rather than the human-facing GetSecret handler,
// which scopes out soft-deleted rows by design. The response marshals
// models.SecretNode directly (see remote_secrets.go's doc for why that's safe
// for this Go-to-Go internal wire), wrapped in a small envelope.
func (h *SecretHandler) GetSecretIncludingDeletedProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid secret id")
		return
	}
	secret, err := h.coreService.Storage().GetSecretIncludingDeleted(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "secret not found")
			return
		}
		log.Printf("secrets proxy: get secret including deleted failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"secret": secret})
}

// --- 3. ListSharesByOwner / ListSharesByUser proxy (ShareHandler) ---

// ListSharesByOwnerProxy handles GET /api/v1/system/shares/by-owner/{ownerID}.
// The response marshals []*models.ShareRecord directly (no json tags of its
// own beyond the embedded gorm.DeletedAt — the same Go-to-Go round-trip choice
// already used by DeleteExpiredShareRecordsProxy for the identical type),
// wrapped in a small envelope.
func (h *ShareHandler) ListSharesByOwnerProxy(w http.ResponseWriter, r *http.Request) {
	ownerID, err := strconv.ParseUint(chi.URLParam(r, "ownerID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid owner id")
		return
	}
	shares, err := h.coreService.Storage().ListSharesByOwner(r.Context(), uint(ownerID))
	if err != nil {
		log.Printf("shares proxy: list shares by owner failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"shares": shares})
}

// ListSharesByUserProxy handles GET /api/v1/system/shares/by-user/{userID} —
// the "received as recipient" half of core.ListSharesByUser, mirroring
// ListSharesByOwnerProxy immediately above exactly (same response envelope,
// same lack of a POLICY decision).
func (h *ShareHandler) ListSharesByUserProxy(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	shares, err := h.coreService.Storage().ListSharesByUser(r.Context(), uint(userID))
	if err != nil {
		log.Printf("shares proxy: list shares by user failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"shares": shares})
}

// --- 4. CreateUserWithRoleGrants proxy (UserHandler) — the atomic primitive ---

// createUserWithRoleGrantsProxyBody mirrors remote_users.go's
// createUserWithRoleGrantsWireRequest exactly.
type createUserWithRoleGrantsProxyBody struct {
	Username          string          `json:"username"`
	Email             string          `json:"email"`
	DisplayName       string          `json:"display_name"`
	PasswordHash      string          `json:"password_hash"`
	IsActive          bool            `json:"is_active"`
	AccountState      string          `json:"account_state"`
	PasswordChangedAt *time.Time      `json:"password_changed_at,omitempty"`
	Grants            []roleGrantBody `json:"grants"`
}

// roleGrantBody mirrors storage.RoleGrant's fields exactly.
type roleGrantBody struct {
	RoleID        uint `json:"role_id"`
	ProjectID     uint `json:"project_id"`
	EnvironmentID uint `json:"environment_id"`
}

// duplicateEmailProxyCode is the machine-readable error code
// CreateUserWithRoleGrantsProxy returns when the upstream's own partial
// unique-index rejection (uniq_users_email_active, #117) fires — the wire-level
// signal RemoteStorage.CreateUserWithRoleGrants uses to reconstruct the same
// storage.ErrDuplicateEmail sentinel core.CreateUserWithAssignments' own
// errors.Is check depends on, mirroring legalHoldAlreadyActiveCode's identical
// two-package-duplicated-constant pattern (server/http/handlers/legal_hold_proxy.go
// / internal/storage/store/remote_legal_hold.go).
const duplicateEmailProxyCode = "DUPLICATE_EMAIL"

// bcryptHashPrefixes are the recognizable prefixes of a golang.org/x/crypto/bcrypt
// hash ($2a$/$2b$/$2y$ cost-and-salt header). CreateUserWithRoleGrantsProxy uses
// this as a cheap format sanity check — see its doc for why full password-policy
// validation cannot happen at this layer.
var bcryptHashPrefixes = [...]string{"$2a$", "$2b$", "$2y$"}

// isPlausibleBcryptHash reports whether s is shaped like a bcrypt hash
// (correct prefix and length; golang.org/x/crypto/bcrypt hashes are always 60
// bytes). This cannot confirm the hash was produced by a real password-policy
// check — it only rejects empty/garbage/non-hash values.
func isPlausibleBcryptHash(s string) bool {
	if len(s) != 60 {
		return false
	}
	for _, p := range bcryptHashPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// CreateUserWithRoleGrantsProxy handles POST /api/v1/system/users/with-role-grants
// — the ONE handler in this file that is not a plain CRUD passthrough.
//
// It calls storage.Storage.CreateUserWithRoleGrants directly
// (h.coreService.Storage() reaches the identical primitive this server's own
// local admin "create user with project assignments" path uses via
// core.CreateUserWithAssignments), which performs the user INSERT and every
// role-grant INSERT inside ONE real DB transaction (ADR-028) — server-side,
// inside this single request, against THIS server's own storage. That is the
// critical property a downstream (spoke) server depends on for correctness
// under storage.type: remote: a failure partway through (bad role ID, a
// SoD-policy violation, a duplicate email) must roll back the ENTIRE create,
// never leaving a user committed with only some of its intended grants — see
// remote_users.go's CreateUserWithRoleGrants doc for the full "why a naive
// two-call proxy would reopen this" reasoning.
//
// #G79: the calling server's own core.CreateUserWithAssignments DOES run
// every validation/escalation-ceiling/SoD check before ever reaching
// storage.Storage — but that only holds for a caller that goes through the
// calling server's human-facing flow first. This HTTP route is reachable
// directly by anyone holding system.write (the same broad permission every
// other RemoteStorage proxy needs), so a caller that skips the calling
// server's core layer entirely and hits this endpoint straight would
// otherwise mint a fully-active account with an attacker-chosen grant set
// and no SoD gate. core.ValidateRoleGrantAuthority re-applies the same
// escalation-ceiling + SoD checks CreateUserWithAssignments uses, against
// actorID(r) (the authenticated caller of THIS request). It cannot
// re-validate password strength (only a pre-computed hash crosses this
// wire, by design — see remote_users.go's doc on why the plaintext never
// leaves the downstream node for this atomic path), so
// isPlausibleBcryptHash is a narrower, format-only backstop instead.
func (h *UserHandler) CreateUserWithRoleGrantsProxy(w http.ResponseWriter, r *http.Request) {
	var body createUserWithRoleGrantsProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Username == "" || body.Email == "" || body.PasswordHash == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "username, email, and password_hash are required")
		return
	}
	if !isPlausibleBcryptHash(body.PasswordHash) {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "password_hash is not a recognizable bcrypt hash")
		return
	}
	grants := make([]storage.RoleGrant, 0, len(body.Grants))
	for _, g := range body.Grants {
		grants = append(grants, storage.RoleGrant{
			RoleID: g.RoleID,
			Scope:  storage.Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID},
		})
	}
	if err := h.coreService.ValidateRoleGrantAuthority(r.Context(), actorID(r), isMachineActor(r), grants); err != nil {
		// Fail closed: an underlying storage error while evaluating authority is
		// indistinguishable from a genuine refusal at this layer, and reporting it
		// as anything other than a flat denial risks leaking whether a specific
		// role/grant combination exists — same fail-closed choice
		// checkBreakGlassRoleContainment makes for RoleSetHasPermission's error path.
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", clientSafe(err))
		return
	}
	// #1642: this endpoint bypasses core.CreateUser/buildUserForCreate
	// entirely (by design — see the doc comment above), so it needs its own
	// fold, mirroring ValidateRoleGrantAuthority's own re-implementation of
	// core's other checks for this wire path. Computed independently from
	// body.Username/body.Email, never trusted from the wire.
	foldedUsername, ferr := identity.NewFoldedName(body.Username)
	if ferr != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid username: "+ferr.Error())
		return
	}
	foldedEmail, ferr := identity.NewFoldedName(body.Email)
	if ferr != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid email: "+ferr.Error())
		return
	}
	user := &models.User{
		Username:          body.Username,
		UsernameFolded:    foldedUsername.Folded(),
		Email:             body.Email,
		EmailFolded:       foldedEmail.Folded(),
		DisplayName:       body.DisplayName,
		PasswordHash:      body.PasswordHash,
		IsActive:          body.IsActive,
		AccountState:      body.AccountState,
		PasswordChangedAt: body.PasswordChangedAt,
	}
	created, err := h.coreService.Storage().CreateUserWithRoleGrants(r.Context(), user, grants)
	if err != nil {
		// #858/#859: a duplicate-email race (uniq_users_email_active, #117) is a
		// validation-shaped outcome, not a server-side failure — classify it 409,
		// matching the same duplicate-email handling core.CreateUserWithAssignments
		// applies against a local backend.
		if errors.Is(err, storage.ErrDuplicateEmail) {
			writeRemoteAPIError(w, http.StatusConflict, duplicateEmailProxyCode, storage.ErrDuplicateEmail.Error())
			return
		}
		log.Printf("users proxy: create user with role grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newUserRetentionProxyWire(created))
}
