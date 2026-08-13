// retention_proxy.go — server-side endpoints backing RemoteStorage's
// data-retention/purge-sweep storage primitives (finding #520):
// PurgeDeletedSecretsBefore, DeleteAnomalyAlertsBefore,
// DeleteClosedAccessReviewsBefore, DeleteExpiredBreakGlassBefore,
// DeleteResolvedAccessRequestsBefore (remote_secrets.go); DeleteExpiredRoleGrants
// (remote_rbac.go); DeleteExpiredShareRecords (remote_sharing.go);
// PurgeDeletedUsersBefore/PurgeDeletedProjectsBefore/
// PurgeDeletedEnvironmentsBefore/ListUsersInStateBefore (remote_users.go).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its scheduled retention/purge/lifecycle-sweep storage calls to whichever
// upstream server it's configured against, through these routes (registered in
// server/http/router.go under /api/v1/system/retention, gated on the existing
// system.read/system.write RBAC permissions — the SAME credential a RemoteStorage
// client already needs for every other proxied call, so this introduces no new
// privilege class). Mirrors dynamic_secrets_proxy.go/login_attempts_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives the
// ADR-032/ADR-033/A.5.18/A.5.34 schedulers (internal/core/purge.go,
// data_retention.go, jit_access.go, account_state.go) already use against a local
// backend — NO retention POLICY decision (which window applies, whether a legal
// hold blocks the sweep, which rows are "in flight" and therefore excluded) is
// made here; all of that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend. There is
// no competing human-facing HTTP surface for any of these eleven methods to avoid
// (unlike groups/machine-identities, these are purely internal scheduler-driven
// primitives), so — unlike several proxies before this one — there is no
// "don't reuse the human-facing route" caveat to document.
//
// Atomicity note: every one of these eleven local (GORM) implementations already
// resolves its "gather eligible rows, then delete/return them" work in ONE
// storage.Storage method call, either as a single SQL statement (e.g.
// PurgeDeletedEnvironmentsBefore, DeleteAnomalyAlertsBefore, ListUsersInStateBefore)
// or as several statements wrapped in the LOCAL backend's own db.Transaction
// (e.g. PurgeDeletedSecretsBefore's node+version+edge cascade,
// DeleteExpiredRoleGrants' gather-then-delete-then-report). Proxying each as a
// single HTTP round trip preserves that guarantee exactly: the transaction (where
// one exists) runs entirely inside the upstream server's own process, on its own
// database, in response to this ONE request — RemoteStorage.WithTransaction being
// a no-op passthrough (internal/storage/store/remote_transaction.go) is irrelevant
// here, because none of these eleven methods ever needed to SPAN multiple
// RemoteStorage calls inside one client-side transaction in the first place (unlike
// WebAuthn's counter race, Machine Identities' state-transition invariant, or
// Secret Dependencies' cycle check, which each combined several separate storage
// calls under one lock). No new atomic primitive was needed for any of the eleven.
//
// Two methods return the deleted rows themselves, not just a count, because their
// CALLING core function writes one audit-log entry per removed row —
// DeleteExpiredRoleGrantsProxy (internal/core.RemoveExpiredRoleGrants writes
// role.expired per grant) and DeleteExpiredShareRecordsProxy
// (internal/core.RemoveExpiredShares writes share.expired per share). Both proxy
// handlers below return the full row set on the wire so that audit trail survives
// the storage.type: remote hop unchanged, rather than degrading to a bare count a
// caller could not use to log anything.
//
// Timezone note: every method here compares a caller-supplied `before`/`ack_before`/
// `unack_ceiling` timestamp against a time.Time column with a plain SQL `<`/`<=`
// operator (deleted_at, detected_at, closed_at, created_at, resolved_at,
// expires_at, account_state's created_at). GORM's SQLite driver formats a bound
// time.Time parameter's TEXT representation using THAT VALUE's OWN Location, not a
// canonical one — see dynamic_secrets_proxy.go's ListExpiredActiveLeasesProxy for
// the full empirical writeup of the resulting bug (a genuinely-expired row silently
// excluded because two different UTC-offset TEXT representations sort
// lexicographically out of instant order). Every decoded timestamp below is
// therefore converted with .Local() before being handed to storage.Storage, so its
// TEXT representation is formatted in the SAME Location this server's own rows were
// written in — matching the one convention every other time.Time comparison in this
// codebase already relies on (time.Now(), never time.Now().UTC()).
//
// Response envelope: like the other proxies, these do NOT use the package's
// generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Shared single-`before` request body ---

// retentionBeforeBody is the wire body for every purge/sweep route below that
// takes a single cutoff timestamp.
type retentionBeforeBody struct {
	Before time.Time `json:"before"`
}

// maxRetentionCutoffSkew bounds how far into the future a caller-supplied `before`
// cutoff may sit relative to this server's own clock (#G44). Every route in this
// file is a retention/expiry SWEEP — "purge/strip everything already older than
// before" — so without SOME bound, a caller (holding the same system.read/
// system.write credential any RemoteStorage node already needs) could set `before`
// far in the future (e.g. decades out) and instantly purge every soft-deleted row,
// or strip role grants/shares that have not actually expired yet, system-wide. A
// generous 24h allowance is kept for legitimate near-future padding — every proxy
// handler's own test suite already exercises a +1h cutoff as valid input (a caller
// pre-emptively sweeping things that will have expired shortly) — while still
// rejecting the actual attack shape (a wildly distant cutoff).
const maxRetentionCutoffSkew = 24 * time.Hour

// validateRetentionCutoff rejects a `before` timestamp that sits more than
// maxRetentionCutoffSkew in the future relative to this server's clock.
func validateRetentionCutoff(before time.Time) error {
	if before.After(time.Now().Add(maxRetentionCutoffSkew)) {
		return fmt.Errorf("before must not be in the future")
	}
	return nil
}

func decodeRetentionBeforeBody(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	var body retentionBeforeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return time.Time{}, false
	}
	if body.Before.IsZero() {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "before is required")
		return time.Time{}, false
	}
	if err := validateRetentionCutoff(body.Before); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return time.Time{}, false
	}
	// See the package doc's timezone note: re-express in this server's own process
	// Location before any storage-layer comparison.
	return body.Before.Local(), true
}

// --- SecretHandler: PurgeDeletedSecretsBefore (ADR-032) ---

// PurgeDeletedSecretsBeforeProxy handles POST /api/v1/system/retention/secrets/purge.
func (h *SecretHandler) PurgeDeletedSecretsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().PurgeDeletedSecretsBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge deleted secrets failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// --- AuditHandler: DeleteAnomalyAlertsBefore (#489, ISO A.5.33) ---

// anomalyAlertsPurgeBody is the wire body for
// POST /api/v1/system/retention/anomaly-alerts/purge. Either field may be the
// zero time.Time — matching DeleteAnomalyAlertsBefore's own contract, a zero
// value disables that clause entirely rather than being misread as "purge
// everything before year 1" (see local_purge.go's DeleteAnomalyAlertsBefore doc).
type anomalyAlertsPurgeBody struct {
	AckBefore    time.Time `json:"ack_before"`
	UnackCeiling time.Time `json:"unack_ceiling"`
}

// DeleteAnomalyAlertsBeforeProxy handles POST
// /api/v1/system/retention/anomaly-alerts/purge.
func (h *AuditHandler) DeleteAnomalyAlertsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	var body anomalyAlertsPurgeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	// A zero value disables the corresponding clause (see the type doc) — only a
	// genuinely-set field needs the future-cutoff bound.
	if !body.AckBefore.IsZero() {
		if err := validateRetentionCutoff(body.AckBefore); err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "ack_before: "+err.Error())
			return
		}
	}
	if !body.UnackCeiling.IsZero() {
		if err := validateRetentionCutoff(body.UnackCeiling); err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "unack_ceiling: "+err.Error())
			return
		}
	}
	// See the package doc's timezone note. .Local() on an already-zero time.Time
	// leaves it zero (IsZero() depends only on the represented instant, not the
	// Location), so DeleteAnomalyAlertsBefore's own "zero disables this clause"
	// contract is preserved for whichever field the caller left unset.
	n, err := h.coreService.Storage().DeleteAnomalyAlertsBefore(r.Context(), body.AckBefore.Local(), body.UnackCeiling.Local())
	if err != nil {
		log.Printf("retention proxy: purge anomaly alerts failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// --- CatalogHandler: access-reviews / break-glass / access-requests / projects /
// environments purges. CatalogHandler already owns the human-facing CRUD (and,
// for access-reviews/break-glass, the sibling CRUD proxy) for every one of these
// subsystems (catalog.go's Project/Environment CRUD, invitations.go's
// AccessRequest CRUD, access_review_campaigns_proxy.go, break_glass_proxy.go), so
// it is the natural owner of each subsystem's own retention sweep too. ---

// DeleteClosedAccessReviewsBeforeProxy handles POST
// /api/v1/system/retention/access-reviews/purge-closed.
func (h *CatalogHandler) DeleteClosedAccessReviewsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	campaigns, items, err := h.coreService.Storage().DeleteClosedAccessReviewsBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge closed access reviews failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"campaigns_purged": campaigns, "items_purged": items})
}

// DeleteExpiredBreakGlassBeforeProxy handles POST
// /api/v1/system/retention/break-glass/purge-expired.
func (h *CatalogHandler) DeleteExpiredBreakGlassBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().DeleteExpiredBreakGlassBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge expired break-glass failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// DeleteResolvedAccessRequestsBeforeProxy handles POST
// /api/v1/system/retention/access-requests/purge-resolved.
func (h *CatalogHandler) DeleteResolvedAccessRequestsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	requests, approvals, err := h.coreService.Storage().DeleteResolvedAccessRequestsBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge resolved access requests failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"requests_purged": requests, "approvals_purged": approvals})
}

// PurgeDeletedProjectsBeforeProxy handles POST
// /api/v1/system/retention/projects/purge.
func (h *CatalogHandler) PurgeDeletedProjectsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().PurgeDeletedProjectsBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge deleted projects failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// PurgeDeletedEnvironmentsBeforeProxy handles POST
// /api/v1/system/retention/environments/purge.
func (h *CatalogHandler) PurgeDeletedEnvironmentsBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().PurgeDeletedEnvironmentsBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge deleted environments failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// --- RBACHandler: DeleteExpiredRoleGrants (JIT access expiry) ---

// DeleteExpiredRoleGrantsProxy handles POST
// /api/v1/system/retention/role-grants/purge-expired. Returns the full removed
// storage.RoleAssignment rows — not just a count — because the calling server's
// own internal/core.RemoveExpiredRoleGrants writes one role.expired audit event
// per grant (principal type/ID, role, scope) using exactly this data; degrading
// to a bare count here would silently drop that audit trail under
// storage.type: remote. storage.RoleAssignment already carries full snake_case
// json tags (internal/core/storage/interface.go) — no separate wire DTO struct is
// needed, unlike models.DynamicSecretConfig's precedent.
func (h *RBACHandler) DeleteExpiredRoleGrantsProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	removed, err := h.coreService.Storage().DeleteExpiredRoleGrants(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge expired role grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if removed == nil {
		removed = []coreStorage.RoleAssignment{}
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"removed": removed})
}

// --- ShareHandler: DeleteExpiredShareRecords (JIT access expiry) ---

// DeleteExpiredShareRecordsProxy handles POST
// /api/v1/system/retention/share-records/purge-expired. Returns the full removed
// models.ShareRecord rows — not just a count — because the calling server's own
// internal/core.RemoveExpiredShares writes one share.expired audit event per
// share (secret ID, recipient kind/ID) using exactly this data; degrading to a
// bare count here would silently drop that audit trail under storage.type:
// remote. models.ShareRecord carries no json tags of its own, so this marshals
// the model directly — matching remote_sharing.go's existing
// CreateShareRecord/GetShareRecord/UpdateShareRecord precedent (which already
// round-trips *models.ShareRecord the same way), rather than introducing a new
// wire DTO struct for the one field this subsystem's other proxied calls didn't
// need one for.
func (h *ShareHandler) DeleteExpiredShareRecordsProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	removed, err := h.coreService.Storage().DeleteExpiredShareRecords(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge expired share records failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if removed == nil {
		removed = []*models.ShareRecord{}
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"removed": removed})
}

// --- UserHandler: PurgeDeletedUsersBefore (ADR-032) / ListUsersInStateBefore
// (ADR-025 stale-account warnings) ---

// userRetentionProxyWire mirrors models.User's fields the stale-account report
// (internal/core.StaleAccounts, surfaced by GET /users/stale) actually reads —
// models.User carries no json tags of its own (PasswordHash's `json:"-"`
// excepted, and never populated here), so marshaling it directly would send Go
// field names verbatim and silently drop every underscore-separated field on
// decode, exactly the #496-class bug documented at length in remote_users.go.
// Deliberately the SAME field set/tags as remote_users.go's userWireResponse (the
// client-side decode counterpart) so ListUsersInStateBeforeProxy's response
// round-trips through the exact same decoder every other User-returning
// RemoteStorage call already uses.
type userRetentionProxyWire struct {
	ID                  uint       `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	DisplayName         string     `json:"display_name"`
	Active              bool       `json:"active"`
	AccountState        string     `json:"account_state"`
	ExternalID          string     `json:"external_id"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
	DeletedAt           *time.Time `json:"deleted_at"`
	LoginLockedUntil    *time.Time `json:"login_locked_until,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LoginLockoutCount   int        `json:"login_lockout_count"`
	LastFailedLoginAt   *time.Time `json:"last_failed_login_at"`
}

func newUserRetentionProxyWire(u *models.User) userRetentionProxyWire {
	w := userRetentionProxyWire{
		ID:                  u.ID,
		Username:            u.Username,
		Email:               u.Email,
		DisplayName:         u.DisplayName,
		Active:              u.IsActive,
		AccountState:        u.AccountState,
		ExternalID:          u.ExternalID,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		LastLoginAt:         u.LastLoginAt,
		LoginLockedUntil:    u.LoginLockedUntil,
		FailedLoginAttempts: u.FailedLoginAttempts,
		LoginLockoutCount:   u.LoginLockoutCount,
		LastFailedLoginAt:   u.LastFailedLoginAt,
	}
	if u.DeletedAt.Valid {
		t := u.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

// PurgeDeletedUsersBeforeProxy handles POST /api/v1/system/retention/users/purge.
func (h *UserHandler) PurgeDeletedUsersBeforeProxy(w http.ResponseWriter, r *http.Request) {
	before, ok := decodeRetentionBeforeBody(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().PurgeDeletedUsersBefore(r.Context(), before)
	if err != nil {
		log.Printf("retention proxy: purge deleted users failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"purged": n})
}

// ListUsersInStateBeforeProxy handles GET
// /api/v1/system/retention/users/stale?state=<state>&before=<RFC3339Nano>. Backs
// the calling server's OWN stale-account warning sweep
// (internal/core.StaleAccounts) against this server's real storage backend — a
// READ, not a delete, so it is gated system.read (see router.go) unlike every
// other route in this file.
func (h *UserHandler) ListUsersInStateBeforeProxy(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "state query parameter is required")
		return
	}
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "before query parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339Nano, beforeStr)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "before must be an RFC3339 timestamp")
		return
	}
	// Unlike every other route in this file, a future `before` here is legitimate:
	// this is a READ (stale-account WARNING report), not a purge, and "list users
	// who will still be in this state as of tomorrow" is valid usage — no
	// "not in the future" bound applies (see TestListUsersInStateBeforeProxy_WithUsers_S11).
	// See the package doc's timezone note.
	rows, err := h.coreService.Storage().ListUsersInStateBefore(r.Context(), state, before.Local())
	if err != nil {
		log.Printf("retention proxy: list stale users failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]userRetentionProxyWire, 0, len(rows))
	for _, u := range rows {
		wire = append(wire, newUserRetentionProxyWire(u))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"users": wire})
}
