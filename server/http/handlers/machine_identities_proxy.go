// machine_identities_proxy.go — server-side endpoints backing RemoteStorage's
// machine-identity storage primitives (ADR-023/ADR-030/ADR-031, finding #518):
// CreateMachineIdentity/GetMachineIdentity/LockMachineIdentityForUpdate/
// UpdateMachineIdentity/TransitionMachineIdentityState/ListMachineIdentities/
// ListAllMachineIdentities/CountMachineIdentitiesByClassification/
// CreateMachineIdentityCredential/GetMachineIdentityCredentialByHash/
// GetMachineIdentityCredentialByID/ListMachineIdentityCredentials/
// ListActiveMachineIdentityCredentials/UpdateMachineIdentityCredential/
// CountMachineIdentityCredentialsByClassification/RevokeMachineIdentityCredential/
// TouchMachineIdentityCredential/AssignMachineRole/RemoveMachineRole/
// GetMachineRoleIDsAt/GetMachineRoles/CreateOIDCBinding/GetMachineByOIDCSubject/
// ListOIDCBindings/GetOIDCBindingByID/DeleteOIDCBinding.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its machine-identity storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/machine-identities, /machine-credentials, and
// /machine-oidc-bindings, gated on the existing system.read/system.write RBAC
// permissions — the SAME tier every RemoteStorage credential already needs for
// every other proxied call), mirroring dynamic_secrets_proxy.go/groups_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/machine_identities.go, machine_token.go, and machine_oidc.go
// already use against a local backend. NO authorization/business-logic decision
// (state-machine transition legality, role-grant authorization, token
// issuance/hashing, OIDC-subject federation policy) is made here — that stays
// entirely in the CALLING server's own internal/core.KeyorixCore, exactly as it
// does against a local backend.
//
// This is why the existing human-facing routes under
// /api/v1/projects/{id}/machine-identities/... (server/http/handlers/
// machine_identities.go, CatalogHandler.TransitionMachineIdentity/
// ClassifyMachineIdentity/IssueMachineToken/GrantMachineRole/CreateOIDCBinding)
// are NOT reused for this proxy — exactly like the human-facing /groups routes
// were the wrong target for the Groups fix (#514): those handlers bake in real
// authorization decisions (project-scoped RBAC via RequireScopedPermission),
// state-machine legality checks, token minting/hashing, and audit-event
// construction against the calling HTTP request's OWN identity — the wrong
// semantics for a raw storage-primitive passthrough, whose caller (the
// downstream server's own internal/core, already authorized against ITS OWN
// caller) only needs this server to persist/return rows.
//
// Sensitive-data note: MachineIdentityCredential.TokenHash is tagged `json:"-"`
// on the model (never exposed on the human-facing API — see
// machine_identities.go's model doc), but it is only ever a SHA-256 hex digest
// of the one-time-displayed raw token, never the raw secret itself (verified via
// its only reader, internal/core/machine_token.go's ValidateMachineToken, which
// looks it up via GetMachineIdentityCredentialByHash(ctx, sha256Hex(raw))) — so,
// like dynamicSecretConfigProxyWire's AdminDSNEnc/AdminDSNMeta, this proxy's wire
// type carries it explicitly rather than silently dropping it, which would
// otherwise make GetMachineIdentityCredentialByHash/CreateMachineIdentityCredential
// entirely non-functional under storage.type: remote (ValidateMachineToken's
// lookup has nothing to match against).
//
// Atomicity note (investigated, not assumed safe): TransitionMachineIdentityState
// exists (internal/core/storage/interface.go) precisely because a naive two-call
// LockMachineIdentityForUpdate-then-UpdateMachineIdentity proxy pair would lose
// the #388 "revoked is terminal" guarantee entirely under storage.type: remote —
// RemoteStorage.WithTransaction is a no-op passthrough (remote_transaction.go), so
// nothing serializes the Lock read against a concurrent writer's commit the way a
// real DB transaction + row lock does locally. TransitionMachineIdentityStateProxy
// runs core.KeyorixCore's SAME conditional "WHERE id = ? AND state = ?" write
// (local_machine_identities.go) in ONE round trip, making no transition-legality
// decision of its own — core.TransitionMachineIdentity still decides fromState/to
// via canTransitionMachine before calling this, exactly as it does locally.
//
// Response envelope: like dynamic_secrets_proxy.go/groups_proxy.go, these
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// isAlreadyAssignedErr reports whether err is local_machine_credentials.go's
// AssignMachineRole "already assigned" client error — a conflict, not a storage
// failure. Classifying it as 409 (rather than a generic 500) matters beyond
// HTTP semantics purity: internal/storage/remote.HTTPClient's isRetryableError
// treats ANY 5xx as retryable and re-sends the request with exponential
// backoff, and 5 CONSECUTIVE recorded failures — which a single retried 500
// call reaches on its own, one per attempt — trips its circuit breaker,
// locking out every OTHER call through the same RemoteStorage instance for the
// next 30s. An expected, deterministic "already assigned" client error must
// therefore map to a genuinely non-retryable 4xx status.
func isAlreadyAssignedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already assigned")
}

// isNotAssignedErr reports whether err is RemoveMachineRole's "not assigned"
// client error (the grant doesn't exist) — see isAlreadyAssignedErr's doc for
// why this must be a non-retryable 4xx, not a 500.
func isNotAssignedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not assigned")
}

// isUniqueViolationErr reports whether err looks like a unique-constraint
// violation from either backing DB driver — mirrors
// internal/storage/store/local_memberships.go's isUniqueViolation exactly
// (matching driver-native message text, since this codebase doesn't opt into
// gorm.Config{TranslateError: true}). Used by CreateOIDCBindingProxy to map
// CreateOIDCBinding's duplicate (issuer, subject) failure to 409 rather than a
// retryable 500 — see isAlreadyAssignedErr's doc for why that distinction
// matters beyond HTTP semantics purity.
func isUniqueViolationErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || // SQLite
		strings.Contains(msg, "duplicate key value violates unique constraint") // Postgres
}

// machineIdentityProxyWire mirrors models.MachineIdentity's fields exactly
// (snake_case) — the model carries no json tags of its own, so a direct
// marshal/unmarshal would produce Go-cased keys ("ID", "ProjectID", ...) instead
// of the snake_case wire shape every other proxy in this package uses.
type machineIdentityProxyWire struct {
	ID             uint       `json:"id"`
	ProjectID      uint       `json:"project_id"`
	Name           string     `json:"name"`
	IdentityType   string     `json:"identity_type"`
	State          string     `json:"state"`
	Description    string     `json:"description"`
	CreatedBy      uint       `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	Classification string     `json:"classification"`
}

func newMachineIdentityProxyWire(m *models.MachineIdentity) machineIdentityProxyWire {
	return machineIdentityProxyWire{
		ID:             m.ID,
		ProjectID:      m.ProjectID,
		Name:           m.Name,
		IdentityType:   m.IdentityType,
		State:          m.State,
		Description:    m.Description,
		CreatedBy:      m.CreatedBy,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
		LastSeenAt:     m.LastSeenAt,
		RevokedAt:      m.RevokedAt,
		Classification: m.Classification,
	}
}

func (w machineIdentityProxyWire) toModel() *models.MachineIdentity {
	return &models.MachineIdentity{
		ID:             w.ID,
		ProjectID:      w.ProjectID,
		Name:           w.Name,
		IdentityType:   w.IdentityType,
		State:          w.State,
		Description:    w.Description,
		CreatedBy:      w.CreatedBy,
		CreatedAt:      w.CreatedAt,
		UpdatedAt:      w.UpdatedAt,
		LastSeenAt:     w.LastSeenAt,
		RevokedAt:      w.RevokedAt,
		Classification: w.Classification,
	}
}

// machineIdentityCredentialProxyWire mirrors models.MachineIdentityCredential's
// fields exactly, INCLUDING TokenHash (tagged `json:"-"` on the model, which
// would otherwise silently drop it from a direct marshal) — see the package doc
// for why sending this SHA-256 hash (never the raw token) across this internal
// boundary is safe.
type machineIdentityCredentialProxyWire struct {
	ID                uint       `json:"id"`
	MachineIdentityID uint       `json:"machine_identity_id"`
	Name              string     `json:"name"`
	TokenHash         string     `json:"token_hash"`
	TokenPrefix       string     `json:"token_prefix"`
	LastUsedAt        *time.Time `json:"last_used_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Revoked           bool       `json:"revoked"`
	CreatedAt         time.Time  `json:"created_at"`
	Classification    string     `json:"classification"`
}

func newMachineIdentityCredentialProxyWire(c *models.MachineIdentityCredential) machineIdentityCredentialProxyWire {
	return machineIdentityCredentialProxyWire{
		ID:                c.ID,
		MachineIdentityID: c.MachineIdentityID,
		Name:              c.Name,
		TokenHash:         c.TokenHash,
		TokenPrefix:       c.TokenPrefix,
		LastUsedAt:        c.LastUsedAt,
		ExpiresAt:         c.ExpiresAt,
		Revoked:           c.Revoked,
		CreatedAt:         c.CreatedAt,
		Classification:    c.Classification,
	}
}

func (w machineIdentityCredentialProxyWire) toModel() *models.MachineIdentityCredential {
	return &models.MachineIdentityCredential{
		ID:                w.ID,
		MachineIdentityID: w.MachineIdentityID,
		Name:              w.Name,
		TokenHash:         w.TokenHash,
		TokenPrefix:       w.TokenPrefix,
		LastUsedAt:        w.LastUsedAt,
		ExpiresAt:         w.ExpiresAt,
		Revoked:           w.Revoked,
		CreatedAt:         w.CreatedAt,
		Classification:    w.Classification,
	}
}

// machineIdentityOIDCBindingProxyWire mirrors models.MachineIdentityOIDCBinding's
// fields exactly (snake_case).
type machineIdentityOIDCBindingProxyWire struct {
	ID                uint      `json:"id"`
	MachineIdentityID uint      `json:"machine_identity_id"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	CreatedBy         uint      `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
}

func newMachineIdentityOIDCBindingProxyWire(b *models.MachineIdentityOIDCBinding) machineIdentityOIDCBindingProxyWire {
	return machineIdentityOIDCBindingProxyWire{
		ID:                b.ID,
		MachineIdentityID: b.MachineIdentityID,
		Issuer:            b.Issuer,
		Subject:           b.Subject,
		CreatedBy:         b.CreatedBy,
		CreatedAt:         b.CreatedAt,
	}
}

func (w machineIdentityOIDCBindingProxyWire) toModel() *models.MachineIdentityOIDCBinding {
	return &models.MachineIdentityOIDCBinding{
		ID:                w.ID,
		MachineIdentityID: w.MachineIdentityID,
		Issuer:            w.Issuer,
		Subject:           w.Subject,
		CreatedBy:         w.CreatedBy,
		CreatedAt:         w.CreatedAt,
	}
}

// roleProxyWire mirrors models.Role's fields exactly (snake_case) — used only by
// GetMachineRolesProxy's response.
type roleProxyWire struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func newRoleProxyWire(r *models.Role) roleProxyWire {
	return roleProxyWire{ID: r.ID, Name: r.Name, Description: r.Description}
}

// --- Machine identities ---

// CreateMachineIdentityProxy handles POST /api/v1/system/machine-identities.
func (h *CatalogHandler) CreateMachineIdentityProxy(w http.ResponseWriter, r *http.Request) {
	var body machineIdentityProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Name == "" || body.ProjectID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "name and project_id are required")
		return
	}
	created, err := h.coreService.Storage().CreateMachineIdentity(r.Context(), body.toModel())
	if err != nil {
		log.Printf("machine-identities proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityProxyWire(created))
}

// GetMachineIdentityProxy handles GET /api/v1/system/machine-identities/{id}.
// Also backs RemoteStorage.LockMachineIdentityForUpdate: LockMachineIdentityForUpdate
// has no row lock to take over HTTP (mirroring LockUserForUpdate's remote
// equivalent, remote_users.go) — it is a plain read, deliberately NOT routed
// through the client's response cache (see remote_machine_identities.go).
func (h *CatalogHandler) GetMachineIdentityProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	m, err := h.coreService.Storage().GetMachineIdentity(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "machine identity not found")
			return
		}
		log.Printf("machine-identities proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityProxyWire(m))
}

// UpdateMachineIdentityProxy handles PUT /api/v1/system/machine-identities/{id}.
// A raw persist (storage.Storage.UpdateMachineIdentity is an unconditional
// full-row Save, matching LocalStorage's own semantics exactly — used by
// core.ClassifyMachineIdentity, which has no state-machine invariant to protect).
// core.TransitionMachineIdentity does NOT use this path — see
// TransitionMachineIdentityStateProxy below.
func (h *CatalogHandler) UpdateMachineIdentityProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	var body machineIdentityProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateMachineIdentity(r.Context(), body.toModel()); err != nil {
		log.Printf("machine-identities proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// transitionMachineIdentityStateBody is the request body
// TransitionMachineIdentityStateProxy expects: the full machine-identity row the
// caller already mutated in memory (m.State/UpdatedAt/RevokedAt already set to
// the target values), plus the fromState the caller observed under its own
// LockMachineIdentityForUpdate read.
type transitionMachineIdentityStateBody struct {
	MachineIdentity machineIdentityProxyWire `json:"machine_identity"`
	FromState       string                   `json:"from_state"`
}

// TransitionMachineIdentityStateProxy handles PUT
// /api/v1/system/machine-identities/{id}/transition. Runs the SAME conditional
// "WHERE id = ? AND state = ?" write core.KeyorixCore.TransitionMachineIdentity
// already relies on against a local backend (#388) — see the package doc's
// atomicity note for why this is a dedicated route rather than a generic
// UpdateMachineIdentityProxy call.
func (h *CatalogHandler) TransitionMachineIdentityStateProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	var body transitionMachineIdentityStateBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.FromState == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "from_state is required")
		return
	}
	body.MachineIdentity.ID = uint(id)
	m := body.MachineIdentity.toModel()
	matched, err := h.coreService.Storage().TransitionMachineIdentityState(r.Context(), m, body.FromState)
	if err != nil {
		log.Printf("machine-identities proxy: transition failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}

// ListMachineIdentitiesProxy handles GET
// /api/v1/system/machine-identities?project_id=X.
func (h *CatalogHandler) ListMachineIdentitiesProxy(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.coreService.Storage().ListMachineIdentities(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("machine-identities proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]machineIdentityProxyWire, 0, len(rows))
	for _, m := range rows {
		wire = append(wire, newMachineIdentityProxyWire(m))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"machine_identities": wire})
}

// ListAllMachineIdentitiesProxy handles GET
// /api/v1/system/machine-identities/all (a static path, registered before
// /machine-identities/{id} in router.go).
func (h *CatalogHandler) ListAllMachineIdentitiesProxy(w http.ResponseWriter, r *http.Request) {
	rows, err := h.coreService.Storage().ListAllMachineIdentities(r.Context())
	if err != nil {
		log.Printf("machine-identities proxy: list-all failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]machineIdentityProxyWire, 0, len(rows))
	for _, m := range rows {
		wire = append(wire, newMachineIdentityProxyWire(m))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"machine_identities": wire})
}

// CountMachineIdentitiesByClassificationProxy handles GET
// /api/v1/system/machine-identities/classification-counts (a static path,
// registered before /machine-identities/{id} in router.go).
func (h *CatalogHandler) CountMachineIdentitiesByClassificationProxy(w http.ResponseWriter, r *http.Request) {
	counts, err := h.coreService.Storage().CountMachineIdentitiesByClassification(r.Context())
	if err != nil {
		log.Printf("machine-identities proxy: count-by-classification failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"counts": counts})
}

// --- Machine-token credentials ---

// CreateMachineIdentityCredentialProxy handles POST /api/v1/system/machine-credentials.
func (h *CatalogHandler) CreateMachineIdentityCredentialProxy(w http.ResponseWriter, r *http.Request) {
	var body machineIdentityCredentialProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.MachineIdentityID == 0 || body.TokenHash == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "machine_identity_id and token_hash are required")
		return
	}
	created, err := h.coreService.Storage().CreateMachineIdentityCredential(r.Context(), body.toModel())
	if err != nil {
		log.Printf("machine-credentials proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityCredentialProxyWire(created))
}

// GetMachineIdentityCredentialByHashProxy handles GET
// /api/v1/system/machine-credentials/by-hash/{hash} (a static prefix, registered
// before /machine-credentials/{id} in router.go). Backs
// core.ValidateMachineToken's machine-token authentication lookup — see the
// package doc for why sending this SHA-256 hash (never the raw token) is safe.
func (h *CatalogHandler) GetMachineIdentityCredentialByHashProxy(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	c, err := h.coreService.Storage().GetMachineIdentityCredentialByHash(r.Context(), hash)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errMachineCredentialNotFound)
			return
		}
		log.Printf("machine-credentials proxy: get-by-hash failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityCredentialProxyWire(c))
}

// GetMachineIdentityCredentialByIDProxy handles GET
// /api/v1/system/machine-credentials/{id}.
func (h *CatalogHandler) GetMachineIdentityCredentialByIDProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidCredentialID)
		return
	}
	c, err := h.coreService.Storage().GetMachineIdentityCredentialByID(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errMachineCredentialNotFound)
			return
		}
		log.Printf("machine-credentials proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityCredentialProxyWire(c))
}

// ListMachineIdentityCredentialsProxy handles GET
// /api/v1/system/machine-identities/{id}/credentials.
func (h *CatalogHandler) ListMachineIdentityCredentialsProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	rows, err := h.coreService.Storage().ListMachineIdentityCredentials(r.Context(), uint(machineID))
	if err != nil {
		log.Printf("machine-credentials proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]machineIdentityCredentialProxyWire, 0, len(rows))
	for _, c := range rows {
		wire = append(wire, newMachineIdentityCredentialProxyWire(c))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"credentials": wire})
}

// ListActiveMachineIdentityCredentialsProxy handles GET
// /api/v1/system/machine-credentials/active (a static path, registered before
// /machine-credentials/{id} in router.go).
func (h *CatalogHandler) ListActiveMachineIdentityCredentialsProxy(w http.ResponseWriter, r *http.Request) {
	rows, err := h.coreService.Storage().ListActiveMachineIdentityCredentials(r.Context())
	if err != nil {
		log.Printf("machine-credentials proxy: list-active failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]machineIdentityCredentialProxyWire, 0, len(rows))
	for _, c := range rows {
		wire = append(wire, newMachineIdentityCredentialProxyWire(c))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"credentials": wire})
}

// UpdateMachineIdentityCredentialProxy handles PUT
// /api/v1/system/machine-credentials/{id}. A raw persist (storage.Storage.
// UpdateMachineIdentityCredential is an unconditional full-row Save, matching
// LocalStorage's own semantics exactly — used by core.ClassifyMachineToken).
func (h *CatalogHandler) UpdateMachineIdentityCredentialProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidCredentialID)
		return
	}
	var body machineIdentityCredentialProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateMachineIdentityCredential(r.Context(), body.toModel()); err != nil {
		log.Printf("machine-credentials proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// CountMachineIdentityCredentialsByClassificationProxy handles GET
// /api/v1/system/machine-credentials/classification-counts (a static path,
// registered before /machine-credentials/{id} in router.go).
func (h *CatalogHandler) CountMachineIdentityCredentialsByClassificationProxy(w http.ResponseWriter, r *http.Request) {
	counts, err := h.coreService.Storage().CountMachineIdentityCredentialsByClassification(r.Context())
	if err != nil {
		log.Printf("machine-credentials proxy: count-by-classification failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"counts": counts})
}

// RevokeMachineIdentityCredentialProxy handles POST
// /api/v1/system/machine-credentials/{id}/revoke. storage.Storage.
// RevokeMachineIdentityCredential is itself an atomic conditional UPDATE
// (local_machine_credentials.go: `UpdateColumn("revoked", true)` gated on
// `id = ?`), so a single passthrough call here preserves that guarantee exactly.
func (h *CatalogHandler) RevokeMachineIdentityCredentialProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidCredentialID)
		return
	}
	if err := h.coreService.Storage().RevokeMachineIdentityCredential(r.Context(), uint(id)); err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errMachineCredentialNotFound)
			return
		}
		log.Printf("machine-credentials proxy: revoke failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"revoked": true})
}

// touchMachineIdentityCredentialBody is TouchMachineIdentityCredentialProxy's
// request body. StalenessSeconds is sent as whole seconds rather than a raw
// time.Duration (nanoseconds) to keep the wire value human-readable/debuggable.
type touchMachineIdentityCredentialBody struct {
	UsedAt           time.Time `json:"used_at"`
	StalenessSeconds int64     `json:"staleness_seconds"`
}

// TouchMachineIdentityCredentialProxy handles POST
// /api/v1/system/machine-credentials/{id}/touch. Preserves
// TouchMachineIdentityCredential's own throttled-write semantics
// (local_machine_credentials.go's `WHERE id = ? AND (last_used_at IS NULL OR
// last_used_at < cutoff)`) via a single passthrough call.
func (h *CatalogHandler) TouchMachineIdentityCredentialProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidCredentialID)
		return
	}
	var body touchMachineIdentityCredentialBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	staleness := time.Duration(body.StalenessSeconds) * time.Second
	if err := h.coreService.Storage().TouchMachineIdentityCredential(r.Context(), uint(id), body.UsedAt, staleness); err != nil {
		log.Printf("machine-credentials proxy: touch failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"touched": true})
}

// --- Machine role grants ---

// machineRoleScopeQuery parses the required project_id/environment_id query
// parameters shared by every machine-role route below (0 is a valid "global
// scope" value for either, so both are required rather than defaulted).
func machineRoleScopeQuery(w http.ResponseWriter, r *http.Request) (storage.Scope, bool) {
	projectIDStr := r.URL.Query().Get("project_id")
	environmentIDStr := r.URL.Query().Get("environment_id")
	if projectIDStr == "" || environmentIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id and environment_id query parameters are required")
		return storage.Scope{}, false
	}
	projectID, err := strconv.ParseUint(projectIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return storage.Scope{}, false
	}
	environmentID, err := strconv.ParseUint(environmentIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "environment_id must be a valid integer")
		return storage.Scope{}, false
	}
	return storage.Scope{ProjectID: uint(projectID), EnvironmentID: uint(environmentID)}, true
}

// AssignMachineRoleProxy handles POST
// /api/v1/system/machine-identities/{id}/roles/{roleId}?project_id=&environment_id=.
func (h *CatalogHandler) AssignMachineRoleProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	roleID, err := strconv.ParseUint(chi.URLParam(r, "roleId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid role id")
		return
	}
	scope, ok := machineRoleScopeQuery(w, r)
	if !ok {
		return
	}
	if err := h.coreService.Storage().AssignMachineRole(r.Context(), uint(machineID), uint(roleID), scope); err != nil {
		if isAlreadyAssignedErr(err) {
			writeRemoteAPIError(w, http.StatusConflict, "ALREADY_ASSIGNED", "role already assigned")
			return
		}
		log.Printf("machine-roles proxy: assign failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"assigned": true})
}

// RemoveMachineRoleProxy handles DELETE
// /api/v1/system/machine-identities/{id}/roles/{roleId}?project_id=&environment_id=.
func (h *CatalogHandler) RemoveMachineRoleProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	roleID, err := strconv.ParseUint(chi.URLParam(r, "roleId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid role id")
		return
	}
	scope, ok := machineRoleScopeQuery(w, r)
	if !ok {
		return
	}
	if err := h.coreService.Storage().RemoveMachineRole(r.Context(), uint(machineID), uint(roleID), scope); err != nil {
		if isNotFoundErr(err) || isNotAssignedErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "role grant not found")
			return
		}
		log.Printf("machine-roles proxy: remove failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"removed": true})
}

// GetMachineRoleIDsAtProxy handles GET
// /api/v1/system/machine-identities/{id}/roles/ids?project_id=&environment_id=
// (a static "ids" path, registered before the /roles/{roleId} routes above in
// router.go).
func (h *CatalogHandler) GetMachineRoleIDsAtProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	scope, ok := machineRoleScopeQuery(w, r)
	if !ok {
		return
	}
	ids, err := h.coreService.Storage().GetMachineRoleIDsAt(r.Context(), uint(machineID), scope)
	if err != nil {
		log.Printf("machine-roles proxy: get-ids-at failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"role_ids": ids})
}

// GetMachineRolesProxy handles GET /api/v1/system/machine-identities/{id}/roles.
func (h *CatalogHandler) GetMachineRolesProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	roles, err := h.coreService.Storage().GetMachineRoles(r.Context(), uint(machineID))
	if err != nil {
		log.Printf("machine-roles proxy: get-roles failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]roleProxyWire, 0, len(roles))
	for _, ro := range roles {
		wire = append(wire, newRoleProxyWire(ro))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"roles": wire})
}

// --- OIDC bindings ---

// CreateOIDCBindingProxy handles POST /api/v1/system/machine-oidc-bindings.
func (h *CatalogHandler) CreateOIDCBindingProxy(w http.ResponseWriter, r *http.Request) {
	var body machineIdentityOIDCBindingProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.MachineIdentityID == 0 || body.Issuer == "" || body.Subject == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "machine_identity_id, issuer, and subject are required")
		return
	}
	created, err := h.coreService.Storage().CreateOIDCBinding(r.Context(), body.toModel())
	if err != nil {
		if isUniqueViolationErr(err) {
			writeRemoteAPIError(w, http.StatusConflict, "DUPLICATE_BINDING", "a binding for this issuer/subject already exists")
			return
		}
		log.Printf("machine-oidc-bindings proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityOIDCBindingProxyWire(created))
}

// GetMachineByOIDCSubjectProxy handles GET
// /api/v1/system/machine-oidc-bindings/by-subject?issuer=&subject= (a static
// path, registered before /machine-oidc-bindings/{id} in router.go).
func (h *CatalogHandler) GetMachineByOIDCSubjectProxy(w http.ResponseWriter, r *http.Request) {
	issuer := r.URL.Query().Get("issuer")
	subject := r.URL.Query().Get("subject")
	if issuer == "" || subject == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "issuer and subject query parameters are required")
		return
	}
	m, err := h.coreService.Storage().GetMachineByOIDCSubject(r.Context(), issuer, subject)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "no machine identity bound to that issuer/subject")
			return
		}
		log.Printf("machine-oidc-bindings proxy: get-by-subject failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityProxyWire(m))
}

// ListOIDCBindingsProxy handles GET
// /api/v1/system/machine-identities/{id}/oidc-bindings.
func (h *CatalogHandler) ListOIDCBindingsProxy(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidMachineIDLower)
		return
	}
	rows, err := h.coreService.Storage().ListOIDCBindings(r.Context(), uint(machineID))
	if err != nil {
		log.Printf("machine-oidc-bindings proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]machineIdentityOIDCBindingProxyWire, 0, len(rows))
	for _, b := range rows {
		wire = append(wire, newMachineIdentityOIDCBindingProxyWire(b))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"bindings": wire})
}

// GetOIDCBindingByIDProxy handles GET
// /api/v1/system/machine-oidc-bindings/{id}.
func (h *CatalogHandler) GetOIDCBindingByIDProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid binding id")
		return
	}
	b, err := h.coreService.Storage().GetOIDCBindingByID(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "oidc binding not found")
			return
		}
		log.Printf("machine-oidc-bindings proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMachineIdentityOIDCBindingProxyWire(b))
}

// DeleteOIDCBindingProxy handles DELETE /api/v1/system/machine-oidc-bindings/{id}.
func (h *CatalogHandler) DeleteOIDCBindingProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid binding id")
		return
	}
	if err := h.coreService.Storage().DeleteOIDCBinding(r.Context(), uint(id)); err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "oidc binding not found")
			return
		}
		log.Printf("machine-oidc-bindings proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}
