// dynamic_secrets_proxy.go — server-side endpoints backing RemoteStorage's
// dynamic-secrets storage primitives (ADR-035/ADR-049): CreateDynamicSecretConfig/
// GetDynamicSecretConfig/ListDynamicSecretConfigs/UpdateDynamicSecretConfig/
// TransitionDynamicSecretConfigDisabled/CountDynamicSecretConfigsByClassification/
// CreateDynamicSecretLease/GetDynamicSecretLease/ListDynamicSecretLeases/
// CountActiveLeases/UpdateDynamicSecretLease/ListExpiredActiveLeases.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its dynamic-secrets storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/dynamic-secrets, gated on the existing system.read/system.write
// RBAC permissions — the SAME credential a RemoteStorage client already needs for
// every other proxied call, e.g. full user CRUD, login-attempts, invitations — so
// this introduces no new privilege class). Mirrors login_attempts_proxy.go and
// invitations_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/dynamic_secrets.go already uses against a local backend — NO
// dynamic-secrets POLICY decision (admin-authority binding check, TTL/max-lease
// clamping, active-lease ceiling enforcement, disabled/soft-deleted-project
// refusal, the encrypt/decrypt of the admin DSN and issued credential) is made
// here; all of that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// Critically, the admin DSN (models.DynamicSecretConfig.AdminDSNEnc/AdminDSNMeta)
// and the issued credential (models.DynamicSecretLease.CredentialEnc/
// CredentialMeta) NEVER cross this boundary in plaintext: internal/core encrypts
// the admin DSN with the CALLING server's own encryption key BEFORE ever handing
// the config to storage.CreateDynamicSecretConfig/UpdateDynamicSecretConfig, and
// decrypts it only after storage.GetDynamicSecretConfig returns the ciphertext
// bytes back to that SAME calling server. These proxy handlers persist/return
// those bytes as opaque ciphertext — this server (the upstream) never decrypts
// them, and in a storage.type: remote deployment generally CANNOT: it has no
// reason to hold the downstream's encryption key at all. This is a stronger
// boundary than CreateSecret's remote passthrough (internal/storage/store/
// remote_secrets.go), which does send a secret's plaintext value across the wire
// once, because for ordinary secrets encryption happens in the STORAGE layer of
// whichever server ultimately persists the row (this server, for a config/lease
// round-tripped through here). For dynamic secrets it happens in core, one layer
// up, so the ciphertext is already opaque by the time it reaches here.
//
// This also means the DynamicSecretHandler's existing human-facing
// /api/v1/dynamic-secrets/* routes (server/http/handlers/dynamic_secrets.go) are
// NOT reused for this proxy, unlike the login-attempts/invitations precedent might
// suggest at a glance: CreateConfig there requires a PLAINTEXT admin_dsn field and
// runs this server's OWN core.CreateDynamicSecretConfig (including this server's
// own admin-authority/project-scope authorization against the HTTP caller's
// identity and this server's own encryption key) — the wrong semantics for a raw
// storage-primitive passthrough, whose caller already ran all of that on the
// downstream side and only needs this server to persist/return already-encrypted
// bytes.
//
// Response envelope: like login_attempts_proxy.go/invitations_proxy.go, these do
// NOT use the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// dynamicSecretConfigProxyWire mirrors models.DynamicSecretConfig's fields
// exactly (snake_case), INCLUDING the encrypted admin-DSN ciphertext + metadata —
// see the package doc for why sending that ciphertext (never plaintext) across
// this boundary is safe. models.DynamicSecretConfig carries no json tags of its
// own (AdminDSNEnc/AdminDSNMeta are actually tagged `json:"-"`, which would
// silently drop them from a direct marshal), so — matching invitationProxyWire's
// (#496-class) reasoning — every field is named explicitly here rather than
// relying on a direct marshal of the model.
type dynamicSecretConfigProxyWire struct {
	ID                uint      `json:"id"`
	Name              string    `json:"name"`
	ProjectID         uint      `json:"project_id"`
	EnvironmentID     uint      `json:"environment_id"`
	BackendType       string    `json:"backend_type"`
	AdminDSNEnc       []byte    `json:"admin_dsn_enc,omitempty"`
	AdminDSNMeta      []byte    `json:"admin_dsn_meta,omitempty"`
	CreationTemplate  string    `json:"creation_template"`
	DefaultTTLSeconds int       `json:"default_ttl_seconds"`
	MaxTTLSeconds     int       `json:"max_ttl_seconds"`
	MaxActiveLeases   int       `json:"max_active_leases"`
	Classification    string    `json:"classification"`
	Disabled          bool      `json:"disabled"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func newDynamicSecretConfigProxyWire(c *models.DynamicSecretConfig) dynamicSecretConfigProxyWire {
	return dynamicSecretConfigProxyWire{
		ID:                c.ID,
		Name:              c.Name,
		ProjectID:         c.ProjectID,
		EnvironmentID:     c.EnvironmentID,
		BackendType:       c.BackendType,
		AdminDSNEnc:       c.AdminDSNEnc,
		AdminDSNMeta:      c.AdminDSNMeta,
		CreationTemplate:  c.CreationTemplate,
		DefaultTTLSeconds: c.DefaultTTLSeconds,
		MaxTTLSeconds:     c.MaxTTLSeconds,
		MaxActiveLeases:   c.MaxActiveLeases,
		Classification:    c.Classification,
		Disabled:          c.Disabled,
		CreatedBy:         c.CreatedBy,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}

func (w dynamicSecretConfigProxyWire) toModel() *models.DynamicSecretConfig {
	return &models.DynamicSecretConfig{
		ID:                w.ID,
		Name:              w.Name,
		ProjectID:         w.ProjectID,
		EnvironmentID:     w.EnvironmentID,
		BackendType:       w.BackendType,
		AdminDSNEnc:       w.AdminDSNEnc,
		AdminDSNMeta:      w.AdminDSNMeta,
		CreationTemplate:  w.CreationTemplate,
		DefaultTTLSeconds: w.DefaultTTLSeconds,
		MaxTTLSeconds:     w.MaxTTLSeconds,
		MaxActiveLeases:   w.MaxActiveLeases,
		Classification:    w.Classification,
		Disabled:          w.Disabled,
		CreatedBy:         w.CreatedBy,
		CreatedAt:         w.CreatedAt,
		UpdatedAt:         w.UpdatedAt,
	}
}

// dynamicSecretLeaseProxyWire mirrors models.DynamicSecretLease's fields exactly,
// including the encrypted credential ciphertext + metadata (CredentialEnc/
// CredentialMeta, tagged `json:"-"` on the model) — same reasoning as
// dynamicSecretConfigProxyWire above: this ciphertext was produced by the CALLING
// server's own core using its own encryption key, and is never decrypted here.
type dynamicSecretLeaseProxyWire struct {
	ID             uint       `json:"id"`
	ConfigID       uint       `json:"config_id"`
	LeaseID        string     `json:"lease_id"`
	ProjectID      uint       `json:"project_id"`
	EnvironmentID  uint       `json:"environment_id"`
	RoleName       string     `json:"role_name"`
	CredentialEnc  []byte     `json:"credential_enc,omitempty"`
	CredentialMeta []byte     `json:"credential_meta,omitempty"`
	Status         string     `json:"status"`
	RevokeReason   string     `json:"revoke_reason"`
	RevokeError    string     `json:"revoke_error"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
}

func newDynamicSecretLeaseProxyWire(l *models.DynamicSecretLease) dynamicSecretLeaseProxyWire {
	return dynamicSecretLeaseProxyWire{
		ID:             l.ID,
		ConfigID:       l.ConfigID,
		LeaseID:        l.LeaseID,
		ProjectID:      l.ProjectID,
		EnvironmentID:  l.EnvironmentID,
		RoleName:       l.RoleName,
		CredentialEnc:  l.CredentialEnc,
		CredentialMeta: l.CredentialMeta,
		Status:         l.Status,
		RevokeReason:   l.RevokeReason,
		RevokeError:    l.RevokeError,
		IssuedAt:       l.IssuedAt,
		ExpiresAt:      l.ExpiresAt,
		RevokedAt:      l.RevokedAt,
	}
}

func (w dynamicSecretLeaseProxyWire) toModel() *models.DynamicSecretLease {
	return &models.DynamicSecretLease{
		ID:             w.ID,
		ConfigID:       w.ConfigID,
		LeaseID:        w.LeaseID,
		ProjectID:      w.ProjectID,
		EnvironmentID:  w.EnvironmentID,
		RoleName:       w.RoleName,
		CredentialEnc:  w.CredentialEnc,
		CredentialMeta: w.CredentialMeta,
		Status:         w.Status,
		RevokeReason:   w.RevokeReason,
		RevokeError:    w.RevokeError,
		IssuedAt:       w.IssuedAt,
		ExpiresAt:      w.ExpiresAt,
		RevokedAt:      w.RevokedAt,
	}
}

func isNotFoundErr(err error) bool {
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "record not found")
}

// CreateDynamicSecretConfigProxy handles POST /api/v1/system/dynamic-secrets/configs.
// Persists the caller's already-fully-built config row as-is (a raw storage-layer
// create) — matching CreateProjectInvitationProxy's precedent, this is NOT the
// human-facing POST /api/v1/dynamic-secrets/configs (DynamicSecretHandler.CreateConfig),
// which additionally requires a plaintext admin_dsn and runs this server's own
// authorization + encryption. The caller (internal/core.CreateDynamicSecretConfig
// on the downstream server) itself does the same two-phase create-then-update this
// server's LocalStorage-backed path does (#94): the DSN ciphertext is usually empty
// on this initial create and arrives moments later via UpdateDynamicSecretConfigProxy.
func (h *DynamicSecretHandler) CreateDynamicSecretConfigProxy(w http.ResponseWriter, r *http.Request) {
	var body dynamicSecretConfigProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Name == "" || body.ProjectID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "name and project_id are required")
		return
	}
	created, err := h.coreService.Storage().CreateDynamicSecretConfig(r.Context(), body.toModel())
	if err != nil {
		log.Printf("dynamic-secrets proxy: create config failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newDynamicSecretConfigProxyWire(created))
}

// GetDynamicSecretConfigProxy handles GET /api/v1/system/dynamic-secrets/configs/{id}.
func (h *DynamicSecretHandler) GetDynamicSecretConfigProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidConfigID)
		return
	}
	cfg, err := h.coreService.Storage().GetDynamicSecretConfig(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "dynamic-secret config not found")
			return
		}
		log.Printf("dynamic-secrets proxy: get config failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newDynamicSecretConfigProxyWire(cfg))
}

// ListDynamicSecretConfigsProxy handles GET
// /api/v1/system/dynamic-secrets/configs?project_id=&environment_id=.
func (h *DynamicSecretHandler) ListDynamicSecretConfigsProxy(w http.ResponseWriter, r *http.Request) {
	projectID, environmentID, ok := parseProxyScopeQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListDynamicSecretConfigs(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("dynamic-secrets proxy: list configs failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]dynamicSecretConfigProxyWire, 0, len(rows))
	for _, c := range rows {
		wire = append(wire, newDynamicSecretConfigProxyWire(c))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"configs": wire})
}

// UpdateDynamicSecretConfigProxy handles PUT /api/v1/system/dynamic-secrets/configs/{id}.
// A raw persist (storage.Storage.UpdateDynamicSecretConfig is an unconditional
// full-row Save, matching LocalStorage's own semantics exactly — there is no
// conditional/optimistic-concurrency write to preserve here, unlike
// UpdateProjectInvitation's `WHERE ... AND state = 'pending'`).
func (h *DynamicSecretHandler) UpdateDynamicSecretConfigProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidConfigID)
		return
	}
	var body dynamicSecretConfigProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateDynamicSecretConfig(r.Context(), body.toModel()); err != nil {
		log.Printf("dynamic-secrets proxy: update config failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// transitionDynamicSecretConfigDisabledBody is the request body
// TransitionDynamicSecretConfigDisabledProxy expects: the full config row the
// caller already mutated in memory (Disabled/UpdatedAt already set to the
// target values), plus the fromDisabled value the caller observed via its own
// GetDynamicSecretConfig read.
type transitionDynamicSecretConfigDisabledBody struct {
	Config       dynamicSecretConfigProxyWire `json:"config"`
	FromDisabled bool                         `json:"from_disabled"`
}

// TransitionDynamicSecretConfigDisabledProxy handles PUT
// /api/v1/system/dynamic-secrets/configs/{id}/transition. Runs the SAME
// conditional "WHERE id = ? AND disabled = ?" write
// core.KeyorixCore.SetDynamicSecretConfigEnabled relies on against a local
// backend (StateTransitionMissingCAS) — see the package doc's atomicity note
// for why this is a dedicated route rather than a generic
// UpdateDynamicSecretConfigProxy call.
func (h *DynamicSecretHandler) TransitionDynamicSecretConfigDisabledProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidConfigID)
		return
	}
	var body transitionDynamicSecretConfigDisabledBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.Config.ID = uint(id)
	cfg := body.Config.toModel()
	matched, err := h.coreService.Storage().TransitionDynamicSecretConfigDisabled(r.Context(), cfg, body.FromDisabled)
	if err != nil {
		log.Printf("dynamic-secrets proxy: transition config failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}

// CountDynamicSecretConfigsByClassificationProxy handles GET
// /api/v1/system/dynamic-secrets/configs/classification-counts (a static path,
// registered before /configs/{id} in router.go).
func (h *DynamicSecretHandler) CountDynamicSecretConfigsByClassificationProxy(w http.ResponseWriter, r *http.Request) {
	counts, err := h.coreService.Storage().CountDynamicSecretConfigsByClassification(r.Context())
	if err != nil {
		log.Printf("dynamic-secrets proxy: count-by-classification failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"counts": counts})
}

// CreateDynamicSecretLeaseProxy handles POST /api/v1/system/dynamic-secrets/leases.
// The calling server has already minted the credential on the target and
// encrypted it with its own key (internal/core.IssueLease) before this call — this
// only persists the resulting lease row (with its opaque ciphertext).
func (h *DynamicSecretHandler) CreateDynamicSecretLeaseProxy(w http.ResponseWriter, r *http.Request) {
	var body dynamicSecretLeaseProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.ConfigID == 0 || body.LeaseID == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "config_id and lease_id are required")
		return
	}
	created, err := h.coreService.Storage().CreateDynamicSecretLease(r.Context(), body.toModel())
	if err != nil {
		log.Printf("dynamic-secrets proxy: create lease failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newDynamicSecretLeaseProxyWire(created))
}

// GetDynamicSecretLeaseProxy handles GET /api/v1/system/dynamic-secrets/leases/{leaseID}.
func (h *DynamicSecretHandler) GetDynamicSecretLeaseProxy(w http.ResponseWriter, r *http.Request) {
	leaseID := chi.URLParam(r, "leaseID")
	lease, err := h.coreService.Storage().GetDynamicSecretLease(r.Context(), leaseID)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "lease not found")
			return
		}
		log.Printf("dynamic-secrets proxy: get lease failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newDynamicSecretLeaseProxyWire(lease))
}

// ListDynamicSecretLeasesProxy handles GET
// /api/v1/system/dynamic-secrets/leases?config_id=X.
func (h *DynamicSecretHandler) ListDynamicSecretLeasesProxy(w http.ResponseWriter, r *http.Request) {
	configID, ok := parseProxyConfigIDQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListDynamicSecretLeases(r.Context(), configID)
	if err != nil {
		log.Printf("dynamic-secrets proxy: list leases failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]dynamicSecretLeaseProxyWire, 0, len(rows))
	for _, l := range rows {
		wire = append(wire, newDynamicSecretLeaseProxyWire(l))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"leases": wire})
}

// CountActiveLeasesProxy handles GET
// /api/v1/system/dynamic-secrets/leases/active-count?config_id=X (a static path,
// registered before /leases/{leaseID} in router.go).
func (h *DynamicSecretHandler) CountActiveLeasesProxy(w http.ResponseWriter, r *http.Request) {
	configID, ok := parseProxyConfigIDQuery(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().CountActiveLeases(r.Context(), configID)
	if err != nil {
		log.Printf("dynamic-secrets proxy: count active leases failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"count": n})
}

// UpdateDynamicSecretLeaseProxy handles PUT /api/v1/system/dynamic-secrets/leases/{leaseID}.
// A raw persist (storage.Storage.UpdateDynamicSecretLease is an unconditional
// full-row Save, matching LocalStorage's own semantics exactly — the calling
// server's own core.RevokeLease/RenewLease already re-fetches the lease and checks
// its status before mutating it, exactly as it does against a local backend; this
// proxy adds no NEW atomicity guarantee beyond what LocalStorage already provides,
// and removes none).
func (h *DynamicSecretHandler) UpdateDynamicSecretLeaseProxy(w http.ResponseWriter, r *http.Request) {
	leaseID := chi.URLParam(r, "leaseID")
	var body dynamicSecretLeaseProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.LeaseID = leaseID
	if err := h.coreService.Storage().UpdateDynamicSecretLease(r.Context(), body.toModel()); err != nil {
		log.Printf("dynamic-secrets proxy: update lease failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// ListExpiredActiveLeasesProxy handles GET
// /api/v1/system/dynamic-secrets/leases/expired?before=<RFC3339> (a static path,
// registered before /leases/{leaseID} in router.go). Backs the calling server's
// OWN auto-revoke sweep (internal/core.RevokeExpiredLeases) against this server's
// real storage backend.
func (h *DynamicSecretHandler) ListExpiredActiveLeasesProxy(w http.ResponseWriter, r *http.Request) {
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
	// Reparsing an RFC3339 "Z"-suffixed wire timestamp always yields a UTC
	// time.Time — but this server's OWN ExpiresAt rows were stored using
	// whichever timezone its process clock (c.now = time.Now()) runs in, and
	// GORM's SQLite driver formats a bound time.Time parameter's TEXT
	// representation using ITS OWN Location, not a canonical one. If this
	// server's process timezone is not UTC, comparing a UTC-formatted `before`
	// against locally-formatted stored rows via SQLite's TEXT `<` operator can
	// silently give the WRONG answer for genuinely-expired rows (verified
	// empirically: a lease expired exactly 1 hour ago was excluded entirely,
	// because "07:...+0000" sorts lexicographically before "08:...+0200" even
	// though the latter is the earlier instant). Convert to Local so this
	// proxy's comparison matches the SAME convention every other ExpiresAt
	// comparison in this codebase already uses (time.Now(), never time.Now().UTC()).
	rows, err := h.coreService.Storage().ListExpiredActiveLeases(r.Context(), before.Local())
	if err != nil {
		log.Printf("dynamic-secrets proxy: list expired leases failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]dynamicSecretLeaseProxyWire, 0, len(rows))
	for _, l := range rows {
		wire = append(wire, newDynamicSecretLeaseProxyWire(l))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"leases": wire})
}

// parseProxyScopeQuery parses the optional project_id/environment_id query
// parameters shared by ListDynamicSecretConfigsProxy. project_id is required (0
// is not a valid project); environment_id 0 means "all environments" — mirroring
// core.ListDynamicSecretConfigs' own storage-layer contract.
func parseProxyScopeQuery(w http.ResponseWriter, r *http.Request) (projectID, environmentID uint, ok bool) {
	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id query parameter is required")
		return 0, 0, false
	}
	pid, err := strconv.ParseUint(projectIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return 0, 0, false
	}
	projectID = uint(pid)
	if v := r.URL.Query().Get("environment_id"); v != "" {
		eid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "environment_id must be a valid integer")
			return 0, 0, false
		}
		environmentID = uint(eid)
	}
	return projectID, environmentID, true
}

// parseProxyConfigIDQuery parses the required config_id query parameter shared by
// ListDynamicSecretLeasesProxy/CountActiveLeasesProxy.
func parseProxyConfigIDQuery(w http.ResponseWriter, r *http.Request) (configID uint, ok bool) {
	v := r.URL.Query().Get("config_id")
	if v == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "config_id query parameter is required")
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "config_id must be a valid integer")
		return 0, false
	}
	return uint(id), true
}
