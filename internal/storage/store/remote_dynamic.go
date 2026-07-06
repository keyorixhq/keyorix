// remote_dynamic.go — dynamic-secrets storage primitives for RemoteStorage
// (ADR-035/ADR-049): thin passthroughs onto ten new server-side routes under
// /api/v1/system/dynamic-secrets (server/http/handlers/dynamic_secrets_proxy.go),
// mirroring the #452-follow-up login-attempts proxy and #507's invitations proxy
// pattern exactly: gated on the SAME broad system.read/system.write RBAC
// permissions a RemoteStorage credential already needs for every other proxied
// call, so this introduces no new privilege class.
//
// No dynamic-secrets POLICY decision (admin-authority binding check, TTL/max-lease
// clamping, active-lease ceiling enforcement, disabled/soft-deleted-project
// refusal, or the encrypt/decrypt of the admin DSN and issued credential) is made
// in these routes — that stays entirely in the CALLING server's own
// internal/core.KeyorixCore (internal/core/dynamic_secrets.go), exactly as it does
// against a local backend.
//
// Sensitive-data boundary (investigated, not assumed): the admin DSN
// (models.DynamicSecretConfig.AdminDSNEnc/AdminDSNMeta) and each issued credential
// (models.DynamicSecretLease.CredentialEnc/CredentialMeta) are encrypted by
// internal/core (KeyorixCore.encryptAuthSecret/decryptAuthSecret) using the
// CALLING server's own encryption key, BEFORE the config/lease is ever handed to
// this package's methods below — never in plaintext, and never by the upstream
// server this proxies to. The wire DTOs below carry that ciphertext as opaque
// bytes; the upstream server's proxy handlers never decrypt it (see
// dynamic_secrets_proxy.go's package doc for the full reasoning, including why
// this is a STRONGER boundary than remote_secrets.go's CreateSecret, which does
// send an ordinary secret's plaintext value across the wire once).
//
// A genuine, deliberate scope boundary: CreateDynamicSecretConfig/IssueLease
// themselves — i.e. actually minting a live credential against a target database
// or cloud-IAM engine — can only ever run on whichever server calls these methods
// (this codebase's dynamic.CredentialEngine implementations dial the target
// directly), which for a storage.type: remote deployment is the DOWNSTREAM
// ("spoke") server, not the upstream one these routes live on. That is unchanged
// by this fix: these are storage-persistence primitives only, exactly like every
// other RemoteStorage method — they do not make a spoke deployment capable of
// engine.Issue/engine.Revoke against a target it has no network path to; that
// requirement was already true (and unrelated to storage.type).
//
// UpdateDynamicSecretLease/UpdateDynamicSecretConfig atomicity: LocalStorage's own
// implementations (internal/storage/store/local_dynamic.go) are both an
// unconditional full-row `Save`, not a conditional/optimistic-concurrency write
// (unlike, say, UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'`).
// internal/core.RevokeLease/RenewLease already re-fetch the lease and check its
// status before mutating it — a check-then-act sequence with exactly the same
// (small, pre-existing, accepted) race window against a local backend as against
// this proxy. This fix preserves that behavior exactly rather than introducing a
// stricter guarantee the local backend itself doesn't have.
//
// For the local (GORM) equivalent of every primitive here see local_dynamic.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// dynamicSecretConfigWire mirrors dynamicSecretConfigProxyWire in
// server/http/handlers/dynamic_secrets_proxy.go exactly — see that type's comment
// for why every field (including the admin-DSN ciphertext) is named explicitly.
type dynamicSecretConfigWire struct {
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

func newDynamicSecretConfigWire(c *models.DynamicSecretConfig) dynamicSecretConfigWire {
	return dynamicSecretConfigWire{
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

func (w dynamicSecretConfigWire) toModel() *models.DynamicSecretConfig {
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

func decodeDynamicSecretConfigResponse(data []byte) (*models.DynamicSecretConfig, error) {
	var wire dynamicSecretConfigWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// dynamicSecretLeaseWire mirrors dynamicSecretLeaseProxyWire exactly.
type dynamicSecretLeaseWire struct {
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

func newDynamicSecretLeaseWire(l *models.DynamicSecretLease) dynamicSecretLeaseWire {
	return dynamicSecretLeaseWire{
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

func (w dynamicSecretLeaseWire) toModel() *models.DynamicSecretLease {
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

func decodeDynamicSecretLeaseResponse(data []byte) (*models.DynamicSecretLease, error) {
	var wire dynamicSecretLeaseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// CreateDynamicSecretConfig persists an already-built config (metadata only —
// AdminDSNEnc/AdminDSNMeta are typically still empty at this point, mirroring
// internal/core.CreateDynamicSecretConfig's own two-phase create-then-update, #94)
// via POST /api/v1/system/dynamic-secrets/configs.
func (rs *RemoteStorage) CreateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/dynamic-secrets/configs", newDynamicSecretConfigWire(c))
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic-secret config: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create dynamic-secret config failed: %s", resp.Error.Error())
	}
	return decodeDynamicSecretConfigResponse(resp.Data)
}

// GetDynamicSecretConfig retrieves a config by ID via GET
// /api/v1/system/dynamic-secrets/configs/{id} — including its admin-DSN
// ciphertext, which the CALLING server (not this package) decrypts.
func (rs *RemoteStorage) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	path := fmt.Sprintf("/api/v1/system/dynamic-secrets/configs/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get dynamic-secret config: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get dynamic-secret config failed: %s", resp.Error.Error())
	}
	return decodeDynamicSecretConfigResponse(resp.Data)
}

// ListDynamicSecretConfigs lists a project's (optionally environment-scoped)
// configs via GET /api/v1/system/dynamic-secrets/configs?project_id=&environment_id=.
func (rs *RemoteStorage) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	q := url.Values{}
	q.Set("project_id", strconv.FormatUint(uint64(projectID), 10))
	if environmentID != 0 {
		q.Set("environment_id", strconv.FormatUint(uint64(environmentID), 10))
	}
	path := "/api/v1/system/dynamic-secrets/configs?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list dynamic-secret configs: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list dynamic-secret configs failed: %s", resp.Error.Error())
	}
	var result struct {
		Configs []dynamicSecretConfigWire `json:"configs"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.DynamicSecretConfig, 0, len(result.Configs))
	for _, w := range result.Configs {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// UpdateDynamicSecretConfig persists the full config row (including, on the
// second phase of a create, the now-encrypted admin-DSN ciphertext) via PUT
// /api/v1/system/dynamic-secrets/configs/{id}. Matches LocalStorage's own
// unconditional full-row Save semantics exactly — see the package doc for why no
// conditional write is needed here.
func (rs *RemoteStorage) UpdateDynamicSecretConfig(ctx context.Context, c *models.DynamicSecretConfig) error {
	path := fmt.Sprintf("/api/v1/system/dynamic-secrets/configs/%d", c.ID)
	resp, err := rs.client.Put(ctx, path, newDynamicSecretConfigWire(c))
	if err != nil {
		return fmt.Errorf("failed to update dynamic-secret config: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update dynamic-secret config failed: %s", resp.Error.Error())
	}
	return nil
}

// CountDynamicSecretConfigsByClassification returns install-wide config counts
// keyed by classification label via GET
// /api/v1/system/dynamic-secrets/configs/classification-counts.
func (rs *RemoteStorage) CountDynamicSecretConfigsByClassification(ctx context.Context) (map[string]int, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/dynamic-secrets/configs/classification-counts")
	if err != nil {
		return nil, fmt.Errorf("failed to count dynamic-secret configs by classification: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("count dynamic-secret configs by classification failed: %s", resp.Error.Error())
	}
	var result struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Counts, nil
}

// CreateDynamicSecretLease persists an already-issued lease (the credential was
// minted on the target and encrypted by the CALLING server's own
// internal/core.IssueLease before this call) via POST
// /api/v1/system/dynamic-secrets/leases.
func (rs *RemoteStorage) CreateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/dynamic-secrets/leases", newDynamicSecretLeaseWire(l))
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic-secret lease: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create dynamic-secret lease failed: %s", resp.Error.Error())
	}
	return decodeDynamicSecretLeaseResponse(resp.Data)
}

// GetDynamicSecretLease retrieves a lease by its opaque public LeaseID via GET
// /api/v1/system/dynamic-secrets/leases/{leaseID}.
func (rs *RemoteStorage) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	path := fmt.Sprintf("/api/v1/system/dynamic-secrets/leases/%s", url.PathEscape(leaseID))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get dynamic-secret lease: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get dynamic-secret lease failed: %s", resp.Error.Error())
	}
	return decodeDynamicSecretLeaseResponse(resp.Data)
}

// ListDynamicSecretLeases lists a config's leases via GET
// /api/v1/system/dynamic-secrets/leases?config_id=X.
func (rs *RemoteStorage) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	q := url.Values{}
	q.Set("config_id", strconv.FormatUint(uint64(configID), 10))
	path := "/api/v1/system/dynamic-secrets/leases?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list dynamic-secret leases: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list dynamic-secret leases failed: %s", resp.Error.Error())
	}
	var result struct {
		Leases []dynamicSecretLeaseWire `json:"leases"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.DynamicSecretLease, 0, len(result.Leases))
	for _, w := range result.Leases {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}

// CountActiveLeases returns how many of a config's leases still hold a live
// credential upstream via GET
// /api/v1/system/dynamic-secrets/leases/active-count?config_id=X.
func (rs *RemoteStorage) CountActiveLeases(ctx context.Context, configID uint) (int64, error) {
	q := url.Values{}
	q.Set("config_id", strconv.FormatUint(uint64(configID), 10))
	path := "/api/v1/system/dynamic-secrets/leases/active-count?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return 0, fmt.Errorf("failed to count active dynamic-secret leases: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("count active dynamic-secret leases failed: %s", resp.Error.Error())
	}
	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Count, nil
}

// UpdateDynamicSecretLease persists the full lease row (status transitions,
// revoke bookkeeping, renewed expiry) via PUT
// /api/v1/system/dynamic-secrets/leases/{leaseID}. Matches LocalStorage's own
// unconditional full-row Save semantics exactly — see the package doc for why no
// conditional write is needed here.
func (rs *RemoteStorage) UpdateDynamicSecretLease(ctx context.Context, l *models.DynamicSecretLease) error {
	path := fmt.Sprintf("/api/v1/system/dynamic-secrets/leases/%s", url.PathEscape(l.LeaseID))
	resp, err := rs.client.Put(ctx, path, newDynamicSecretLeaseWire(l))
	if err != nil {
		return fmt.Errorf("failed to update dynamic-secret lease: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("update dynamic-secret lease failed: %s", resp.Error.Error())
	}
	return nil
}

// ListExpiredActiveLeases lists every lease past `before` that still needs its
// target credential dropped, via GET
// /api/v1/system/dynamic-secrets/leases/expired?before=<RFC3339Nano> — backing the
// CALLING server's own auto-revoke sweep (internal/core.RevokeExpiredLeases).
func (rs *RemoteStorage) ListExpiredActiveLeases(ctx context.Context, before time.Time) ([]*models.DynamicSecretLease, error) {
	q := url.Values{}
	q.Set("before", before.UTC().Format(time.RFC3339Nano))
	path := "/api/v1/system/dynamic-secrets/leases/expired?" + q.Encode()
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list expired dynamic-secret leases: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list expired dynamic-secret leases failed: %s", resp.Error.Error())
	}
	var result struct {
		Leases []dynamicSecretLeaseWire `json:"leases"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	rows := make([]*models.DynamicSecretLease, 0, len(result.Leases))
	for _, w := range result.Leases {
		rows = append(rows, w.toModel())
	}
	return rows, nil
}
