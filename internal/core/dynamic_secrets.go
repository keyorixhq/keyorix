// dynamic_secrets.go — on-demand database credentials (ADR-035): an operator
// registers a target (DynamicSecretConfig); callers issue short-lived leases that
// mint a role on the target; an auto-revoke sweep drops them at expiry. The admin
// DSN and each issued credential are encrypted at rest.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const defaultDynamicTTL = 1 * time.Hour

// CreateDynamicSecretConfigRequest registers a dynamic-secrets target.
type CreateDynamicSecretConfigRequest struct {
	Name              string
	ProjectID         uint
	EnvironmentID     uint
	BackendType       string
	AdminDSN          string
	CreationTemplate  string
	DefaultTTLSeconds int
	MaxTTLSeconds     int
	MaxActiveLeases   int
	CreatedBy         string
	// Classification is an optional data-sensitivity label (A.5.12) for the
	// credentials this config mints: "" or one of public|internal|confidential|restricted.
	Classification string
}

// IssuedLease is the credential returned to the caller once, on issue. Database
// backends populate Username/Password; cloud-IAM backends (AWS STS) leave those
// empty and populate Fields (access_key_id, secret_access_key, session_token, …).
type IssuedLease struct {
	LeaseID   string            `json:"lease_id"`
	Username  string            `json:"username,omitempty"`
	Password  string            `json:"password,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// CreateDynamicSecretConfig validates the backend, encrypts the admin DSN, and
// stores the config.
func (c *KeyorixCore) CreateDynamicSecretConfig(ctx context.Context, req *CreateDynamicSecretConfigRequest) (*models.DynamicSecretConfig, error) {
	if req.Name == "" || req.ProjectID == 0 || req.AdminDSN == "" {
		return nil, fmt.Errorf("name, project_id and admin_dsn are required")
	}
	if _, err := c.dynamicEngine(req.BackendType); err != nil {
		return nil, err
	}
	if req.MaxTTLSeconds > 0 && req.DefaultTTLSeconds > req.MaxTTLSeconds {
		return nil, fmt.Errorf("default_ttl_seconds (%d) cannot exceed max_ttl_seconds (%d)", req.DefaultTTLSeconds, req.MaxTTLSeconds)
	}
	if !IsValidClassification(req.Classification) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty)")
	}
	dsnEnc, dsnMeta, err := c.encryptAuthSecret(req.AdminDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt admin DSN: %w", err)
	}
	cfg, err := c.storage.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name:              req.Name,
		ProjectID:         req.ProjectID,
		EnvironmentID:     req.EnvironmentID,
		BackendType:       req.BackendType,
		AdminDSNEnc:       dsnEnc,
		AdminDSNMeta:      dsnMeta,
		CreationTemplate:  req.CreationTemplate,
		DefaultTTLSeconds: req.DefaultTTLSeconds,
		MaxTTLSeconds:     req.MaxTTLSeconds,
		MaxActiveLeases:   req.MaxActiveLeases,
		Classification:    req.Classification,
		CreatedBy:         req.CreatedBy,
		CreatedAt:         c.now(),
		UpdatedAt:         c.now(),
	})
	if err != nil {
		return nil, err
	}
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_secret.config_created", nil, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q (%s) created in project %d", cfg.Name, cfg.BackendType, cfg.ProjectID))
	return cfg, nil
}

func (c *KeyorixCore) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	return c.storage.GetDynamicSecretConfig(ctx, id)
}

func (c *KeyorixCore) ListDynamicSecretConfigs(ctx context.Context, projectID, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	return c.storage.ListDynamicSecretConfigs(ctx, projectID, environmentID)
}

// ClassifyDynamicSecretConfig sets (or clears, with "") the data-classification
// label on a dynamic-secret config and audits the change with a before/after diff.
func (c *KeyorixCore) ClassifyDynamicSecretConfig(ctx context.Context, actorID uint, configID uint, level string) (*models.DynamicSecretConfig, error) {
	if configID == 0 {
		return nil, fmt.Errorf("config id is required")
	}
	if !IsValidClassification(level) {
		return nil, fmt.Errorf("classification must be one of public, internal, confidential, restricted (or empty to clear)")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found: %w", err)
	}
	if cfg.Classification == level {
		return cfg, nil // no-op
	}
	old := cfg.Classification
	cfg.Classification = level
	cfg.UpdatedAt = c.now()
	if err := c.storage.UpdateDynamicSecretConfig(ctx, cfg); err != nil {
		return nil, err
	}
	aid := actorID
	pid := cfg.ProjectID
	diff := fmt.Sprintf(`{"classification":{"before":%q,"after":%q}}`, old, level)
	c.writeAuditEventDiff(ctx, "dynamic_secret.config_classified", &aid, nil, &pid, "",
		fmt.Sprintf("dynamic-secret config %q classification set to %q", cfg.Name, level), diff)
	return cfg, nil
}

func (c *KeyorixCore) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	return c.storage.ListDynamicSecretLeases(ctx, configID)
}

func (c *KeyorixCore) GetDynamicSecretLease(ctx context.Context, leaseID string) (*models.DynamicSecretLease, error) {
	return c.storage.GetDynamicSecretLease(ctx, leaseID)
}

// IssueLease mints a short-lived credential on the target and persists the lease.
// The plaintext credential is returned ONCE; only its encrypted form is stored.
// ttlSeconds<=0 uses the config default (or 1h).
func (c *KeyorixCore) IssueLease(ctx context.Context, configID uint, ttlSeconds int, userID uint) (*IssuedLease, error) {
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("dynamic-secret config not found")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return nil, err
	}
	// A backend with no DB-level expiry (MySQL/MongoDB) relies entirely on the
	// auto-revoke sweeper to enforce the lease TTL. Issuing from it while the
	// sweeper is disabled would mint a credential whose advertised expiry is never
	// enforced — a false promise — so refuse and point the operator at the fix.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return nil, fmt.Errorf("cannot issue from the %s backend while the auto-revoke sweeper is disabled: its lease TTL is enforced only by the sweeper, so the credential would never expire — enable dynamic_secrets.sweep_enabled", cfg.BackendType)
	}
	// Enforce the config's active-lease ceiling so a caller can't mint unbounded real DB
	// roles/users (resource exhaustion on the target). A small race under concurrency is
	// acceptable for a soft resource cap.
	if cfg.MaxActiveLeases > 0 {
		active, cerr := c.storage.CountActiveLeases(ctx, configID)
		if cerr != nil {
			return nil, fmt.Errorf("failed to check active lease count: %w", cerr)
		}
		if active >= int64(cfg.MaxActiveLeases) {
			return nil, fmt.Errorf("active-lease limit reached for this config (%d); revoke a lease before issuing another", cfg.MaxActiveLeases)
		}
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	ttl := c.dynamicTTL(cfg, ttlSeconds)

	cred, roleName, err := engine.Issue(ctx, adminDSN, cfg.CreationTemplate, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to issue credential: %w", err)
	}
	credJSON, _ := json.Marshal(cred) // #nosec G117 -- intentional: serialized only to be immediately encrypted at rest below, never persisted or logged in cleartext
	credEnc, credMeta, err := c.encryptAuthSecret(string(credJSON))
	if err != nil {
		// The role exists on the target — revoke it so we don't leak it.
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, fmt.Errorf("failed to encrypt credential: %w", err)
	}

	leaseID, err := generateSecureToken()
	if err != nil {
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, err
	}
	expiresAt := c.now().Add(ttl)
	lease, err := c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID:       cfg.ID,
		LeaseID:        leaseID,
		ProjectID:      cfg.ProjectID,
		EnvironmentID:  cfg.EnvironmentID,
		RoleName:       roleName,
		CredentialEnc:  credEnc,
		CredentialMeta: credMeta,
		Status:         "active",
		IssuedAt:       c.now(),
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		c.cleanupOrphanedRole(ctx, cfg, engine, adminDSN, roleName, userID)
		return nil, fmt.Errorf("failed to persist lease: %w", err)
	}
	uid := userID
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.issued", &uid, nil, &pid, "",
		fmt.Sprintf("issued dynamic credential (lease=%s, config=%q, ttl=%s)", lease.LeaseID, cfg.Name, ttl))
	return &IssuedLease{LeaseID: lease.LeaseID, Username: cred.Username, Password: cred.Password, Fields: cred.Fields, ExpiresAt: expiresAt}, nil
}

// cleanupOrphanedRole drops a just-minted role after a post-mint failure aborts the
// issue (encryption / token-gen / lease-persist failed). If the drop itself fails,
// the role would otherwise be a LIVE credential with no lease row — invisible to
// every list/sweep/revoke path (all keyed off the lease table) and therefore
// permanent and undrop-able. To keep it visible, we record a revoke_failed lease
// capturing the role name and audit it, mirroring RevokeLease's failure handling.
func (c *KeyorixCore) cleanupOrphanedRole(ctx context.Context, cfg *models.DynamicSecretConfig, engine dynamic.CredentialEngine, adminDSN, roleName string, userID uint) {
	if err := engine.Revoke(ctx, adminDSN, roleName); err == nil {
		return // role dropped cleanly — nothing to track
	} else {
		now := c.now()
		leaseID, gerr := generateSecureToken()
		if gerr != nil {
			leaseID = "orphan-" + roleName // last-resort id so the row still persists
		}
		// No credential is stored — the issue was aborted; only the role name
		// matters so an operator can drop it. CredentialEnc is intentionally empty.
		_, _ = c.storage.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
			ConfigID:      cfg.ID,
			LeaseID:       leaseID,
			ProjectID:     cfg.ProjectID,
			EnvironmentID: cfg.EnvironmentID,
			RoleName:      roleName,
			Status:        "revoke_failed",
			RevokeError:   "orphaned on aborted issue: " + err.Error(),
			IssuedAt:      now,
			ExpiresAt:     now,
			RevokedAt:     &now,
		})
		var uidPtr *uint
		if userID != 0 {
			uidPtr = &userID
		}
		var pidPtr *uint
		if cfg.ProjectID != 0 {
			pid := cfg.ProjectID
			pidPtr = &pid
		}
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, pidPtr, "",
			fmt.Sprintf("FAILED to clean up orphaned dynamic role %s after an aborted issue (config=%q): %v — drop it manually", roleName, cfg.Name, err))
	}
}

// RevokeLease revokes a lease on the target and marks it revoked (or
// revoke_failed if the target drop fails, surfacing it to an operator).
func (c *KeyorixCore) RevokeLease(ctx context.Context, leaseID string, userID uint, reason string) error {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("lease not found")
	}
	// Admit revoke_failed too: a prior revoke whose target drop failed left the underlying
	// credential LIVE, so it must remain retryable (manually or via the sweep). Only an
	// already-revoked/expired lease is a no-op.
	if lease.Status != "active" && lease.Status != "revoke_failed" {
		return fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return fmt.Errorf("config not found")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return err
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta)
	if err != nil {
		return fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	now := c.now()
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := lease.ProjectID
	if rerr := engine.Revoke(ctx, adminDSN, lease.RoleName); rerr != nil {
		lease.Status = "revoke_failed"
		lease.RevokeError = rerr.Error()
		// Deliberately NOT stamping RevokedAt here: the target drop failed, so the
		// credential is still live. Stamping it would make the audit trail / API
		// falsely claim the role was dropped at this time, even though it wasn't —
		// and it wasn't dropped at all yet, so there is no "revoked at" moment to
		// record. RevokedAt is set only on the success path below.
		_ = c.storage.UpdateDynamicSecretLease(ctx, lease)
		c.writeAuditEventFull(ctx, "dynamic_lease.revoke_failed", uidPtr, nil, &pid, "",
			fmt.Sprintf("FAILED to revoke dynamic lease %s (role %s): %v", lease.LeaseID, lease.RoleName, rerr))
		return fmt.Errorf("failed to revoke on target: %w", rerr)
	}
	lease.Status = "revoked"
	lease.RevokeReason = reason
	lease.RevokedAt = &now
	if err := c.storage.UpdateDynamicSecretLease(ctx, lease); err != nil {
		return err
	}
	c.writeAuditEventFull(ctx, "dynamic_lease.revoked", uidPtr, nil, &pid, "",
		fmt.Sprintf("revoked dynamic lease %s (reason=%s)", lease.LeaseID, reason))
	return nil
}

// RevokeExpiredLeases is the auto-revoke sweep: it revokes every active (or previously
// revoke_failed) lease past its expiry (system-actored). Returns the count revoked and a
// non-nil error if any revoke failed, so the scheduler records the partial failure rather
// than reporting a clean sweep while credentials remain live past their TTL.
func (c *KeyorixCore) RevokeExpiredLeases(ctx context.Context, before time.Time) (int, error) {
	expired, err := c.storage.ListExpiredActiveLeases(ctx, before)
	if err != nil {
		return 0, err
	}
	revoked, failed := 0, 0
	for _, l := range expired {
		if err := c.RevokeLease(ctx, l.LeaseID, 0, "expired"); err == nil {
			revoked++
		} else {
			failed++
		}
	}
	if failed > 0 {
		return revoked, fmt.Errorf("dynamic-secrets sweep: %d of %d expired lease(s) failed to revoke — those credentials remain live past their TTL", failed, len(expired))
	}
	return revoked, nil
}

// RevokeLeasesForConfig revokes every active lease issued from a config — an
// incident-response kill switch for a config's outstanding dynamic credentials
// (e.g. a compromised target DB or config). Returns the counts revoked and failed
// (each revoke is audited per-lease as well). Best-effort: one lease's revoke
// failure does not stop the others.
func (c *KeyorixCore) RevokeLeasesForConfig(ctx context.Context, configID, userID uint, reason string) (revoked, failed int, err error) {
	leases, err := c.storage.ListDynamicSecretLeases(ctx, configID)
	if err != nil {
		return 0, 0, err
	}
	for _, l := range leases {
		// Retry a previously-failed revoke too — its credential is still live.
		if l.Status != "active" && l.Status != "revoke_failed" {
			continue
		}
		if rerr := c.RevokeLease(ctx, l.LeaseID, userID, reason); rerr != nil {
			failed++
		} else {
			revoked++
		}
	}
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &userID
	}
	pid := uint(0)
	if cfg, gerr := c.storage.GetDynamicSecretConfig(ctx, configID); gerr == nil {
		pid = cfg.ProjectID
	}
	var pidPtr *uint
	if pid != 0 {
		pidPtr = &pid
	}
	c.writeAuditEventFull(ctx, "dynamic_secret.bulk_revoke", uidPtr, nil, pidPtr, "",
		fmt.Sprintf("bulk-revoked dynamic leases for config %d (revoked=%d, failed=%d, reason=%s)", configID, revoked, failed, reason))
	return revoked, failed, nil
}

// dynamicTTL resolves the requested TTL (override, else config default, else 1h)
// and clamps it to the config's MaxTTLSeconds ceiling when one is set.
func (c *KeyorixCore) dynamicTTL(cfg *models.DynamicSecretConfig, override int) time.Duration {
	ttl := defaultDynamicTTL
	switch {
	case override > 0:
		ttl = time.Duration(override) * time.Second
	case cfg.DefaultTTLSeconds > 0:
		ttl = time.Duration(cfg.DefaultTTLSeconds) * time.Second
	}
	if cfg.MaxTTLSeconds > 0 {
		if max := time.Duration(cfg.MaxTTLSeconds) * time.Second; ttl > max {
			ttl = max
		}
	}
	return ttl
}

// RenewLease extends an active lease's expiry by ttlSeconds (or the config
// default), capped so the lease's total lifetime from issue never exceeds the
// config's MaxTTLSeconds. On backends with a DB-level expiry (PostgreSQL) it also
// pushes the role's VALID UNTIL forward. Returns the new expiry.
func (c *KeyorixCore) RenewLease(ctx context.Context, leaseID string, ttlSeconds int, userID uint) (time.Time, error) {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return time.Time{}, fmt.Errorf("lease not found")
	}
	if lease.Status != "active" {
		return time.Time{}, fmt.Errorf("lease is not active (status %s)", lease.Status)
	}
	// A lease whose expiry has already passed is logically dead even if the sweeper
	// has not yet flipped its status (sweep disabled, or not run yet). Renewing it
	// would push the backend credential's lifetime forward — resurrecting a
	// credential that should be gone, violating the promised TTL — and would race the
	// sweep that is about to revoke it. Refuse; the caller must issue a new lease.
	if !c.now().Before(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("lease has expired; issue a new lease instead")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return time.Time{}, fmt.Errorf("config not found")
	}
	// Cloud-IAM backends (AWS STS) mint self-expiring credentials whose lifetime is
	// fixed by the provider at issue — they cannot be renewed; issue a new lease.
	if eng, eerr := c.dynamicEngine(cfg.BackendType); eerr == nil && eng.IsEphemeralBackend() {
		return time.Time{}, fmt.Errorf("the %s backend mints self-expiring credentials that cannot be renewed; issue a new lease instead", cfg.BackendType)
	}
	newExpiry := c.now().Add(c.dynamicTTL(cfg, ttlSeconds))
	// Never let renewal push total lifetime past the config's max-TTL ceiling.
	if cfg.MaxTTLSeconds > 0 {
		if hardCap := lease.IssuedAt.Add(time.Duration(cfg.MaxTTLSeconds) * time.Second); newExpiry.After(hardCap) {
			newExpiry = hardCap
		}
	}
	if !newExpiry.After(lease.ExpiresAt) {
		return time.Time{}, fmt.Errorf("renewal would not extend the lease (max-TTL ceiling reached)")
	}
	engine, err := c.dynamicEngine(cfg.BackendType)
	if err != nil {
		return time.Time{}, err
	}
	// A backend with no DB-level expiry relies entirely on the sweeper to enforce a
	// lease's TTL. With the sweeper disabled, a renewal would extend a credential nothing
	// will ever revoke — mirror IssueLease's fail-closed refusal.
	if !engine.SupportsNativeExpiry() && !c.dynamicSweepEnabled {
		return time.Time{}, fmt.Errorf("renewal is unavailable for the %s backend while the lease sweeper is disabled (its TTL would be unenforced)", cfg.BackendType)
	}
	adminDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decrypt admin DSN: %w", err)
	}
	if err := engine.Renew(ctx, adminDSN, lease.RoleName, newExpiry); err != nil {
		return time.Time{}, fmt.Errorf("failed to renew on target: %w", err)
	}
	lease.ExpiresAt = newExpiry
	if err := c.storage.UpdateDynamicSecretLease(ctx, lease); err != nil {
		return time.Time{}, err
	}
	uid := userID
	var uidPtr *uint
	if userID != 0 {
		uidPtr = &uid
	}
	pid := lease.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.renewed", uidPtr, nil, &pid, "",
		fmt.Sprintf("renewed dynamic lease %s (new expiry %s)", lease.LeaseID, newExpiry.UTC().Format(time.RFC3339)))
	return newExpiry, nil
}
