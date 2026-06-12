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
	CreatedBy         string
}

// IssuedLease is the credential returned to the caller once, on issue.
type IssuedLease struct {
	LeaseID   string    `json:"lease_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
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
		_ = engine.Revoke(ctx, adminDSN, roleName)
		return nil, fmt.Errorf("failed to encrypt credential: %w", err)
	}

	leaseID, err := generateSecureToken()
	if err != nil {
		_ = engine.Revoke(ctx, adminDSN, roleName)
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
		_ = engine.Revoke(ctx, adminDSN, roleName)
		return nil, fmt.Errorf("failed to persist lease: %w", err)
	}
	uid := userID
	pid := cfg.ProjectID
	c.writeAuditEventFull(ctx, "dynamic_lease.issued", &uid, nil, &pid, "",
		fmt.Sprintf("issued dynamic credential (lease=%s, config=%q, ttl=%s)", lease.LeaseID, cfg.Name, ttl))
	return &IssuedLease{LeaseID: lease.LeaseID, Username: cred.Username, Password: cred.Password, ExpiresAt: expiresAt}, nil
}

// RevokeLease revokes a lease on the target and marks it revoked (or
// revoke_failed if the target drop fails, surfacing it to an operator).
func (c *KeyorixCore) RevokeLease(ctx context.Context, leaseID string, userID uint, reason string) error {
	lease, err := c.storage.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("lease not found")
	}
	if lease.Status != "active" {
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
		lease.RevokedAt = &now
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

// RevokeExpiredLeases is the auto-revoke sweep: it revokes every active lease
// past its expiry (system-actored). Returns the count revoked.
func (c *KeyorixCore) RevokeExpiredLeases(ctx context.Context, before time.Time) (int, error) {
	expired, err := c.storage.ListExpiredActiveLeases(ctx, before)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for _, l := range expired {
		if err := c.RevokeLease(ctx, l.LeaseID, 0, "expired"); err == nil {
			revoked++
		}
	}
	return revoked, nil
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
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, lease.ConfigID)
	if err != nil {
		return time.Time{}, fmt.Errorf("config not found")
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
