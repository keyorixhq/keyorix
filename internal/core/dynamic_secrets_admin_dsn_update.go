// dynamic_secrets_admin_dsn_update.go — replace a stored dynamic-secret config's
// admin_dsn (DYNAMIC-ADMIN-DSN-1). A config stored before #3952 can carry an
// option that makes the driver read a server file; it can no longer issue, and
// before this the only fix was to delete and recreate it (losing its ID, its
// lease history and the leases' link to it).
package core

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// UpdateDynamicSecretConfigAdminDSNRequest replaces a config's admin DSN.
type UpdateDynamicSecretConfigAdminDSNRequest struct {
	ConfigID uint
	AdminDSN string
	// ActorID is the authenticated caller, checked for admin authority at the
	// config's scope exactly as CreateDynamicSecretConfig checks it (#162).
	ActorID uint
}

// UpdateDynamicSecretConfigAdminDSN validates a new admin DSN exactly as
// CreateDynamicSecretConfig does (admin authority at the config's scope, the
// SSRF host guard, the refused local-file options), encrypts it bound to the
// config's identity and replaces the stored one. The write touches only the DSN
// columns (SetDynamicSecretConfigAdminDSN, #2651), so it cannot undo a
// concurrent disable, and it commits in one transaction with its audit row
// (withAuditedMutation): no audit row, no change. Neither the audit row nor any
// error carries the DSN.
//
// Live leases keep running: a lease's revoke reads the config's admin DSN when
// it runs, so once this commits revoke and the sweep use the new DSN. That is why
// the new DSN must name the same host(s) while the config has a live lease
// (requireSameTargetWhileLeasesLive).
func (c *KeyorixCore) UpdateDynamicSecretConfigAdminDSN(ctx context.Context, req *UpdateDynamicSecretConfigAdminDSNRequest) (*models.DynamicSecretConfig, error) {
	if req.ConfigID == 0 || req.AdminDSN == "" {
		return nil, validationErrorf("config id and admin_dsn are required")
	}
	cfg, err := c.storage.GetDynamicSecretConfig(ctx, req.ConfigID)
	if err != nil {
		return nil, classifyReadErrorAs(err, ErrDynamicSecretNotFound, "dynamic-secret config not found")
	}
	// Authority first: a caller without it learns nothing about the DSN it sent
	// (the host guard below resolves names, which is a probe of its own).
	if err := c.requireDynamicSecretAdminAuthority(ctx, req.ActorID, cfg.ProjectID, cfg.EnvironmentID); err != nil {
		return nil, err
	}
	if err := c.enforceDynamicSecretSSRFGuard(req.AdminDSN); err != nil {
		return nil, err
	}
	if err := dsn.CheckLocalFileOptions(cfg.BackendType, req.AdminDSN); err != nil {
		return nil, err
	}
	if err := c.requireSameTargetWhileLeasesLive(ctx, cfg, req.AdminDSN); err != nil {
		return nil, err
	}
	// The AAD binds the ciphertext to (id, project, environment); none of them is
	// ever rewritten on a config row, so the identity read above is the one the
	// issue/revoke paths decrypt with.
	dsnEnc, dsnMeta, err := c.encryptAuthSecret(req.AdminDSN, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt admin DSN: %w", err)
	}
	if err := validateEncryptedAdminDSNField(dsnEnc); err != nil {
		return nil, fmt.Errorf("encrypted admin DSN is invalid: %w", err)
	}
	actor, pid := req.ActorID, cfg.ProjectID
	if err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		if err := tx.SetDynamicSecretConfigAdminDSN(ctx, cfg.ID, dsnEnc, dsnMeta); err != nil {
			return fmt.Errorf("failed to persist encrypted admin DSN: %w", err)
		}
		c.writeAuditEventFullOn(ctx, tgt, "dynamic_secret.config_admin_dsn_updated", &actor, nil, &pid, "",
			fmt.Sprintf("admin_dsn of dynamic-secret config %d %q (%s) replaced in project %d", cfg.ID, cfg.Name, cfg.BackendType, cfg.ProjectID))
		return nil
	}); err != nil {
		return nil, err
	}
	cfg.AdminDSNEnc, cfg.AdminDSNMeta = dsnEnc, dsnMeta
	return cfg, nil
}

// requireSameTargetWhileLeasesLive refuses (ErrDynamicSecretPrecondition, 409 /
// FailedPrecondition) a new admin DSN that names other hosts than the stored one
// while cfg has an active or revoke_failed lease. Those leases are revoked through
// the config's DSN at the time of the revoke: pointed at another server, revoke
// and the sweep would drop a role that does not exist there, mark the lease
// revoked and leave the real credential alive on the old server. A stored DSN
// that cannot be decrypted cannot be compared, so it is refused the same way.
// Hosts are compared as parsed (dsn.ParseDSNHosts), case-insensitively; a DSN
// with no host (postgres service=, cloud backends) only matches another with none.
//
// Not covered: a lease issued between this check and the write. The window is one
// admin's own request; issue from a config with a refused option fails anyway.
func (c *KeyorixCore) requireSameTargetWhileLeasesLive(ctx context.Context, cfg *models.DynamicSecretConfig, newDSN string) error {
	leases, err := c.storage.ListDynamicSecretLeases(ctx, cfg.ID)
	if err != nil {
		return &storageReadFault{cause: fmt.Errorf("failed to list the config's leases: %w", err)}
	}
	live := 0
	for _, l := range leases {
		if l.Status == "active" || l.Status == "revoke_failed" {
			live++
		}
	}
	if live == 0 {
		return nil
	}
	oldDSN, err := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
	if err == nil && slices.Equal(normalizedDSNHosts(oldDSN), normalizedDSNHosts(newDSN)) {
		return nil
	}
	return dynamicPreconditionf("dynamic-secret config %d has %d live lease(s) and the new admin_dsn names a different host: "+
		"revoke them first (drop the roles of revoke_failed leases by hand), or create a new config for the new host", cfg.ID, live)
}

// normalizedDSNHosts is dsn.ParseDSNHosts lower-cased and sorted.
func normalizedDSNHosts(adminDSN string) []string {
	hosts := dsn.ParseDSNHosts(adminDSN)
	for i, h := range hosts {
		hosts[i] = strings.ToLower(h)
	}
	slices.Sort(hosts)
	return hosts
}
