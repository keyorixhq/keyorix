package core

import (
	"context"
	"errors"

	"github.com/keyorixhq/keyorix/internal/core/dsn"
	"github.com/keyorixhq/keyorix/internal/core/ports"
)

// RefusedAdminDSNConfig is a dynamic-secret config whose stored admin_dsn names
// an option #3952 refuses (dsn.CheckLocalFileOptions): such a config can no
// longer issue. Its live leases still revoke with the option removed, except for
// the options revoke cannot remove (internal/dynamic/revoke_dsn.go), which leave
// them revoke_failed.
type RefusedAdminDSNConfig struct {
	ConfigID      uint
	ProjectID     uint
	EnvironmentID uint
	Name          string
	BackendType   string
	// Option is the first refused option found; the DSN may name more.
	Option string
	// Options names every refused option in the DSN (dsn.RefusedLocalFileOptions):
	// option names only, never a value or any other part of the DSN.
	Options []string
	// LiveLeases counts the config's active and revoke_failed leases.
	LiveLeases int
}

// RefusedAdminDSNReport is the result of ListConfigsWithRefusedAdminDSN.
type RefusedAdminDSNReport struct {
	Configs []RefusedAdminDSNConfig
	// Unreadable counts configs whose admin_dsn could not be decrypted, so they
	// were not checked.
	Unreadable int
}

// ListConfigsWithRefusedAdminDSN finds the configs, in every project including
// soft-deleted ones (their leases are still swept), whose stored admin_dsn would
// be refused at issue time (#3980). For the operator at upgrade: a startup
// warning, read-only. A storage error stops the scan and is returned.
func (c *KeyorixCore) ListConfigsWithRefusedAdminDSN(ctx context.Context) (*RefusedAdminDSNReport, error) {
	projects, err := c.storage.ListProjectsWithCounts(ctx, true)
	if err != nil {
		return nil, err
	}
	rep := &RefusedAdminDSNReport{}
	for _, p := range projects {
		if err := c.collectRefusedAdminDSNConfigs(ctx, p.ID, rep); err != nil {
			return nil, err
		}
	}
	return rep, nil
}

// ListProjectConfigsWithRefusedAdminDSN is ListConfigsWithRefusedAdminDSN for one
// project, for an operator who must find the configs to fix with
// UpdateDynamicSecretConfigAdminDSN (DYNAMIC-ADMIN-DSN-1). It is gated like that
// update: actorID needs dynamic-secret admin authority on the project, because the
// report is derived from the decrypted admin DSNs. It names configs and refused
// option names only, never a DSN.
func (c *KeyorixCore) ListProjectConfigsWithRefusedAdminDSN(ctx context.Context, actorID, projectID uint) (*RefusedAdminDSNReport, error) {
	if projectID == 0 {
		return nil, validationErrorf("project_id is required")
	}
	if err := c.requireDynamicSecretAdminAuthority(ctx, actorID, projectID, 0); err != nil {
		return nil, err
	}
	rep := &RefusedAdminDSNReport{}
	if err := c.collectRefusedAdminDSNConfigs(ctx, projectID, rep); err != nil {
		return nil, &storageReadFault{cause: err}
	}
	return rep, nil
}

// collectRefusedAdminDSNConfigs appends projectID's configs with a refused
// admin_dsn option to rep.
func (c *KeyorixCore) collectRefusedAdminDSNConfigs(ctx context.Context, projectID uint, rep *RefusedAdminDSNReport) error {
	cfgs, err := c.storage.ListDynamicSecretConfigs(ctx, projectID, 0)
	if err != nil {
		return err
	}
	for _, cfg := range cfgs {
		adminDSN, derr := c.decryptAuthSecret(cfg.AdminDSNEnc, cfg.AdminDSNMeta, ports.DynamicSecretConfigAAD(cfg.ID, cfg.ProjectID, cfg.EnvironmentID))
		if derr != nil {
			rep.Unreadable++
			continue
		}
		fe, ok := errors.AsType[*dsn.ForbiddenOptionError](dsn.CheckLocalFileOptions(cfg.BackendType, adminDSN))
		if !ok {
			continue
		}
		leases, err := c.storage.ListDynamicSecretLeases(ctx, cfg.ID)
		if err != nil {
			return err
		}
		live := 0
		for _, l := range leases {
			if l.Status == "active" || l.Status == "revoke_failed" {
				live++
			}
		}
		rep.Configs = append(rep.Configs, RefusedAdminDSNConfig{
			ConfigID: cfg.ID, ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID, Name: cfg.Name, BackendType: cfg.BackendType,
			Option: fe.Option, Options: dsn.RefusedLocalFileOptions(cfg.BackendType, adminDSN), LiveLeases: live,
		})
	}
	return nil
}
