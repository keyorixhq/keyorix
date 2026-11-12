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
	ConfigID    uint
	ProjectID   uint
	Name        string
	BackendType string
	// Option is the first refused option found; the DSN may name more.
	Option string
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
		cfgs, err := c.storage.ListDynamicSecretConfigs(ctx, p.ID, 0)
		if err != nil {
			return nil, err
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
				return nil, err
			}
			live := 0
			for _, l := range leases {
				if l.Status == "active" || l.Status == "revoke_failed" {
					live++
				}
			}
			rep.Configs = append(rep.Configs, RefusedAdminDSNConfig{
				ConfigID: cfg.ID, ProjectID: cfg.ProjectID, Name: cfg.Name, BackendType: cfg.BackendType,
				Option: fe.Option, LiveLeases: live,
			})
		}
	}
	return rep, nil
}
