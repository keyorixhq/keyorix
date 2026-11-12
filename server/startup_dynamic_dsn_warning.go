package main

import (
	"context"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/besteffort"
	"github.com/keyorixhq/keyorix/internal/core"
)

// refusedDSNLogLimit caps the per-config lines of the startup warning.
const refusedDSNLogLimit = 20

// refusedDSNCheckTimeout bounds the startup scan.
const refusedDSNCheckTimeout = 30 * time.Second

// warnRefusedDynamicAdminDSNs logs, once at startup, the dynamic-secret configs
// whose stored admin_dsn names an option refused since #3952 (#3980): issue from
// them fails, and their live leases revoke with the option removed, except
// postgres service/servicefile and mongodb ambient authMechanism, which stay
// revoke_failed until the role is dropped by hand. Read-only and bounded, so it
// cannot hold up startup; a failure is logged, never fatal.
func warnRefusedDynamicAdminDSNs(ctx context.Context, coreService *core.KeyorixCore) {
	defer besteffort.RunRecover("dynamic_secrets.refused_admin_dsn_warning")()
	ctx, cancel := context.WithTimeout(ctx, refusedDSNCheckTimeout)
	defer cancel()
	rep, err := coreService.ListConfigsWithRefusedAdminDSN(ctx)
	if err != nil {
		log.Printf("WARNING: dynamic secrets: could not check stored admin_dsn values for refused options: %v", err)
		return
	}
	if rep.Unreadable > 0 {
		log.Printf("WARNING: dynamic secrets: %d config(s) skipped by the admin_dsn option check: the stored admin_dsn could not be decrypted", rep.Unreadable)
	}
	if len(rep.Configs) == 0 {
		return
	}
	live := 0
	for _, c := range rep.Configs {
		live += c.LiveLeases
	}
	log.Printf("WARNING: dynamic secrets: %d config(s) store an admin_dsn option that makes the driver read a server file "+
		"(refused since #3952); %d live lease(s) on them. Issue from these configs fails. Revoke and the expiry sweep "+
		"remove the option (a CA file is replaced by the system trust store) except postgres service/servicefile and "+
		"mongodb authMechanism=MONGODB-AWS/MONGODB-OIDC/GSSAPI, whose leases stay revoke_failed: drop those roles by hand. "+
		"Create a replacement config whose DSN names no server file.", len(rep.Configs), live)
	for i, c := range rep.Configs {
		if i == refusedDSNLogLimit {
			log.Printf("WARNING: dynamic secrets: ... and %d more config(s)", len(rep.Configs)-i)
			break
		}
		log.Printf("WARNING: dynamic secrets: config %d (project %d, %q, %s): option %q, %d live lease(s)",
			c.ConfigID, c.ProjectID, c.Name, c.BackendType, c.Option, c.LiveLeases)
	}
}
