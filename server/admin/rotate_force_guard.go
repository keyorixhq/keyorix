package admin

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
)

// refuseForcedDEKRotation refuses a DEK rotation (`admin encryption rotate`
// and `admin encryption auth-encryption rotate`, both RotateDEKWithSweep) on
// PostgreSQL when --force let it past the exclusive database lock (lockBypass
// set by acquireDatabaseLock). A dry run reads only and is not refused.
//
// Why (DEK-ROTATE-SAFETY-1 item 2, DEK-ROTATION-CROSS-HOST): dek.lock is a
// flock on one host's key directory, so with several replicas on one database
// the presence lock is the only thing that keeps a rotation away from live
// replicas on other hosts. The DEK epoch (#3337) fences their NEW encryptions,
// but a value a replica encrypted just before the fence and INSERTs after the
// sweep's table lock commits under the old DEK once the sweep has committed,
// and it is undecryptable once the old DEK is gone. Nothing short of the
// presence lock closes that window, so --force cannot drop it for a rotation.
// Guards: rotate_force_cross_replica_postgres_test.go (pg-gated, both
// commands) and rotate_force_guard_family_test.go (every admin function that
// reaches RotateDEKWithSweep calls this first).
func refuseForcedDEKRotation(cfg *config.Config, dryRun bool) error {
	if lockBypass == "" || dryRun {
		return nil
	}
	if cfg.Storage.Type != "postgres" && cfg.Storage.Type != "postgresql" {
		return nil
	}
	return fmt.Errorf("refusing to rotate the DEK: could not acquire this database's exclusive lock (%s), and --force cannot override it for a DEK rotation on PostgreSQL: "+
		"a replica on another host that is still running would commit rows under the old DEK after the sweep, and they become undecryptable once the old DEK is gone. "+
		"Stop every server that uses this database (every replica, on every host), then retry without --force; a lock left by a dead connection is released when PostgreSQL closes it (emergency SQL: %s)",
		lockBypass, keyDirLockEmergencySQL)
}
