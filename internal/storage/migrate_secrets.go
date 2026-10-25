package storage

// migrateDatabase steps for secret_nodes, secret_versions, rotation policies and secret dependencies.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// alterSecretNodes is one of migrateDatabase's ordered steps (factory.go).
func alterSecretNodes(db *gorm.DB, exec func(string) error) error {
	// Additive column migration for existing databases (no-op on fresh DBs).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "last_rotated_at") {
		if err := exec("ALTER TABLE secret_nodes ADD COLUMN last_rotated_at TIMESTAMP WITH TIME ZONE"); err != nil {
			return err
		}
	}
	// ADR-033: secrets soft-delete. Additive deleted_at (nil = live).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "deleted_at") {
		if err := exec("ALTER TABLE secret_nodes ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE"); err != nil {
			return err
		}
	}
	// Frozen purge date (models.SecretNode.PurgeAt). Additive, nil = live secret or one
	// soft-deleted before this column existed. secret_nodes is NOT re-AutoMigrated on an
	// existing database (freshInstallComplete returns early), so without this ALTER every
	// secret create/delete on an upgraded install fails with "no column named purge_at".
	// The type is per dialect: SQLite's driver only scans a non-NULL value into *time.Time
	// when the declared type is DATETIME (what AutoMigrate creates on a fresh install);
	// "TIMESTAMP WITH TIME ZONE" is stored but fails on read with "unsupported Scan,
	// storing driver.Value type string into type *time.Time".
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "purge_at") {
		purgeAtType := "DATETIME"
		if db.Dialector.Name() == "postgres" {
			purgeAtType = "TIMESTAMP WITH TIME ZONE"
		}
		if err := exec("ALTER TABLE secret_nodes ADD COLUMN purge_at " + purgeAtType); err != nil {
			return err
		}
	}
	// Data classification (ISO A.5.12). Additive classification ("" = unclassified).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "classification") {
		if err := exec("ALTER TABLE secret_nodes ADD COLUMN classification TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	// Companion index: models.SecretNode.Classification carries `gorm:"index"`, so a
	// fresh AutoMigrate-created install already gets this index automatically, but an
	// upgraded install only ever reaches the column via the raw ALTER above (AutoMigrate
	// never re-diffs an existing table's indexes here), so it would otherwise never gain
	// the index and classification-filtered queries would degrade to a full table scan
	// as secret_nodes grows. Gated on tableExists only (not columnExists) so it also
	// converges an install that already has the column from an older deploy of this
	// migration but predates this index. CREATE INDEX IF NOT EXISTS is idempotent, so
	// running it unconditionally on every boot (matching the ensure*Index helpers below)
	// is cheap once the index is in place.
	if tableExists(db, "secret_nodes") {
		if err := exec("CREATE INDEX IF NOT EXISTS idx_secret_nodes_classification ON secret_nodes (classification)"); err != nil {
			return err
		}
	}
	// ADR-046: automated rotation opt-in. Additive auto_rotate (false = off).
	if tableExists(db, "secret_nodes") && !columnExists(db, "secret_nodes", "auto_rotate") {
		if err := exec("ALTER TABLE secret_nodes ADD COLUMN auto_rotate BOOLEAN NOT NULL DEFAULT false"); err != nil {
			return err
		}
	}
	// ADR-046: per-secret generated-value shape. Additive (0/'' = defaults).
	if tableExists(db, "secret_nodes") {
		if !columnExists(db, "secret_nodes", "rotation_length") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN rotation_length INTEGER NOT NULL DEFAULT 0"); err != nil {
				return err
			}
		}
		if !columnExists(db, "secret_nodes", "rotation_charset") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN rotation_charset TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		// ADR-047: backend rotation wiring. Additive ('' = regenerate-in-Keyorix).
		if !columnExists(db, "secret_nodes", "rotation_backend") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN rotation_backend TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if !columnExists(db, "secret_nodes", "rotation_ref") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN rotation_ref TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		// SUSPEND-PURGE-1: per-suspension "also clear synced Kubernetes copies"
		// marker. Additive (false = the resource's own onSuspend setting decides).
		if !columnExists(db, "secret_nodes", "suspend_clear_synced_copies") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN suspend_clear_synced_copies BOOLEAN NOT NULL DEFAULT false"); err != nil {
				return err
			}
		}
		// ADR-056: cached certificate expiry. Additive (nil = not yet evaluated).
		if !columnExists(db, "secret_nodes", "cert_not_after") {
			if err := exec("ALTER TABLE secret_nodes ADD COLUMN cert_not_after TIMESTAMP WITH TIME ZONE"); err != nil {
				return err
			}
		}
		// Companion index (models.SecretNode.CertNotAfter is `gorm:"index"`); see the
		// classification companion-index comment above for why this runs unconditionally
		// (gated on the table only) rather than nested inside the ALTER guard above.
		if err := exec("CREATE INDEX IF NOT EXISTS idx_secret_nodes_cert_not_after ON secret_nodes (cert_not_after)"); err != nil {
			return err
		}
	}
	// MT-006: partial unique index on (project_id, environment_id, name) WHERE
	// deleted_at IS NULL — enforces at the DB layer the invariant the application
	// already assumes in GetSecretByName (which scopes by project+environment+name
	// without a parent_id qualifier). A soft-deleted secret's name is freed for reuse
	// (the partial predicate excludes it), matching the deleted_at soft-delete pattern
	// used for users, groups, and projects. This closes the TOCTOU window in
	// core.CreateSecret (GetSecretByName check-then-act) the same way
	// ensureSecretVersionIndex closes the RotateSecret race.
	if tableExists(db, "secret_nodes") {
		if err := ensureSecretNodeNameIndex(db); err != nil {
			return err
		}
		// The UPGRADE call site for cache_epoch (the read-path cache's generation
		// stamp — see store.EnsureSecretNodeCacheEpoch). It needs BOTH this one
		// and the one in the transactional tail, for the same reason
		// ensureSecretNodeNameIndex does and in the opposite direction:
		// freshInstallComplete below returns early on EVERY boot of an
		// already-initialised database, so the tail covers only a fresh (or
		// half-migrated) install, while this tableExists-gated call is the only
		// thing that reaches an existing deployment. Caught by
		// TestSecretNodeCacheEpoch_FreshInstallAndUpgrade_{SQLite,Postgres}, which
		// failed with "cache_epoch missing" when only the tail call existed.
		//
		// The two never both ALTER in one boot (on a fresh install secret_nodes
		// does not exist yet at this point, so this call no-ops), so this cannot
		// re-trip the pgx "insufficient arguments" hazard that re-inspecting a
		// just-ALTERed table in the bulk AutoMigrate loop causes.
		if err := store.EnsureSecretNodeCacheEpoch(db); err != nil {
			return err
		}
	}
	return nil
}

// createRotationPolicies is one of migrateDatabase's ordered steps (factory.go).
func createRotationPolicies(db *gorm.DB, rotationExists bool) error {
	// Create rotation_policies if missing (additive, safe on existing DBs).
	if !rotationExists {
		if err := db.AutoMigrate(&models.RotationPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate rotation_policies table: %w", err)
		}
	}
	return nil
}

// createSecretDependencies is one of migrateDatabase's ordered steps (factory.go).
func createSecretDependencies(db *gorm.DB, secretDepExists bool) error {
	// Create the secret-dependency edge table if missing (ADR-052, additive).
	if !secretDepExists {
		if err := db.AutoMigrate(&models.SecretDependency{}); err != nil {
			return fmt.Errorf("failed to migrate secret_dependencies table: %w", err)
		}
	}
	return nil
}

// alterSecretVersionIndex is one of migrateDatabase's ordered steps (factory.go).
func alterSecretVersionIndex(db *gorm.DB) error {
	// Close the secret-version TOCTOU (#121): a unique index on (secret_node_id,
	// version_number) so two concurrent RotateSecret calls for the same secret can no
	// longer both write the same next version number. Additive + idempotent; the full
	// AutoMigrate below covers fresh DBs.
	if tableExists(db, "secret_versions") {
		if err := ensureSecretVersionIndex(db); err != nil {
			return err
		}
	}
	return nil
}
