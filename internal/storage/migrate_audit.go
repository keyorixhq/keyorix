package storage

// migrateDatabase steps for audit_events, secret_access_logs, audit_checkpoints and pending_audit_events.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// alterAuditEvents is one of migrateDatabase's ordered steps (factory.go).
func alterAuditEvents(db *gorm.DB, exec func(string) error) error {
	// Audit-design block: diff payload + impersonation attribution on audit rows.
	if tableExists(db, "audit_events") {
		if !columnExists(db, "audit_events", "diff") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN diff TEXT"); err != nil {
				return err
			}
		}
		if !columnExists(db, "audit_events", "impersonated_by") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN impersonated_by INTEGER"); err != nil {
				return err
			}
		}
		if !columnExists(db, "audit_events", "acting_as") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN acting_as INTEGER"); err != nil {
				return err
			}
		}
		if !columnExists(db, "audit_events", "impersonation") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN impersonation BOOLEAN NOT NULL DEFAULT false"); err != nil {
				return err
			}
		}
		// ADR-023: actor kind (user vs machine_identity) on every event.
		if !columnExists(db, "audit_events", "actor_type") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user'"); err != nil {
				return err
			}
		}
		// ADR-029: tamper-evidence hash chain. Empty on legacy rows (the chain
		// begins at the first event written after these columns exist).
		if !columnExists(db, "audit_events", "prev_hash") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		if !columnExists(db, "audit_events", "entry_hash") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
		// Epoch 6 (AUDIT-REQUEST-ID-1): advisory request id, outside the hash chain.
		// Nullable with no default, so Postgres changes only the catalog (no rewrite).
		if !columnExists(db, "audit_events", "request_id") {
			if err := exec("ALTER TABLE audit_events ADD COLUMN request_id TEXT"); err != nil {
				return err
			}
		}
		// DB-TUNE-1: drop the prev_hash/entry_hash indexes earlier releases
		// created (models.AuditEvent once tagged both `gorm:"index"`). No query
		// looks a row up by either hash: VerifyAuditChain, internal/auditverify,
		// the chain-head read and the checkpoint/anchor code all walk or fetch
		// audit_events by id, and the links are compared in memory. The two
		// indexes held random 64-hex keys, most of the table's index storage,
		// and every audit INSERT paid for both. An older binary booted against
		// this database recreates them (CREATE INDEX IF NOT EXISTS), which is
		// harmless. Guard: TestAuditEventHashIndexes_DroppedOnUpgrade.
		if err := exec("DROP INDEX IF EXISTS idx_audit_events_prev_hash"); err != nil {
			return err
		}
		if err := exec("DROP INDEX IF EXISTS idx_audit_events_entry_hash"); err != nil {
			return err
		}
	}
	return nil
}

// createAuditCheckpoints is one of migrateDatabase's ordered steps (factory.go).
func createAuditCheckpoints(db *gorm.DB, auditCkptExists bool) error {
	// Create the audit_checkpoints table if missing (ADR-029 signed checkpoints,
	// additive, safe on existing DBs).
	if !auditCkptExists {
		if err := db.AutoMigrate(&models.AuditCheckpoint{}); err != nil {
			return fmt.Errorf("failed to migrate audit_checkpoints table: %w", err)
		}
	} else {
		// Add only the newer external-notary anchor columns on an existing table
		// (additive; same pgx hazard as elsewhere — never full-AutoMigrate here).
		m := db.Migrator()
		for _, col := range []string{"AnchorToken", "AnchoredAt", "AnchorProvider"} {
			if !m.HasColumn(&models.AuditCheckpoint{}, col) {
				if err := m.AddColumn(&models.AuditCheckpoint{}, col); err != nil {
					return fmt.Errorf("failed to add audit_checkpoints column %s: %w", col, err)
				}
			}
		}
	}
	return nil
}

// createPendingAuditEvents is one of migrateDatabase's ordered steps (factory.go).
func createPendingAuditEvents(db *gorm.DB, pendingAuditExists bool) error {
	// Create pending_audit_events if missing (audit rows owed by a plain secret
	// suspend that took effect while the audit log refused writes; additive).
	if !pendingAuditExists {
		if err := db.AutoMigrate(&models.PendingAuditEvent{}); err != nil {
			return fmt.Errorf("failed to migrate pending_audit_events table: %w", err)
		}
	} else {
		// BREAKGLASS-OWED-1 (epoch 5): the link from an owed row to its degraded
		// break-glass activation, added to a table an epoch-3/4 install already has
		// (never full-AutoMigrate an existing table here, as above).
		m := db.Migrator()
		if !m.HasColumn(&models.PendingAuditEvent{}, "BreakGlassActivationID") {
			if err := m.AddColumn(&models.PendingAuditEvent{}, "BreakGlassActivationID"); err != nil {
				return fmt.Errorf("failed to add pending_audit_events.break_glass_activation_id column: %w", err)
			}
		}
		if !m.HasIndex(&models.PendingAuditEvent{}, "BreakGlassActivationID") {
			if err := m.CreateIndex(&models.PendingAuditEvent{}, "BreakGlassActivationID"); err != nil {
				return fmt.Errorf("failed to index pending_audit_events.break_glass_activation_id: %w", err)
			}
		}
	}
	return nil
}
