package storage

// migrateDatabase steps for break-glass activations, legal holds and risk exceptions.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createBreakGlassActivations is one of migrateDatabase's ordered steps (factory.go).
func createBreakGlassActivations(db *gorm.DB, breakGlassExists bool) error {
	// Create the break-glass activations table if missing (additive).
	if !breakGlassExists {
		if err := db.AutoMigrate(&models.BreakGlassActivation{}); err != nil {
			return fmt.Errorf("failed to migrate break_glass_activations table: %w", err)
		}
	} else {
		// ADR-112 §3 (break-glass review item 5): ReviewedBy/ReviewedAt/ReviewNote
		// were added to BreakGlassActivation after this table could already exist in
		// the field — same "never full-AutoMigrate an existing table here" constraint
		// as AccessReviewCampaign above; add the new columns via the Migrator so an
		// upgraded install picks them up. Without this, ReviewBreakGlassActivation's
		// conditional UPDATE would hard-fail on every upgraded install that predates
		// this feature (the column it sets simply wouldn't exist).
		//
		// BREAKGLASS-OWED-1 (epoch 5): Degraded/AuditSettledAt the same way. Without
		// them an upgraded install's degraded commit (audit log down) would fail, and
		// break-glass would be refused exactly when it is needed.
		m := db.Migrator()
		for _, col := range []string{"ReviewedBy", "ReviewedAt", "ReviewNote", "Degraded", "AuditSettledAt"} {
			if !m.HasColumn(&models.BreakGlassActivation{}, col) {
				if err := m.AddColumn(&models.BreakGlassActivation{}, col); err != nil {
					return fmt.Errorf("failed to add break_glass_activations.%s column: %w", col, err)
				}
			}
		}
	}
	// Enforce at most one ACTIVE break-glass activation per (project, user), even
	// under a race — see ensureBreakGlassActiveIndex. Runs whether the table was just
	// created above or already existed on an older DB (additive, idempotent).
	if err := ensureBreakGlassActiveIndex(db); err != nil {
		return err
	}
	return nil
}

// createLegalHolds is one of migrateDatabase's ordered steps (factory.go).
func createLegalHolds(db *gorm.DB, legalHoldExists bool) error {
	// Create the legal-holds table if missing (additive).
	if !legalHoldExists {
		if err := db.AutoMigrate(&models.LegalHold{}); err != nil {
			return fmt.Errorf("failed to migrate legal_holds table: %w", err)
		}
	}
	// At most one legal hold may be active (released = false) at a time — a plain
	// check-then-insert in core.PlaceLegalHold has a TOCTOU window (#305): two
	// concurrent placements can both observe "no active hold" and both insert one,
	// orphaning a row that GetActiveLegalHold's highest-id lookup never surfaces
	// again, so lifting the hold an operator sees leaves purges permanently blocked.
	// Close the race at the DB layer regardless of whether the table pre-existed.
	if err := ensureLegalHoldActiveIndex(db); err != nil {
		return err
	}
	return nil
}

// createRiskExceptions is one of migrateDatabase's ordered steps (factory.go).
func createRiskExceptions(db *gorm.DB, riskExceptionExists bool) error {
	// Create the risk-exceptions table if missing (A.5.8 risk treatment, additive).
	if !riskExceptionExists {
		if err := db.AutoMigrate(&models.RiskException{}); err != nil {
			return fmt.Errorf("failed to migrate risk_exceptions table: %w", err)
		}
	}
	return nil
}
