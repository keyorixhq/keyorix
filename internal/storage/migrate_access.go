package storage

// migrateDatabase steps for project invitations, access requests and access-review campaigns.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createAccessRequestTables is one of migrateDatabase's ordered steps (factory.go).
func createAccessRequestTables(db *gorm.DB, invitationsExists, accessReqExists, accessReqApprovalsExists, rejectionReasonTemplateExists bool) error {
	// Create project_invitations if missing (ADR-024, additive); otherwise add only
	// the newer global-invite columns via the Migrator (same pgx hazard as the
	// notifications block below — never full-AutoMigrate an existing table here).
	if !invitationsExists {
		if err := db.AutoMigrate(&models.ProjectInvitation{}); err != nil {
			return fmt.Errorf("failed to migrate project_invitations table: %w", err)
		}
	} else {
		m := db.Migrator()
		for _, col := range []string{"SystemRole", "AssignmentsJSON"} {
			if !m.HasColumn(&models.ProjectInvitation{}, col) {
				if err := m.AddColumn(&models.ProjectInvitation{}, col); err != nil {
					return fmt.Errorf("failed to add project_invitations.%s column: %w", col, err)
				}
			}
		}
	}
	if !accessReqExists {
		if err := db.AutoMigrate(&models.AccessRequest{}); err != nil {
			return fmt.Errorf("failed to migrate access_requests table: %w", err)
		}
	} else {
		// SecretID was added after this table could already exist in the field (same
		// pgx hazard as project_invitations above — never full-AutoMigrate an existing
		// table here); add it via the Migrator so an upgraded install still gets the
		// column the secret-scoped access-request flow needs (classification gate).
		m := db.Migrator()
		if !m.HasColumn(&models.AccessRequest{}, "SecretID") {
			if err := m.AddColumn(&models.AccessRequest{}, "SecretID"); err != nil {
				return fmt.Errorf("failed to add access_requests.secret_id column: %w", err)
			}
		}
	}

	// Create the access-request approvals table if missing (N-of-M dual control).
	if !accessReqApprovalsExists {
		if err := db.AutoMigrate(&models.AccessRequestApproval{}); err != nil {
			return fmt.Errorf("failed to migrate access_request_approvals table: %w", err)
		}
	}

	// Create rejection-reason templates table if missing (ADR-024 extension, additive).
	if !rejectionReasonTemplateExists {
		if err := db.AutoMigrate(&models.RejectionReasonTemplate{}); err != nil {
			return fmt.Errorf("failed to migrate rejection_reason_templates table: %w", err)
		}
	}
	return nil
}

// createAccessReviewCampaigns is one of migrateDatabase's ordered steps (factory.go).
func createAccessReviewCampaigns(db *gorm.DB, campaignExists bool) error {
	// Create the access-review campaign tables if missing (A.5.18, additive).
	if !campaignExists {
		if err := db.AutoMigrate(&models.AccessReviewCampaign{}, &models.AccessReviewItem{}); err != nil {
			return fmt.Errorf("failed to migrate access_review_campaign tables: %w", err)
		}
	} else {
		// #483/#237: Degraded/DegradedReasons/ForcedIncomplete/ActivityWindowDays were each added to
		// AccessReviewCampaign after this table could already exist in the field (same
		// pgx hazard as project_invitations above — never full-AutoMigrate an existing
		// table here); add the new columns via the Migrator so an existing deployment's
		// campaigns table picks them up. UpdateAccessReviewCampaign does a full-column
		// Select("*").Updates, so a missing column here isn't just a silently-unused
		// field — it hard-fails every subsequent campaign create/update on an upgraded
		// install that predates whichever field was added.
		m := db.Migrator()
		for _, col := range []string{"Degraded", "DegradedReasons", "ForcedIncomplete", "ActivityWindowDays"} {
			if !m.HasColumn(&models.AccessReviewCampaign{}, col) {
				if err := m.AddColumn(&models.AccessReviewCampaign{}, col); err != nil {
					return fmt.Errorf("failed to add access_review_campaigns.%s column: %w", col, err)
				}
			}
		}
	}
	return nil
}
