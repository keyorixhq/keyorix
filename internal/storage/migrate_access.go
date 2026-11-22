package storage

// migrateDatabase steps for project invitations, access requests and access-review campaigns.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"
	"strings"

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
		// InvitedByMachineIdentityID (#1573, #4518): the machine-identity actor column
		// a database first installed before v0.92 never got.
		for _, col := range []string{"SystemRole", "AssignmentsJSON", "InvitedByMachineIdentityID"} {
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
		//
		// ResolvedByMachineIdentityID (#1573, #4518) the same way.
		m := db.Migrator()
		for _, col := range []string{"SecretID", "ResolvedByMachineIdentityID"} {
			if !m.HasColumn(&models.AccessRequest{}, col) {
				if err := m.AddColumn(&models.AccessRequest{}, col); err != nil {
					return fmt.Errorf("failed to add access_requests.%s column: %w", col, err)
				}
			}
		}
	}

	// Create the access-request approvals table if missing (N-of-M dual control).
	if !accessReqApprovalsExists {
		if err := db.AutoMigrate(&models.AccessRequestApproval{}); err != nil {
			return fmt.Errorf("failed to migrate access_request_approvals table: %w", err)
		}
	} else if err := widenAccessRequestApprovals(db); err != nil {
		return err
	}

	// Create rejection-reason templates table if missing (ADR-024 extension, additive).
	if !rejectionReasonTemplateExists {
		if err := db.AutoMigrate(&models.RejectionReasonTemplate{}); err != nil {
			return fmt.Errorf("failed to migrate rejection_reason_templates table: %w", err)
		}
	}
	return nil
}

// accessRequestApproverIndex is the unique index that allows one sign-off per approver
// of a request: (request_id, approver_id, approver_machine_identity_id) since #1573,
// (request_id, approver_id) before it.
const accessRequestApproverIndex = "ux_access_request_approver"

// widenAccessRequestApprovals brings an existing access_request_approvals table to what a
// fresh install has (#4518): the approver_machine_identity_id column (NOT NULL DEFAULT 0,
// the model's definition, so every existing row is a human approval) and the unique index
// widened to include it. Widening only loosens the constraint, so no existing row can
// violate it. The old index is dropped and the new one created in one transaction, so a
// crash between the two cannot leave the table without its uniqueness guard. Idempotent:
// a database that already has the wide index is not touched.
func widenAccessRequestApprovals(db *gorm.DB) error {
	m := db.Migrator()
	if !m.HasColumn(&models.AccessRequestApproval{}, "ApproverMachineIdentityID") {
		if err := m.AddColumn(&models.AccessRequestApproval{}, "ApproverMachineIdentityID"); err != nil {
			return fmt.Errorf("failed to add access_request_approvals.approver_machine_identity_id column: %w", err)
		}
	}
	if strings.Contains(indexDefinition(db, accessRequestApproverIndex), "approver_machine_identity_id") {
		return nil
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DROP INDEX IF EXISTS " + accessRequestApproverIndex).Error; err != nil {
			return err
		}
		return tx.Exec("CREATE UNIQUE INDEX " + accessRequestApproverIndex +
			" ON access_request_approvals (request_id, approver_id, approver_machine_identity_id)").Error
	}); err != nil {
		return fmt.Errorf("failed to widen %s: %w", accessRequestApproverIndex, err)
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
		//
		// CreatedByMachineIdentityID/ClosedByMachineIdentityID (#1573, #4518) the same way.
		for _, col := range []string{"Degraded", "DegradedReasons", "ForcedIncomplete", "ActivityWindowDays",
			"CreatedByMachineIdentityID", "ClosedByMachineIdentityID"} {
			if !m.HasColumn(&models.AccessReviewCampaign{}, col) {
				if err := m.AddColumn(&models.AccessReviewCampaign{}, col); err != nil {
					return fmt.Errorf("failed to add access_review_campaigns.%s column: %w", col, err)
				}
			}
		}
	}
	return nil
}
