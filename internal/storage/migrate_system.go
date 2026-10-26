package storage

// migrateDatabase steps for scheduler lock leases and tables an older migration never created.
// Called in order from migrateDatabase (factory.go); see the step lists there.

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createSchedulerLockLeases is one of migrateDatabase's ordered steps (factory.go).
func createSchedulerLockLeases(db *gorm.DB, schedulerLockLeaseExists bool) error {
	// Create the scheduler-lock-lease table if missing (#530, additive). Backs
	// TryAcquireSchedulerLock/ReleaseSchedulerLock — a TTL-bounded distributed mutex
	// originally built for a storage.type: remote spoke's WithSchedulerLock to proxy
	// through (RemoteStorage, since deleted, #2162), independent of (and never
	// migrated onto) the pre-existing Postgres advisory lock local WithSchedulerLock
	// still uses for a server's OWN scheduler ticks.
	if !schedulerLockLeaseExists {
		if err := db.AutoMigrate(&models.SchedulerLockLease{}); err != nil {
			return fmt.Errorf("failed to migrate scheduler_lock_leases table: %w", err)
		}
	}
	return nil
}

// createUnmigratedFeatureTables is one of migrateDatabase's ordered steps (factory.go).
func createUnmigratedFeatureTables(db *gorm.DB, secretTemplateExists, alertEscalationExists, secretVersionCommentExists, mfaStepupTokenExists, hygieneTrendExists, compliancePostureExists bool) error {
	// Seven models with live, wired handler code (alert_escalation.go,
	// notification_channels.go, secret_templates.go, secret_version_comments.go,
	// mfa_stepup.go, hygiene_trends.go, compliance_snapshots_handler.go) were never
	// reachable from ANY db.AutoMigrate call in this function -- confirmed by
	// grepping the entire repo for AutoMigrate(&models.<each type>) and finding
	// matches only in _test.go files, never in server/http/handlers or here. Every
	// fresh install AND every existing install upgrading onto a binary with this
	// handler code would hit "no such table"/"relation does not exist" the first
	// time any of these seven features was used -- found while building
	// storage.AllModels() for design-b3-backup-v2.md §3.2, whose whole premise is
	// that AutoMigrate coverage and the backup table-walk share one real list;
	// these were silently absent from both. None of the seven carries a GORM
	// relationship tag (plain uint reference columns, not `gorm:"foreignKey"`), so
	// each is a standalone table with no create-order dependency on another model.
	if !secretTemplateExists {
		if err := db.AutoMigrate(&models.SecretTemplate{}); err != nil {
			return fmt.Errorf("failed to migrate secret_templates table: %w", err)
		}
	}
	if !alertEscalationExists {
		if err := db.AutoMigrate(&models.AlertEscalationPolicy{}); err != nil {
			return fmt.Errorf("failed to migrate alert_escalation_policies table: %w", err)
		}
	}
	// Unconditional (#2433), not guarded on !notificationChannelExists like the
	// SESSION-U U1 block above: that guard only ever existed to catch up a table
	// that was missing ENTIRELY on an upgrading install (the historical bug those
	// 11 models share) -- it was never meant to freeze the table's columns at
	// whatever existed the day the catch-up landed. NotificationChannel added two
	// new columns (URLEnc/URLMeta) after that fix shipped; the old `if !exists`
	// gate would skip AutoMigrate entirely once the table exists, so an
	// upgrading install would never get the new columns at all, even though
	// notification_channels.go's CRUD now depends on them unconditionally.
	// AutoMigrate is additive and safe on an existing table (same rationale as
	// "Create rotation_policies if missing" below), so there is no reason this
	// one model needed the once-only gate going forward.
	if err := db.AutoMigrate(&models.NotificationChannel{}); err != nil {
		return fmt.Errorf("failed to migrate notification_channels table: %w", err)
	}
	if !secretVersionCommentExists {
		if err := db.AutoMigrate(&models.SecretVersionComment{}); err != nil {
			return fmt.Errorf("failed to migrate secret_version_comments table: %w", err)
		}
	}
	if !mfaStepupTokenExists {
		if err := db.AutoMigrate(&models.MFAStepupToken{}); err != nil {
			return fmt.Errorf("failed to migrate mfa_stepup_tokens table: %w", err)
		}
	}
	if !hygieneTrendExists {
		if err := db.AutoMigrate(&models.HygieneTrendSnapshot{}); err != nil {
			return fmt.Errorf("failed to migrate hygiene_trend_snapshots table: %w", err)
		}
	}
	if !compliancePostureExists {
		if err := db.AutoMigrate(&models.CompliancePostureSnapshot{}); err != nil {
			return fmt.Errorf("failed to migrate compliance_posture_snapshots table: %w", err)
		}
	}
	return nil
}

// createU1Tables is one of migrateDatabase's ordered steps (factory.go).
func createU1Tables(db *gorm.DB, apiClientExists, apiTokenExists, apiCallLogExists, externalIdentityExists, grpcServiceExists, identityProviderExists, passwordResetExists, rateLimitExists, secretAccessLogExists, secretMetadataHistoryExists, settingExists bool) error {
	// SESSION-U guard U1: create these 11 tables unconditionally (not only on a
	// fresh install) -- see the existence-flag block above for why. Each is a
	// brand new table with no legacy columns to conditionally backfill, so a
	// plain gated AutoMigrate is enough, matching MFAStepUpGrant/AuditCheckpoint
	// above.
	if !apiClientExists {
		if err := db.AutoMigrate(&models.APIClient{}); err != nil {
			return fmt.Errorf("failed to migrate api_clients table: %w", err)
		}
	}
	if !apiTokenExists {
		if err := db.AutoMigrate(&models.APIToken{}); err != nil {
			return fmt.Errorf("failed to migrate api_tokens table: %w", err)
		}
	}
	if !apiCallLogExists {
		if err := db.AutoMigrate(&models.APICallLog{}); err != nil {
			return fmt.Errorf("failed to migrate api_call_logs table: %w", err)
		}
	}
	if !externalIdentityExists {
		if err := db.AutoMigrate(&models.ExternalIdentity{}); err != nil {
			return fmt.Errorf("failed to migrate external_identities table: %w", err)
		}
	}
	if !grpcServiceExists {
		if err := db.AutoMigrate(&models.GRPCService{}); err != nil {
			return fmt.Errorf("failed to migrate g_rpc_services table: %w", err)
		}
	}
	if !identityProviderExists {
		if err := db.AutoMigrate(&models.IdentityProvider{}); err != nil {
			return fmt.Errorf("failed to migrate identity_providers table: %w", err)
		}
	}
	if !passwordResetExists {
		if err := db.AutoMigrate(&models.PasswordReset{}); err != nil {
			return fmt.Errorf("failed to migrate password_resets table: %w", err)
		}
	}
	if !rateLimitExists {
		if err := db.AutoMigrate(&models.RateLimit{}); err != nil {
			return fmt.Errorf("failed to migrate rate_limits table: %w", err)
		}
	}
	if !secretAccessLogExists {
		if err := db.AutoMigrate(&models.SecretAccessLog{}); err != nil {
			return fmt.Errorf("failed to migrate secret_access_logs table: %w", err)
		}
	}
	if !secretMetadataHistoryExists {
		if err := db.AutoMigrate(&models.SecretMetadataHistory{}); err != nil {
			return fmt.Errorf("failed to migrate secret_metadata_histories table: %w", err)
		}
	}
	if !settingExists {
		if err := db.AutoMigrate(&models.Setting{}); err != nil {
			return fmt.Errorf("failed to migrate settings table: %w", err)
		}
	}
	return nil
}
