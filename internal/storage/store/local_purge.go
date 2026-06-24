// local_purge.go — retention purge of soft-deleted rows (ADR-032).
//
// Each method hard-deletes (Unscoped) rows whose deleted_at predates the cutoff,
// returning the count removed. The purge scheduler (main.go) drives these on an
// interval when enabled. Irreversible by design — the retention window is the
// only safety net.
package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) purgeDeletedBefore(ctx context.Context, model interface{}, before time.Time) (int64, error) {
	result := ls.db.WithContext(ctx).Unscoped().
		Where("deleted_at IS NOT NULL AND deleted_at < ?", before).
		Delete(model)
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

func (ls *LocalStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.User{}, before)
}

func (ls *LocalStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.Project{}, before)
}

func (ls *LocalStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.Environment{}, before)
}

// PurgeDeletedSecretsBefore hard-deletes soft-deleted secrets past the retention window,
// together with their version rows AND the dependency-graph edges incident to them, in one
// transaction. The secret VALUE lives in secret_versions.encrypted_value, which has no
// deleted_at and no FK cascade to secret_nodes — so deleting only the node row (as a plain
// purge would) left the ciphertext in the database indefinitely, still decryptable (key
// rotation even re-encrypts orphaned version rows), defeating the "irreversible by design"
// retention / GDPR-erasure guarantee. A SecretDependency edge likewise has no soft-delete of
// its own (ADR-052) — it lives and dies with its endpoints — so purging a secret without
// removing its edges would leave rows referencing a hard-deleted secret. Returns the number
// of secret_nodes purged (version and edge rows are not counted).
func (ls *LocalStorage) PurgeDeletedSecretsBefore(ctx context.Context, before time.Time) (int64, error) {
	var purged int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Unscoped().Model(&models.SecretNode{}).
			Where("deleted_at IS NOT NULL AND deleted_at < ?", before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		// Destroy the ciphertext-bearing versions and the incident dependency edges
		// first, then the node rows.
		if e := tx.Where("secret_node_id IN ?", ids).Delete(&models.SecretVersion{}).Error; e != nil {
			return e
		}
		if e := tx.Where("dependent_secret_id IN ? OR depends_on_secret_id IN ?", ids, ids).
			Delete(&models.SecretDependency{}).Error; e != nil {
			return e
		}
		rn := tx.Unscoped().Where("id IN ?", ids).Delete(&models.SecretNode{})
		if rn.Error != nil {
			return rn.Error
		}
		purged = rn.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// --- Data-retention purges (ISO A.5.33 / GDPR storage-limitation) ---
//
// These age out compliance records the application accumulates indefinitely.
// None of the target models carry a deleted_at, so a plain Delete is a true hard
// delete (no Unscoped needed). Active/open/pending rows are excluded by predicate
// so an in-flight record is never destroyed by a too-short window.

// DeleteAnomalyAlertsBefore hard-deletes anomaly alerts detected before the cutoff.
func (ls *LocalStorage) DeleteAnomalyAlertsBefore(ctx context.Context, before time.Time) (int64, error) {
	result := ls.db.WithContext(ctx).
		Where("detected_at < ?", before).
		Delete(&models.AnomalyAlert{})
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteClosedAccessReviewsBefore hard-deletes closed recertification campaigns
// closed before the cutoff together with their snapshot items, in one transaction.
// Open campaigns (closed_at IS NULL) are never touched.
func (ls *LocalStorage) DeleteClosedAccessReviewsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	var campaigns, items int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Model(&models.AccessReviewCampaign{}).
			Where("state = ? AND closed_at IS NOT NULL AND closed_at < ?", "closed", before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		ri := tx.Where("campaign_id IN ?", ids).Delete(&models.AccessReviewItem{})
		if ri.Error != nil {
			return ri.Error
		}
		items = ri.RowsAffected
		rc := tx.Where("id IN ?", ids).Delete(&models.AccessReviewCampaign{})
		if rc.Error != nil {
			return rc.Error
		}
		campaigns = rc.RowsAffected
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return campaigns, items, nil
}

// DeleteExpiredBreakGlassBefore hard-deletes non-active break-glass activations
// created before the cutoff. Active activations are never purged.
func (ls *LocalStorage) DeleteExpiredBreakGlassBefore(ctx context.Context, before time.Time) (int64, error) {
	result := ls.db.WithContext(ctx).
		Where("state <> ? AND created_at < ?", "active", before).
		Delete(&models.BreakGlassActivation{})
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteResolvedAccessRequestsBefore hard-deletes terminal-state access requests
// (resolved_at set, before the cutoff) together with their approval records, in one
// transaction. Pending requests (resolved_at IS NULL) are never touched.
func (ls *LocalStorage) DeleteResolvedAccessRequestsBefore(ctx context.Context, before time.Time) (int64, int64, error) {
	var requests, approvals int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Model(&models.AccessRequest{}).
			Where("resolved_at IS NOT NULL AND resolved_at < ?", before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		ra := tx.Where("request_id IN ?", ids).Delete(&models.AccessRequestApproval{})
		if ra.Error != nil {
			return ra.Error
		}
		approvals = ra.RowsAffected
		rr := tx.Where("id IN ?", ids).Delete(&models.AccessRequest{})
		if rr.Error != nil {
			return rr.Error
		}
		requests = rr.RowsAffected
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return requests, approvals, nil
}
