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

// PurgeDeletedUsersBefore hard-deletes soft-deleted users past the retention window,
// together with every row that references them as a principal — role/group
// membership, shares they RECEIVED, personal access tokens, and sessions — in one
// transaction. None of those tables carry their own deleted_at, so a plain purge of
// only the users row (as every other purgeDeletedBefore call does) left them
// orphaned indefinitely: a stale UserRole/GroupRole grant referencing a purged ID
// that could collide with a future reused ID, a PAT/session row that (before the
// core.DeleteUser fix) may still be live, and a share the user received sitting
// unreachable but undestroyed. Returns the number of users purged.
//
// #276-sibling: like PurgeDeletedSecretsBefore, the eligible-ID list is gathered by a
// SELECT (Pluck) and the deletes run moments later — a window in which a concurrent
// RestoreUser can flip deleted_at back to NULL on one of those IDs. Deleting purely
// off the stale ID list would hard-delete that already-restored user (and cascade
// through its role grants, memberships, sessions and PATs) anyway, silently undoing a
// restore that already reported success. Every delete below therefore re-applies the
// same "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used,
// keyed on id — not just the ID list — so a user a restore raced out from under the
// purge is left alone.
func (ls *LocalStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	var purged int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Unscoped().Model(&models.User{}).
			Where("deleted_at IS NOT NULL AND deleted_at < ?", before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		// Re-scoped to still-deleted-and-eligible users only, via a subquery against
		// users' live deleted_at rather than the stale `ids` list, so a user restored
		// after the SELECT above is excluded from every delete below it. A fresh
		// subquery builder is used per reference since a *gorm.DB is stateful and must
		// not be shared across clauses.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.User{}).
				Select("id").
				Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before)
		}
		if e := tx.Where("user_id IN (?)", stillEligible()).Delete(&models.UserRole{}).Error; e != nil {
			return e
		}
		if e := tx.Where("user_id IN (?)", stillEligible()).Delete(&models.UserGroup{}).Error; e != nil {
			return e
		}
		// ShareRecord carries its own DeletedAt (soft-delete) — Unscoped so this is a
		// true hard delete, not another soft-deleted orphan nothing else purges.
		if e := tx.Unscoped().Where("recipient_id IN (?) AND is_group = ?", stillEligible(), false).Delete(&models.ShareRecord{}).Error; e != nil {
			return e
		}
		if e := tx.Where("user_id IN (?)", stillEligible()).Delete(&models.PersonalAccessToken{}).Error; e != nil {
			return e
		}
		if e := tx.Where("user_id IN (?) OR impersonated_by IN (?)", stillEligible(), stillEligible()).Delete(&models.Session{}).Error; e != nil {
			return e
		}
		ru := tx.Unscoped().
			Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before).
			Delete(&models.User{})
		if ru.Error != nil {
			return ru.Error
		}
		purged = ru.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// PurgeDeletedProjectsBefore hard-deletes soft-deleted projects past the retention
// window, together with the project-scoped role grants (UserRole/GroupRole) that
// reference them, in one transaction. UserRole/GroupRole are plain join rows keyed
// by ProjectID with no FK/cascade of their own — a plain purge of just the projects
// row left these grants behind, permanently orphaned (referencing a project ID that
// no longer exists anywhere, since IDs are never reused): dead weight in every "who
// has access" report and role/access-review listing forever after. Global-scope
// grants (ProjectID 0) are untouched — they aren't project-scoped.
//
// #276-sibling: like PurgeDeletedSecretsBefore, the eligible-ID list is gathered by a
// SELECT (Pluck) and the deletes run moments later — a window in which a concurrent
// RestoreProject can flip deleted_at back to NULL on one of those IDs (and cascade the
// restore onto its environments/secrets, see LocalStorage.RestoreProject). Deleting
// purely off the stale ID list would hard-delete that already-restored project anyway,
// silently undoing a restore that already reported success — and orphaning the very
// environments/secrets RestoreProject just brought back, which would reference a
// project ID that no longer exists. Every delete below therefore re-applies the same
// "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used, keyed on
// id — not just the ID list — so a project a restore raced out from under the purge is
// left alone.
func (ls *LocalStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	var purged int64
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var ids []uint
		if e := tx.Unscoped().Model(&models.Project{}).
			Where("deleted_at IS NOT NULL AND deleted_at < ?", before).
			Pluck("id", &ids).Error; e != nil {
			return e
		}
		if len(ids) == 0 {
			return nil
		}
		// Re-scoped to still-deleted-and-eligible projects only, via a subquery against
		// projects' live deleted_at rather than the stale `ids` list, so a project
		// restored after the SELECT above is excluded from every delete below it. A
		// fresh subquery builder is used per reference since a *gorm.DB is stateful and
		// must not be shared across clauses.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.Project{}).
				Select("id").
				Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before)
		}
		if e := tx.Where("project_id IN (?)", stillEligible()).Delete(&models.UserRole{}).Error; e != nil {
			return e
		}
		if e := tx.Where("project_id IN (?)", stillEligible()).Delete(&models.GroupRole{}).Error; e != nil {
			return e
		}
		rp := tx.Unscoped().
			Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before).
			Delete(&models.Project{})
		if rp.Error != nil {
			return rp.Error
		}
		purged = rp.RowsAffected
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return purged, nil
}

// PurgeDeletedEnvironmentsBefore is NOT #276-sibling-affected despite RestoreEnvironment
// existing: unlike the Pluck-then-delete-by-ID-list shape used above, purgeDeletedBefore
// issues a single DELETE ... WHERE deleted_at IS NOT NULL AND deleted_at < before
// statement — there is no separate SELECT and no stale ID list for a concurrent restore
// to race against, so the predicate is necessarily evaluated against live row state at
// delete time already.
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
//
// #276: the eligible-ID list is gathered by a SELECT (Pluck) and the deletes run moments
// later — a window in which a concurrent RestoreSecret can flip deleted_at back to NULL on
// one of those IDs. Deleting purely off the stale ID list would hard-delete that
// already-restored secret anyway, silently undoing a restore that already reported success
// to its caller. Every delete below therefore re-applies the same
// "deleted_at IS NOT NULL AND deleted_at < before" predicate the SELECT used, keyed on id —
// not just the ID list — so a row a restore raced out from under the purge is left alone.
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
		// first, then the node rows — each re-scoped to still-deleted-and-eligible
		// secrets only, via a subquery against secret_nodes' live deleted_at rather
		// than the stale `ids` list, so a secret restored after the SELECT above is
		// excluded from every delete below it. A fresh subquery builder is used per
		// reference since a *gorm.DB is stateful and must not be shared across clauses.
		stillEligible := func() *gorm.DB {
			return tx.Unscoped().Model(&models.SecretNode{}).
				Select("id").
				Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before)
		}
		if e := tx.Where("secret_node_id IN (?)", stillEligible()).Delete(&models.SecretVersion{}).Error; e != nil {
			return e
		}
		if e := tx.Where("dependent_secret_id IN (?) OR depends_on_secret_id IN (?)", stillEligible(), stillEligible()).
			Delete(&models.SecretDependency{}).Error; e != nil {
			return e
		}
		rn := tx.Unscoped().
			Where("id IN ? AND deleted_at IS NOT NULL AND deleted_at < ?", ids, before).
			Delete(&models.SecretNode{})
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
