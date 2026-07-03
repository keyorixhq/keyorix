// local_sharing.go — ShareRecord operations for LocalStorage.
//
// Covers: CreateShareRecord, GetShareRecord, UpdateShareRecord, DeleteShareRecord,
//
//	ListSharesBySecret, ListSharesByUser, ListSharesByOwner, ListSharesByGroup,
//	ListSharedSecrets, CheckSharePermission.
//
// Sharing logic includes soft-delete awareness (deleted_at IS NULL filters),
// group-based share resolution, and upsert behaviour on CreateShareRecord.
// For the remote (HTTP) equivalent see remote_sharing.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreateShareRecord creates a share record, or updates the permission if one already exists.
func (ls *LocalStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	if err := models.ValidateShareRecord(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	secret, err := ls.GetSecret(ctx, share.SecretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	if secret.OwnerID != share.OwnerID {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
	}

	if share.IsGroup {
		var count int64
		if err := ls.db.Model(&models.Group{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
		}
	} else {
		var count int64
		if err := ls.db.Model(&models.User{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
	}

	var existing models.ShareRecord
	result := ls.db.Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL",
		share.SecretID, share.RecipientID, share.IsGroup).First(&existing)

	if result.Error == nil {
		existing.Permission = share.Permission
		// ExpiresAt reflects the caller's requested value verbatim (nil = permanent,
		// non-nil = time-bound), mirroring UpdateShareRecord's behaviour — a re-share
		// must be able to tighten (or clear) an existing grant's expiry, not just its
		// permission. Save writes nil as NULL.
		existing.ExpiresAt = share.ExpiresAt
		existing.UpdatedAt = time.Now()
		if err := ls.db.Save(&existing).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		return &existing, nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), result.Error)
	}

	if err := ls.db.Create(share).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return share, nil
}

// GetShareRecord retrieves a share record by ID.
func (ls *LocalStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	var share models.ShareRecord
	if err := ls.db.First(&share, shareID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return &share, nil
}

// UpdateShareRecord updates the permission on an existing share record.
func (ls *LocalStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	if err := models.ValidateShareUpdate(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	existing, err := ls.GetShareRecord(ctx, share.ID)
	if err != nil {
		return nil, err
	}
	existing.Permission = share.Permission
	// ExpiresAt is caller-resolved (the core layer preserves the current value unless a
	// change was requested), so copy it through — including nil to clear a time-bound
	// share back to permanent. Save writes the nil as NULL.
	existing.ExpiresAt = share.ExpiresAt
	existing.UpdatedAt = time.Now()
	if err := ls.db.Save(existing).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return existing, nil
}

// DeleteShareRecord soft-deletes a share record.
func (ls *LocalStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	share, err := ls.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}
	if err := ls.db.Delete(share).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return nil
}

// DeleteExpiredShareRecords soft-deletes time-bound shares whose ExpiresAt is
// non-NULL and at or before the cutoff, returning the removed rows so the caller can
// audit each. Runs in a transaction so the rows it reports are exactly the rows it
// removed. Idempotent — a tick that finds nothing removes nothing.
func (ls *LocalStorage) DeleteExpiredShareRecords(ctx context.Context, before time.Time) ([]*models.ShareRecord, error) {
	var removed []*models.ShareRecord
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(
			"expires_at IS NOT NULL AND expires_at <= ? AND deleted_at IS NULL", before,
		).Find(&removed).Error; err != nil {
			return err
		}
		if len(removed) == 0 {
			return nil
		}
		ids := make([]uint, len(removed))
		for i, s := range removed {
			ids[i] = s.ID
		}
		return tx.Where("id IN ?", ids).Delete(&models.ShareRecord{}).Error
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return removed, nil
}

// ListSharesBySecret lists active share records for a secret.
func (ls *LocalStorage) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where("secret_id = ? AND deleted_at IS NULL", secretID).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByUser lists active share records where userID is the direct recipient.
func (ls *LocalStorage) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where("recipient_id = ? AND is_group = ? AND deleted_at IS NULL", userID, false).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByOwner lists active share records created by ownerID.
func (ls *LocalStorage) ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where("owner_id = ? AND deleted_at IS NULL", ownerID).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByGroup lists active share records where groupID is the recipient.
func (ls *LocalStorage) ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := ls.db.Where("recipient_id = ? AND is_group = ? AND deleted_at IS NULL", groupID, true).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharedSecrets returns all secrets shared with userID, directly or via group membership.
func (ls *LocalStorage) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	var secrets []*models.SecretNode
	// Expired (time-bound) shares no longer authorize, so they must not surface in
	// the "shared with me" listing either — filter them the same way the auth queries do.
	now := time.Now()
	directQuery := `
		SELECT s.* FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		WHERE sr.recipient_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL AND s.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
	`
	if err := ls.db.Raw(directQuery, userID, false, now).Scan(&secrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	// JOIN groups … deleted_at IS NULL: a soft-deleted group's shares grant nothing,
	// even though the share/membership rows are kept for restore.
	groupQuery := `
		SELECT s.* FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		JOIN groups g ON g.id = ug.group_id AND g.deleted_at IS NULL
		JOIN users u ON u.id = ug.user_id AND u.deleted_at IS NULL
		WHERE ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL AND s.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
	`
	var groupSecrets []*models.SecretNode
	if err := ls.db.Raw(groupQuery, userID, true, now).Scan(&groupSecrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	return append(secrets, groupSecrets...), nil
}

// CheckSharePermission returns the effective permission level for userID on secretID.
// Owner → "write". Direct share → share.Permission. Group share → share.Permission.
func (ls *LocalStorage) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	var secret models.SecretNode
	if err := ls.db.First(&secret, secretID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	if secret.OwnerID == userID {
		return "write", nil
	}

	// Skip expired (time-bound) shares — an expired share grants no permission.
	now := time.Now()
	var directShare models.ShareRecord
	err := ls.db.Where(
		"secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
		secretID, userID, false, now,
	).First(&directShare).Error
	if err == nil {
		return directShare.Permission, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	var groupShare models.ShareRecord
	groupQuery := `
		SELECT sr.* FROM share_records sr
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		JOIN groups g ON g.id = ug.group_id AND g.deleted_at IS NULL
		JOIN users u ON u.id = ug.user_id AND u.deleted_at IS NULL
		WHERE sr.secret_id = ? AND ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
		  AND (sr.expires_at IS NULL OR sr.expires_at > ?)
		LIMIT 1
	`
	res := ls.db.Raw(groupQuery, secretID, userID, true, now).Scan(&groupShare)
	if res.Error == nil && groupShare.ID != 0 {
		return groupShare.Permission, nil
	} else if res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), res.Error)
	}

	return "", fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
}
