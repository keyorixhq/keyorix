// secret_listing_query.go — ListSecretsWithSharingInfo and supporting query/filter/sort helpers.
//
// Handles the main listing flow: fetch owned + shared secrets, deduplicate, filter, sort, paginate.
// For sharing status and UI indicators see secret_listing_sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsWithSharingInfo lists secrets with sharing information for a specific user.
func (c *KeyorixCore) ListSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100
	}

	var allSecrets []*models.SecretWithSharingInfo
	var ownedCount, sharedCount int

	if !filter.ShowSharedOnly {
		ownedSecrets, err := c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
		allSecrets = append(allSecrets, ownedSecrets...)
		ownedCount = len(ownedSecrets)
	}

	if !filter.ShowOwnedOnly {
		sharedSecrets, err := c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
		allSecrets = append(allSecrets, sharedSecrets...)
		sharedCount = len(sharedSecrets)
	}

	// Deduplicate by secret ID — a secret can appear in both owned and shared lists.
	seen := make(map[uint]bool)
	deduped := allSecrets[:0]
	for _, s := range allSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			deduped = append(deduped, s)
		}
	}
	allSecrets = deduped

	filteredSecrets := c.applySecretFilters(allSecrets, filter)
	c.sortSecrets(filteredSecrets, filter.SortBy, filter.SortOrder)

	total := int64(len(filteredSecrets))
	start := (filter.Page - 1) * filter.PageSize
	end := start + filter.PageSize
	if start > len(filteredSecrets) {
		start = len(filteredSecrets)
	}
	if end > len(filteredSecrets) {
		end = len(filteredSecrets)
	}

	totalPages := int((total + int64(filter.PageSize) - 1) / int64(filter.PageSize))

	return &models.SecretListResponse{
		Secrets:     filteredSecrets[start:end],
		Total:       total,
		Page:        filter.Page,
		PageSize:    filter.PageSize,
		TotalPages:  totalPages,
		OwnedCount:  ownedCount,
		SharedCount: sharedCount,
	}, nil
}

// getOwnedSecretsWithSharingInfo retrieves secrets owned by the user with sharing information.
func (c *KeyorixCore) getOwnedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	storageFilter := c.convertToStorageFilter(filter)
	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, secret := range secrets {
		shares, err := c.storage.ListSharesBySecret(ctx, secret.ID)
		if err != nil {
			continue
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          len(shares) > 0,
			IsOwnedByUser:     true,
			UserPermission:    "",
			ShareCount:        len(shares),
			SharingIndicators: c.buildSharingIndicators(secret, shares, true, ""),
		}
		result = append(result, s)
	}
	return result, nil
}

// getSharedSecretsWithSharingInfo retrieves secrets shared with the user.
func (c *KeyorixCore) getSharedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	shares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, share := range shares {
		secret, err := c.storage.GetSecret(ctx, share.SecretID)
		if err != nil {
			continue
		}
		ownerUsername := ""
		if owner, err := c.storage.GetUser(ctx, secret.OwnerID); err == nil && owner != nil {
			ownerUsername = owner.Username
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          true,
			IsOwnedByUser:     false,
			OwnerUsername:     ownerUsername,
			UserPermission:    share.Permission,
			ShareCount:        1,
			SharedAt:          &share.CreatedAt,
			SharingIndicators: c.buildSharingIndicators(secret, []*models.ShareRecord{share}, false, share.Permission),
		}
		result = append(result, s)
	}
	return result, nil
}

// applySecretFilters filters the secret list by permission, type, namespace, zone, environment, and date.
func (c *KeyorixCore) applySecretFilters(secrets []*models.SecretWithSharingInfo, filter *models.SecretListFilter) []*models.SecretWithSharingInfo {
	var filtered []*models.SecretWithSharingInfo
	for _, secret := range secrets {
		if filter.Permission != "" {
			if secret.IsOwnedByUser {
				if filter.Permission != "read" && filter.Permission != "write" {
					continue
				}
			} else if secret.UserPermission != filter.Permission {
				continue
			}
		}
		if filter.Type != nil && secret.Type != *filter.Type {
			continue
		}
		if filter.NamespaceID != nil && secret.NamespaceID != *filter.NamespaceID {
			continue
		}
		if filter.ZoneID != nil && secret.ZoneID != *filter.ZoneID {
			continue
		}
		if filter.EnvironmentID != nil && secret.EnvironmentID != *filter.EnvironmentID {
			continue
		}
		if filter.CreatedAfter != nil && secret.CreatedAt.Before(*filter.CreatedAfter) {
			continue
		}
		if filter.CreatedBefore != nil && secret.CreatedAt.After(*filter.CreatedBefore) {
			continue
		}
		filtered = append(filtered, secret)
	}
	return filtered
}

// sortSecrets sorts the secret list by name, created_at, shared_at, or owner.
func (c *KeyorixCore) sortSecrets(secrets []*models.SecretWithSharingInfo, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "name"
	}
	if sortOrder == "" {
		sortOrder = "asc"
	}
	sort.Slice(secrets, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "name":
			less = secrets[i].Name < secrets[j].Name
		case "created_at":
			less = secrets[i].CreatedAt.Before(secrets[j].CreatedAt)
		case "shared_at":
			if secrets[i].SharedAt == nil && secrets[j].SharedAt == nil {
				less = false
			} else if secrets[i].SharedAt == nil {
				less = false
			} else if secrets[j].SharedAt == nil {
				less = true
			} else {
				less = secrets[i].SharedAt.Before(*secrets[j].SharedAt)
			}
		case "owner":
			less = secrets[i].OwnerUsername < secrets[j].OwnerUsername
		default:
			less = secrets[i].Name < secrets[j].Name
		}
		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// convertToStorageFilter converts SecretListFilter to storage.SecretFilter.
func (c *KeyorixCore) convertToStorageFilter(filter *models.SecretListFilter) *storage.SecretFilter {
	return &storage.SecretFilter{
		NamespaceID:   filter.NamespaceID,
		ZoneID:        filter.ZoneID,
		EnvironmentID: filter.EnvironmentID,
		Type:          filter.Type,
		Tags:          filter.Tags,
		CreatedBy:     filter.CreatedBy,
		CreatedAfter:  filter.CreatedAfter,
		CreatedBefore: filter.CreatedBefore,
		Page:          filter.Page,
		PageSize:      filter.PageSize,
	}
}
