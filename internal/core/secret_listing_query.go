// secret_listing_query.go — ListSecretsWithSharingInfo and helpers.
//
// For sharing status and UI indicators see secret_listing_sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsInScope lists every secret in the filter's project/environment
// scope, with no per-user ownership or sharing resolution. It backs machine
// principals (ADR-030), which have no user identity and whose authorization to
// the scope is already enforced by the route's scoped-permission gate. The
// response shape matches ListSecretsWithSharingInfo so the handler is uniform;
// the sharing fields are owner-agnostic (a machine does not "own" or have
// secrets "shared with" it).
func (c *KeyorixCore) ListSecretsInScope(ctx context.Context, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	storageFilter := c.convertToStorageFilter(filter)
	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	all := make([]*models.SecretWithSharingInfo, 0, len(secrets))
	for _, secret := range secrets {
		all = append(all, &models.SecretWithSharingInfo{SecretNode: secret})
	}
	all = c.applySecretFilters(all, filter)
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return &models.SecretListResponse{
		Secrets:    all[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ListSecretsWithSharingInfo lists secrets with sharing information for a specific user.
func (c *KeyorixCore) ListSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}

	// Fetch owned secrets (skip when user only wants to see what's shared with them).
	var ownedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowSharedOnly {
		var err error
		ownedSecrets, err = c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Fetch shared secrets (only when not filtering by project — project view shows owned only).
	var sharedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowOwnedOnly && filter.ProjectID == nil {
		var err error
		sharedSecrets, err = c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Merge owned + shared, deduplicating by secret ID
	seen := make(map[uint]bool)
	var all []*models.SecretWithSharingInfo
	for _, s := range ownedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}
	for _, s := range sharedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}

	// Apply post-fetch filters (search, type, shared-only)
	all = c.applySecretFilters(all, filter)

	// Sort
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))

	// Paginate
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	paged := all[start:end]

	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.SecretListResponse{
		Secrets:     paged,
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
		OwnedCount:  len(ownedSecrets),
		SharedCount: len(sharedSecrets),
	}, nil
}

// getOwnedSecretsWithSharingInfo retrieves secrets owned by the user with sharing information.
func (c *KeyorixCore) getOwnedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	storageFilter := c.convertToStorageFilter(filter)

	// Resolve the user first — fail closed for an unknown/zero principal (e.g. a
	// machine identity has no owning user, so it owns no secrets).
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("failed to resolve user for secret listing: %w", err)
	}
	// "Owned" means owner_id == userID — the canonical ownership the permission
	// model uses (CheckSecretPermission), not the created_by username string. The
	// username proxy missed CLI-created secrets (created_by "cli-user") and could
	// mis-attribute ownership across a deleted-then-reused username.
	storageFilter.OwnerID = &userID

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

func (c *KeyorixCore) getSharedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	shares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, share := range shares {
		secret, err := c.storage.GetSecret(ctx, share.SecretID)
		if err != nil || secret == nil {
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
			UserPermission:    string(share.Permission),
			ShareCount:        0,
			SharingIndicators: c.buildSharingIndicators(secret, nil, false, string(share.Permission)),
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *KeyorixCore) applySecretFilters(secrets []*models.SecretWithSharingInfo, filter *models.SecretListFilter) []*models.SecretWithSharingInfo {
	var out []*models.SecretWithSharingInfo
	for _, s := range secrets {
		if filter.ShowSharedOnly && !s.IsShared {
			continue
		}
		if filter.Search != nil && *filter.Search != "" {
			if !strings.Contains(strings.ToLower(s.Name), strings.ToLower(*filter.Search)) {
				continue
			}
		}
		if filter.Type != nil && *filter.Type != "" && s.Type != *filter.Type {
			continue
		}
		if filter.Classification != nil && *filter.Classification != "" {
			if *filter.Classification == "unclassified" {
				if s.Classification != "" {
					continue
				}
			} else if s.Classification != *filter.Classification {
				continue
			}
		}
		if filter.ExpiresBefore != nil {
			if s.Expiration == nil || !s.Expiration.Before(*filter.ExpiresBefore) {
				continue // no expiration, or expires at/after the cutoff
			}
		}
		out = append(out, s)
	}
	return out
}

// sortSecrets sorts the secret list by name, created_at, updated_at, or owner.
// Uses strict comparators (Before/After, <, >) so equal elements return false in
// both directions, letting sort.SliceStable preserve insertion order as a tie-break.
func (c *KeyorixCore) sortSecrets(secrets []*models.SecretWithSharingInfo, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "updated_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	desc := sortOrder == "desc"
	sort.SliceStable(secrets, func(i, j int) bool {
		a, b := secrets[i], secrets[j]
		switch sortBy {
		case "name":
			if desc {
				return a.Name > b.Name
			}
			return a.Name < b.Name
		case "created_at":
			if desc {
				return a.CreatedAt.After(b.CreatedAt)
			}
			return a.CreatedAt.Before(b.CreatedAt)
		case "owner":
			if desc {
				return a.OwnerUsername > b.OwnerUsername
			}
			return a.OwnerUsername < b.OwnerUsername
		default: // updated_at / recently modified
			if desc {
				return a.UpdatedAt.After(b.UpdatedAt)
			}
			return a.UpdatedAt.Before(b.UpdatedAt)
		}
	})
}

// convertToStorageFilter converts SecretListFilter to storage.SecretFilter.
func (c *KeyorixCore) convertToStorageFilter(filter *models.SecretListFilter) *storage.SecretFilter {
	f := &storage.SecretFilter{
		Page:           filter.Page,
		PageSize:       filter.PageSize,
		Type:           filter.Type,
		Classification: filter.Classification,
		CreatedBy:      filter.CreatedBy,
		ProjectID:      filter.ProjectID,
		EnvironmentID:  filter.EnvironmentID,
		IncludeDeleted: filter.IncludeDeleted,
	}
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 20
	}
	return f
}
