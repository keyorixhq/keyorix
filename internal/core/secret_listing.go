package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsWithSharingInfo lists secrets with sharing information for a specific user
func (c *KeyorixCore) ListSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	if filter == nil {
		filter = &models.SecretListFilter{}
	}

	// Set default pagination
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

	// Get owned secrets if not filtering for shared only
	if !filter.ShowSharedOnly {
		ownedSecrets, err := c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
		allSecrets = append(allSecrets, ownedSecrets...)
		ownedCount = len(ownedSecrets)
	}

	// Get shared secrets if not filtering for owned only
	if !filter.ShowOwnedOnly {
		sharedSecrets, err := c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
		allSecrets = append(allSecrets, sharedSecrets...)
		sharedCount = len(sharedSecrets)
	}

	// Apply additional filters
	filteredSecrets := c.applySecretFilters(allSecrets, filter)

	// Sort secrets
	c.sortSecrets(filteredSecrets, filter.SortBy, filter.SortOrder)

	// Apply pagination
	total := int64(len(filteredSecrets))
	start := (filter.Page - 1) * filter.PageSize
	end := start + filter.PageSize

	if start > len(filteredSecrets) {
		start = len(filteredSecrets)
	}
	if end > len(filteredSecrets) {
		end = len(filteredSecrets)
	}

	paginatedSecrets := filteredSecrets[start:end]
	totalPages := int((total + int64(filter.PageSize) - 1) / int64(filter.PageSize))

	return &models.SecretListResponse{
		Secrets:     paginatedSecrets,
		Total:       total,
		Page:        filter.Page,
		PageSize:    filter.PageSize,
		TotalPages:  totalPages,
		OwnedCount:  ownedCount,
		SharedCount: sharedCount,
	}, nil
}

// getOwnedSecretsWithSharingInfo retrieves secrets owned by the user with sharing information
func (c *KeyorixCore) getOwnedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	// Convert to storage filter
	storageFilter := c.convertToStorageFilter(filter)
	// Note: CreatedBy filter removed — secrets are visible to all authenticated users with access

	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, secret := range secrets {
		// Get sharing information for this secret
		shares, err := c.storage.ListSharesBySecret(ctx, secret.ID)
		if err != nil {
			// Log error but continue
			continue
		}

		secretWithSharing := &models.SecretWithSharingInfo{
			SecretNode:     secret,
			IsShared:       len(shares) > 0,
			IsOwnedByUser:  true,
			UserPermission: "", // Owner has full permissions
			ShareCount:     len(shares),
		}

		// Add UI indicators for owned secrets
		secretWithSharing.SharingIndicators = c.buildSharingIndicators(secret, shares, true, "")

		result = append(result, secretWithSharing)
	}

	return result, nil
}

// getSharedSecretsWithSharingInfo retrieves secrets shared with the user
func (c *KeyorixCore) getSharedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	// Get all shares for this user
	shares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, share := range shares {
		// Get the secret
		secret, err := c.storage.GetSecret(ctx, share.SecretID)
		if err != nil {
			// Log error but continue
			continue
		}

		// Get owner information
		owner, err := c.storage.GetUser(ctx, secret.OwnerID)
		ownerUsername := ""
		if err == nil && owner != nil {
			ownerUsername = owner.Username
		}

		secretWithSharing := &models.SecretWithSharingInfo{
			SecretNode:     secret,
			IsShared:       true,
			IsOwnedByUser:  false,
			OwnerUsername:  ownerUsername,
			UserPermission: share.Permission,
			ShareCount:     1, // We know at least this user has access
			SharedAt:       &share.CreatedAt,
		}

		// Add UI indicators for shared secrets
		secretWithSharing.SharingIndicators = c.buildSharingIndicators(secret, []*models.ShareRecord{share}, false, share.Permission)

		result = append(result, secretWithSharing)
	}

	return result, nil
}

// applySecretFilters applies additional filters to the secret list
func (c *KeyorixCore) applySecretFilters(secrets []*models.SecretWithSharingInfo, filter *models.SecretListFilter) []*models.SecretWithSharingInfo {
	var filtered []*models.SecretWithSharingInfo

	for _, secret := range secrets {
		// Apply permission filter
		if filter.Permission != "" {
			if secret.IsOwnedByUser {
				// Owner has all permissions, so only include if filter allows it
				if filter.Permission != "read" && filter.Permission != "write" {
					continue
				}
			} else {
				// Check user's permission
				if secret.UserPermission != filter.Permission {
					continue
				}
			}
		}

		// Apply type filter
		if filter.Type != nil && secret.Type != *filter.Type {
			continue
		}

		// Apply namespace filter
		if filter.NamespaceID != nil && secret.NamespaceID != *filter.NamespaceID {
			continue
		}

		// Apply zone filter
		if filter.ZoneID != nil && secret.ZoneID != *filter.ZoneID {
			continue
		}

		// Apply environment filter
		if filter.EnvironmentID != nil && secret.EnvironmentID != *filter.EnvironmentID {
			continue
		}

		// Apply date filters
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

// sortSecrets sorts the secret list based on the specified criteria
func (c *KeyorixCore) sortSecrets(secrets []*models.SecretWithSharingInfo, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "name" // Default sort by name
	}
	if sortOrder == "" {
		sortOrder = "asc" // Default ascending order
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

// convertToStorageFilter converts SecretListFilter to storage.SecretFilter
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

// GetSecretSharingStatus returns the sharing status of a secret
func (c *KeyorixCore) GetSecretSharingStatus(ctx context.Context, secretID uint) (*models.SharingStatus, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	// Get all shares for this secret
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	status := &models.SharingStatus{
		IsShared:   len(shares) > 0,
		ShareCount: len(shares),
	}

	// Get detailed share information
	for _, share := range shares {
		var recipientName string
		if share.IsGroup {
			// TODO: Get group name when group functionality is available
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			// Get user name
			user, err := c.storage.GetUser(ctx, share.RecipientID)
			if err == nil && user != nil {
				recipientName = user.Username
			}
		}

		shareSummary := &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		}

		status.Shares = append(status.Shares, shareSummary)
	}

	return status, nil
}

// GetSecretSharingStatusWithIndicators returns the sharing status of a secret with UI indicators
func (c *KeyorixCore) GetSecretSharingStatusWithIndicators(ctx context.Context, secretID, userID uint) (*models.SharingStatusWithIndicators, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Get the secret to check ownership
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	// Get all shares for this secret
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Check user's permission
	isOwner := secret.OwnerID == userID
	userPermission := ""
	
	if !isOwner {
		// Find user's permission through shares
		for _, share := range shares {
			if !share.IsGroup && share.RecipientID == userID {
				userPermission = share.Permission
				break
			}
		}
		
		// If no direct share found, user has no access
		if userPermission == "" {
			return nil, fmt.Errorf("user does not have permission to access this secret")
		}
	}

	status := &models.SharingStatusWithIndicators{
		IsShared:   len(shares) > 0,
		ShareCount: len(shares),
		IsOwner:    isOwner,
		UserPermission: userPermission,
	}

	// Get detailed share information
	for _, share := range shares {
		var recipientName string
		if share.IsGroup {
			// TODO: Get group name when group functionality is available
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			// Get user name
			user, err := c.storage.GetUser(ctx, share.RecipientID)
			if err == nil && user != nil {
				recipientName = user.Username
			} else {
				recipientName = fmt.Sprintf("User %d", share.RecipientID)
			}
		}

		shareSummary := &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		}

		status.Shares = append(status.Shares, shareSummary)
	}

	// Add UI indicators
	status.SharingIndicators = c.buildSharingIndicators(secret, shares, isOwner, userPermission)

	return status, nil
}

// GetUserSecretPermission returns a user's permission for a specific secret
func (c *KeyorixCore) GetUserSecretPermission(ctx context.Context, secretID, userID uint) (*models.UserSecretPermission, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Get the secret to check ownership
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	// Check if user is the owner
	if secret.OwnerID == userID {
		return &models.UserSecretPermission{
			SecretID:   secretID,
			UserID:     userID,
			Permission: "owner",
			Source:     "owner",
		}, nil
	}

	// Check direct shares
	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	for _, share := range shares {
		if !share.IsGroup && share.RecipientID == userID {
			return &models.UserSecretPermission{
				SecretID:   secretID,
				UserID:     userID,
				Permission: share.Permission,
				Source:     "direct_share",
				ShareID:    &share.ID,
			}, nil
		}
	}

	// Check group shares (if group functionality is implemented)
	// This would require checking if the user is a member of any groups that have access
	// For now, we'll return no permission
	return nil, fmt.Errorf("user does not have permission to access this secret")
}

// buildSharingIndicators creates UI indicators for a secret based on sharing information
func (c *KeyorixCore) buildSharingIndicators(secret *models.SecretNode, shares []*models.ShareRecord, isOwner bool, userPermission string) *models.SharingIndicators {
	indicators := &models.SharingIndicators{
		CanRead:   true, // All users with access can read
		CanWrite:  isOwner || userPermission == "write",
		CanShare:  isOwner, // Only owners can share
		CanDelete: isOwner, // Only owners can delete
	}

	// Set visual indicators based on ownership and sharing status
	if isOwner {
		if len(shares) > 0 {
			indicators.Icon = "shared-owner"
			indicators.Badge = "OWNER"
			indicators.BadgeColor = "green"
			indicators.StatusText = fmt.Sprintf("You own this secret (shared with %d)", len(shares))
		} else {
			indicators.Icon = "owned"
			indicators.Badge = "OWNER"
			indicators.BadgeColor = "blue"
			indicators.StatusText = "You own this secret"
		}
	} else {
		// User has access through sharing
		switch userPermission {
		case "read":
			indicators.Icon = "shared-read"
			indicators.Badge = "READ-ONLY"
			indicators.BadgeColor = "orange"
			indicators.StatusText = "Shared with you (read-only)"
		case "write":
			indicators.Icon = "shared-write"
			indicators.Badge = "SHARED"
			indicators.BadgeColor = "blue"
			indicators.StatusText = "Shared with you (can edit)"
		default:
			indicators.Icon = "shared"
			indicators.Badge = "SHARED"
			indicators.BadgeColor = "gray"
			indicators.StatusText = "Shared with you"
		}
	}

	// Build share details for UI
	if len(shares) > 0 {
		indicators.ShareDetails = c.buildShareDetails(shares)
	}

	return indicators
}

// buildShareDetails creates detailed sharing information for UI
func (c *KeyorixCore) buildShareDetails(shares []*models.ShareRecord) *models.ShareDetails {
	details := &models.ShareDetails{
		TotalShares: len(shares),
	}

	var directShares, groupShares int
	var recentShares []*models.RecentShareInfo
	
	// Analyze shares
	for _, share := range shares {
		if share.IsGroup {
			groupShares++
		} else {
			directShares++
		}

		// Check if share is recent (within last 7 days)
		isRecent := time.Since(share.CreatedAt).Hours() < 168 // 7 days * 24 hours

		// Get recipient name with actual user/group lookups
		recipientName := fmt.Sprintf("User %d", share.RecipientID)
		recipientType := "user"
		if share.IsGroup {
			recipientType = "group"
			// TODO: Get group name when group functionality is available
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			// Try to get user name
			if user, err := c.storage.GetUser(context.Background(), share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			} else {
				recipientName = fmt.Sprintf("User %d", share.RecipientID)
			}
		}

		recentShare := &models.RecentShareInfo{
			RecipientName: recipientName,
			RecipientType: recipientType,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
			IsRecent:      isRecent,
		}

		// Only include recent shares or limit to first 5
		if isRecent || len(recentShares) < 5 {
			recentShares = append(recentShares, recentShare)
		}
	}

	details.DirectShares = directShares
	details.GroupShares = groupShares
	details.RecentShares = recentShares

	// Build summary text
	if directShares > 0 && groupShares > 0 {
		details.ShareSummary = fmt.Sprintf("Shared with %d users and %d groups", directShares, groupShares)
	} else if directShares > 0 {
		details.ShareSummary = fmt.Sprintf("Shared with %d users", directShares)
	} else if groupShares > 0 {
		details.ShareSummary = fmt.Sprintf("Shared with %d groups", groupShares)
	} else {
		details.ShareSummary = "Not shared"
	}

	// Build permission text
	readCount := 0
	writeCount := 0
	for _, share := range shares {
		if share.Permission == "read" {
			readCount++
		} else if share.Permission == "write" {
			writeCount++
		}
	}

	if readCount > 0 && writeCount > 0 {
		details.PermissionText = fmt.Sprintf("%d with read access, %d with write access", readCount, writeCount)
	} else if readCount > 0 {
		details.PermissionText = fmt.Sprintf("%d with read access", readCount)
	} else if writeCount > 0 {
		details.PermissionText = fmt.Sprintf("%d with write access", writeCount)
	}

	return details
}