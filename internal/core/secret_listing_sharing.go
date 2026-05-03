// secret_listing_sharing.go — Sharing status queries and UI indicator builders.
//
// Provides GetSecretSharingStatus, GetSecretSharingStatusWithIndicators,
// GetUserSecretPermission, and the buildSharingIndicators / buildShareDetails helpers
// used by both this file and secret_listing_query.go.
//
// For the main list/filter/sort/paginate flow see secret_listing_query.go.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetSecretSharingStatus returns the sharing status of a secret.
func (c *KeyorixCore) GetSecretSharingStatus(ctx context.Context, secretID uint) (*models.SharingStatus, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	status := &models.SharingStatus{
		IsShared:   len(shares) > 0,
		ShareCount: len(shares),
	}

	for _, share := range shares {
		recipientName := ""
		if share.IsGroup {
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			if user, err := c.storage.GetUser(ctx, share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			}
		}
		status.Shares = append(status.Shares, &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		})
	}
	return status, nil
}

// GetSecretSharingStatusWithIndicators returns the sharing status of a secret with UI indicators.
func (c *KeyorixCore) GetSecretSharingStatusWithIndicators(ctx context.Context, secretID, userID uint) (*models.SharingStatusWithIndicators, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	shares, err := c.storage.ListSharesBySecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	isOwner := secret.OwnerID == userID
	userPermission := ""
	if !isOwner {
		for _, share := range shares {
			if !share.IsGroup && share.RecipientID == userID {
				userPermission = share.Permission
				break
			}
		}
		if userPermission == "" {
			return nil, fmt.Errorf("user does not have permission to access this secret")
		}
	}

	status := &models.SharingStatusWithIndicators{
		IsShared:       len(shares) > 0,
		ShareCount:     len(shares),
		IsOwner:        isOwner,
		UserPermission: userPermission,
	}

	for _, share := range shares {
		recipientName := ""
		if share.IsGroup {
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			if user, err := c.storage.GetUser(ctx, share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			} else {
				recipientName = fmt.Sprintf("User %d", share.RecipientID)
			}
		}
		status.Shares = append(status.Shares, &models.ShareSummary{
			ID:            share.ID,
			RecipientID:   share.RecipientID,
			RecipientName: recipientName,
			IsGroup:       share.IsGroup,
			Permission:    share.Permission,
			SharedAt:      share.CreatedAt,
		})
	}

	status.SharingIndicators = c.buildSharingIndicators(secret, shares, isOwner, userPermission)
	return status, nil
}

// GetUserSecretPermission returns a user's effective permission for a specific secret.
func (c *KeyorixCore) GetUserSecretPermission(ctx context.Context, secretID, userID uint) (*models.UserSecretPermission, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, err
	}

	if secret.OwnerID == userID {
		return &models.UserSecretPermission{
			SecretID:   secretID,
			UserID:     userID,
			Permission: "owner",
			Source:     "owner",
		}, nil
	}

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

	return nil, fmt.Errorf("user does not have permission to access this secret")
}

// buildSharingIndicators creates UI indicators for a secret based on sharing information.
func (c *KeyorixCore) buildSharingIndicators(secret *models.SecretNode, shares []*models.ShareRecord, isOwner bool, userPermission string) *models.SharingIndicators {
	indicators := &models.SharingIndicators{
		CanRead:   true,
		CanWrite:  isOwner || userPermission == "write",
		CanShare:  isOwner,
		CanDelete: isOwner,
	}

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

	if len(shares) > 0 {
		indicators.ShareDetails = c.buildShareDetails(shares)
	}
	return indicators
}

// buildShareDetails creates detailed sharing information for UI display.
func (c *KeyorixCore) buildShareDetails(shares []*models.ShareRecord) *models.ShareDetails {
	details := &models.ShareDetails{TotalShares: len(shares)}

	var directShares, groupShares, readCount, writeCount int
	var recentShares []*models.RecentShareInfo

	for _, share := range shares {
		if share.IsGroup {
			groupShares++
		} else {
			directShares++
		}
		if share.Permission == "read" {
			readCount++
		} else if share.Permission == "write" {
			writeCount++
		}

		isRecent := time.Since(share.CreatedAt).Hours() < 168 // 7 days

		recipientName := fmt.Sprintf("User %d", share.RecipientID)
		recipientType := "user"
		if share.IsGroup {
			recipientType = "group"
			recipientName = fmt.Sprintf("Group %d", share.RecipientID)
		} else {
			if user, err := c.storage.GetUser(context.Background(), share.RecipientID); err == nil && user != nil {
				recipientName = user.Username
			}
		}

		if isRecent || len(recentShares) < 5 {
			recentShares = append(recentShares, &models.RecentShareInfo{
				RecipientName: recipientName,
				RecipientType: recipientType,
				Permission:    share.Permission,
				SharedAt:      share.CreatedAt,
				IsRecent:      isRecent,
			})
		}
	}

	details.DirectShares = directShares
	details.GroupShares = groupShares
	details.RecentShares = recentShares

	switch {
	case directShares > 0 && groupShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d users and %d groups", directShares, groupShares)
	case directShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d users", directShares)
	case groupShares > 0:
		details.ShareSummary = fmt.Sprintf("Shared with %d groups", groupShares)
	default:
		details.ShareSummary = "Not shared"
	}

	switch {
	case readCount > 0 && writeCount > 0:
		details.PermissionText = fmt.Sprintf("%d with read access, %d with write access", readCount, writeCount)
	case readCount > 0:
		details.PermissionText = fmt.Sprintf("%d with read access", readCount)
	case writeCount > 0:
		details.PermissionText = fmt.Sprintf("%d with write access", writeCount)
	}

	return details
}
