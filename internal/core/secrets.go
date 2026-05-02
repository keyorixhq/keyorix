package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSecretRequest represents a request to create a new secret.
type CreateSecretRequest struct {
	Name          string            `json:"name" validate:"required,min=1,max=255"`
	Value         []byte            `json:"value" validate:"required"`
	NamespaceID   uint              `json:"namespace_id" validate:"required"`
	ZoneID        uint              `json:"zone_id" validate:"required"`
	EnvironmentID uint              `json:"environment_id" validate:"required"`
	Type          string            `json:"type" validate:"required"`
	MaxReads      *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration    *time.Time        `json:"expiration,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	CreatedBy     string            `json:"created_by" validate:"required"`
	OwnerID       uint              `json:"owner_id,omitempty"`
}

// UpdateSecretRequest represents a request to update an existing secret.
type UpdateSecretRequest struct {
	ID         uint              `json:"id" validate:"required"`
	Value      []byte            `json:"value,omitempty"`
	MaxReads   *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
	Expiration *time.Time        `json:"expiration,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	UpdatedBy  string            `json:"updated_by" validate:"required"`
	UserID     uint              `json:"user_id,omitempty"` // For permission checking
}

// CreateSecret creates a new secret with business logic validation.
func (c *KeyorixCore) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*models.SecretNode, error) {
	if err := c.validateCreateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	existing, err := c.storage.GetSecretByName(ctx, req.Name, req.NamespaceID, req.ZoneID, req.EnvironmentID)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretAlreadyExists", nil))
	}

	secret := &models.SecretNode{
		Name:          req.Name,
		NamespaceID:   req.NamespaceID,
		ZoneID:        req.ZoneID,
		EnvironmentID: req.EnvironmentID,
		Type:          req.Type,
		MaxReads:      req.MaxReads,
		Expiration:    req.Expiration,
		IsSecret:      true,
		Status:        "active",
		CreatedBy:     req.CreatedBy,
		OwnerID:       req.OwnerID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	createdSecret, err := c.storage.CreateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if err := c.storeSecretVersion(ctx, createdSecret, req.Value, 1); err != nil {
		if delErr := c.storage.DeleteSecret(ctx, createdSecret.ID); delErr != nil {
			log.Printf("warning: failed to cleanup orphaned secret %d after failed version creation: %v", createdSecret.ID, delErr)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return createdSecret, nil
}

// GetSecret retrieves a secret by ID with business logic validation.
func (c *KeyorixCore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}

	return secret, nil
}

// GetSecretWithPermissionCheck retrieves a secret by ID with permission validation.
func (c *KeyorixCore) GetSecretWithPermissionCheck(ctx context.Context, id, userID uint) (*models.SecretNode, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, id, userID); err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, id)
}

// UpdateSecret updates an existing secret with business logic validation.
func (c *KeyorixCore) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if err := c.validateUpdateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	secret, err := c.storage.GetSecret(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	if req.MaxReads != nil {
		secret.MaxReads = req.MaxReads
	}
	if req.Expiration != nil {
		secret.Expiration = req.Expiration
	}
	if req.Metadata != nil {
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		secret.Metadata = metadataJSON
	}
	secret.UpdatedAt = time.Now()

	if len(req.Value) > 0 {
		latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
		nextVersionNumber := 1
		if err == nil && latestVersion != nil {
			nextVersionNumber = latestVersion.VersionNumber + 1
		}
		if err := c.storeSecretVersion(ctx, secret, req.Value, nextVersionNumber); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}

	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return updatedSecret, nil
}

// UpdateSecretWithPermissionCheck updates an existing secret with permission validation.
func (c *KeyorixCore) UpdateSecretWithPermissionCheck(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if req.UserID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretWritePermission(ctx, req.ID, req.UserID); err != nil {
		return nil, err
	}
	return c.UpdateSecret(ctx, req)
}

// RotateSecret creates a new version of the secret with a new value and updates LastRotatedAt.
func (c *KeyorixCore) RotateSecret(ctx context.Context, id uint, newValue []byte, rotatedBy string) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}

	latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
	nextVersionNumber := 1
	if err == nil && latestVersion != nil {
		nextVersionNumber = latestVersion.VersionNumber + 1
	}
	if err := c.storeSecretVersion(ctx, secret, newValue, nextVersionNumber); err != nil {
		return nil, fmt.Errorf("failed to store rotated secret: %w", err)
	}

	now := time.Now()
	secret.LastRotatedAt = &now
	secret.UpdatedAt = now
	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to update rotation timestamp: %w", err)
	}
	return updatedSecret, nil
}

// DeleteSecret deletes a secret by ID.
func (c *KeyorixCore) DeleteSecret(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if _, err := c.storage.GetSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if err := c.storage.DeleteSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// DeleteSecretWithPermissionCheck deletes a secret by ID with permission validation.
func (c *KeyorixCore) DeleteSecretWithPermissionCheck(ctx context.Context, id, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}
	if _, err := c.EnforceSecretOwnerPermission(ctx, id, userID); err != nil {
		return err
	}
	return c.DeleteSecret(ctx, id)
}

// ListSecrets lists secrets with filtering options.
func (c *KeyorixCore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if filter == nil {
		filter = &storage.SecretFilter{}
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
	secrets, total, err := c.storage.ListSecrets(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// storeSecretVersion is a shared helper used by Create, Update, and Rotate.
// It routes through encryption if enabled, otherwise stores the raw value.
func (c *KeyorixCore) storeSecretVersion(ctx context.Context, secret *models.SecretNode, value []byte, versionNumber int) error {
	if c.encryption != nil {
		_, err := c.encryption.StoreSecret(secret, value)
		return err
	}
	version := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		VersionNumber:      versionNumber,
		EncryptedValue:     value,
		EncryptionMetadata: []byte("{}"),
		ReadCount:          0,
		CreatedAt:          time.Now(),
	}
	_, err := c.storage.CreateSecretVersion(ctx, version)
	return err
}

// validateCreateSecretRequest validates a create secret request.
func (c *KeyorixCore) validateCreateSecretRequest(req *CreateSecretRequest) error {
	if req.Name == "" {
		return fmt.Errorf("%s", i18n.T("LabelName", nil))
	}
	if len(req.Value) == 0 {
		return fmt.Errorf("%s", i18n.T("LabelValue", nil))
	}
	if req.NamespaceID == 0 {
		return fmt.Errorf("%s", i18n.T("LabelNamespace", nil))
	}
	if req.ZoneID == 0 {
		return fmt.Errorf("%s", i18n.T("LabelZone", nil))
	}
	if req.EnvironmentID == 0 {
		return fmt.Errorf("%s", i18n.T("LabelEnvironment", nil))
	}
	if req.CreatedBy == "" {
		return fmt.Errorf("%s", i18n.T("ErrorRequiredField", nil))
	}
	return nil
}

// validateUpdateSecretRequest validates an update secret request.
func (c *KeyorixCore) validateUpdateSecretRequest(req *UpdateSecretRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.UpdatedBy == "" {
		return fmt.Errorf("%s", i18n.T("ErrorRequiredField", nil))
	}
	return nil
}
