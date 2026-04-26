package core

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// KeyorixCore represents the core business logic layer
// It orchestrates all business operations while remaining transport-agnostic
type KeyorixCore struct {
	storage    storage.Storage
	encryption *encryption.SecretEncryption
	now        func() time.Time // For testability
}

// NewKeyorixCore creates a new instance of the core business logic
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:    storage,
		encryption: nil, // No encryption by default
		now:        time.Now, // Use actual time by default
	}
}

// NewKeyorixCoreWithEncryption creates a new instance with encryption support
func NewKeyorixCoreWithEncryption(storage storage.Storage, encryption *encryption.SecretEncryption) *KeyorixCore {
	return &KeyorixCore{
		storage:    storage,
		encryption: encryption,
		now:        time.Now, // Use actual time by default
	}
}

// Storage returns the underlying storage interface (used by ancillary services such as AnomalyDetector).
func (c *KeyorixCore) Storage() storage.Storage {
	return c.storage
}

// ListActiveSecrets returns all secrets for anomaly detection. Returns empty slice on error.
func (c *KeyorixCore) ListActiveSecrets(ctx context.Context) []models.SecretNode {
	secrets, _, err := c.ListSecrets(ctx, nil)
	if err != nil || secrets == nil {
		return nil
	}
	result := make([]models.SecretNode, 0, len(secrets))
	for _, s := range secrets {
		if s != nil {
			result = append(result, *s)
		}
	}
	return result
}

// Secret Management Operations

// CreateSecretRequest represents a request to create a new secret
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

// UpdateSecretRequest represents a request to update an existing secret
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

// CreateSecret creates a new secret with business logic validation
func (c *KeyorixCore) CreateSecret(ctx context.Context, req *CreateSecretRequest) (*models.SecretNode, error) {
	// Validate request
	if err := c.validateCreateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Check if secret with same name already exists
	existing, err := c.storage.GetSecretByName(ctx, req.Name, req.NamespaceID, req.ZoneID, req.EnvironmentID)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretAlreadyExists", nil))
	}

	// Create secret model
	secret := &models.SecretNode{
		Name:          req.Name,
		NamespaceID:   req.NamespaceID,
		ZoneID:        req.ZoneID,
		EnvironmentID: req.EnvironmentID,
		Type:          req.Type,
		MaxReads:      req.MaxReads,
		Expiration:    req.Expiration,
		IsSecret:      true, // Mark as secret
		Status:        "active",
		CreatedBy:     req.CreatedBy,
		OwnerID:       req.OwnerID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Store secret
	createdSecret, err := c.storage.CreateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Create the first version with the secret value
	if c.encryption != nil {
		// Use encryption service to store the secret
		_, err = c.encryption.StoreSecret(createdSecret, req.Value)
		if err != nil {
			// If version creation fails, we should clean up the secret
			c.storage.DeleteSecret(ctx, createdSecret.ID)
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	} else {
		// Store without encryption
		version := &models.SecretVersion{
			SecretNodeID:       createdSecret.ID,
			VersionNumber:      1,
			EncryptedValue:     req.Value,
			EncryptionMetadata: []byte("{}"),
			ReadCount:          0,
			CreatedAt:          time.Now(),
		}

		_, err = c.storage.CreateSecretVersion(ctx, version)
		if err != nil {
			// If version creation fails, we should clean up the secret
			c.storage.DeleteSecret(ctx, createdSecret.ID)
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}

	return createdSecret, nil
}

// GetSecret retrieves a secret by ID with business logic validation
func (c *KeyorixCore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Check if secret has expired
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}

	return secret, nil
}

// GetSecretWithPermissionCheck retrieves a secret by ID with permission validation
func (c *KeyorixCore) GetSecretWithPermissionCheck(ctx context.Context, id, userID uint) (*models.SecretNode, error) {
	// Check permission first
	_, err := c.EnforceSecretReadPermission(ctx, id, userID)
	if err != nil {
		return nil, err
	}

	// Get the secret
	return c.GetSecret(ctx, id)
}

// UpdateSecret updates an existing secret with business logic validation
func (c *KeyorixCore) UpdateSecret(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	// Validate request
	if err := c.validateUpdateSecretRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Get existing secret
	secret, err := c.storage.GetSecret(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Update fields
	if req.MaxReads != nil {
		secret.MaxReads = req.MaxReads
	}
	if req.Expiration != nil {
		secret.Expiration = req.Expiration
	}
	if req.Metadata != nil {
		// Convert map[string]string to JSON
		metadataJSON, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorInvalidMetadata", nil), err)
		}
		secret.Metadata = metadataJSON
	}
	secret.UpdatedAt = time.Now()

	// If value is being updated, create a new version
	if req.Value != nil && len(req.Value) > 0 {
		if c.encryption != nil {
			// Use encryption service to store the new version
			_, err = c.encryption.StoreSecret(secret, req.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
		} else {
			// Get the latest version to determine next version number
			latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
			nextVersionNumber := 1
			if err == nil && latestVersion != nil {
				nextVersionNumber = latestVersion.VersionNumber + 1
			}

			// Create new version without encryption
			newVersion := &models.SecretVersion{
				SecretNodeID:       secret.ID,
				VersionNumber:      nextVersionNumber,
				EncryptedValue:     req.Value,
				EncryptionMetadata: []byte("{}"),
				ReadCount:          0,
				CreatedAt:          time.Now(),
			}

			_, err = c.storage.CreateSecretVersion(ctx, newVersion)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
		}
	}

	// Store updated secret
	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return updatedSecret, nil
}

// RotateSecret creates a new version of the secret with a new value and updates LastRotatedAt.
func (c *KeyorixCore) RotateSecret(ctx context.Context, id uint, newValue []byte, rotatedBy string) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	// Store new version
	if c.encryption != nil {
		_, err = c.encryption.StoreSecret(secret, newValue)
		if err != nil {
			return nil, fmt.Errorf("failed to store rotated secret: %w", err)
		}
	} else {
		latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
		nextVersionNumber := 1
		if err == nil && latestVersion != nil {
			nextVersionNumber = latestVersion.VersionNumber + 1
		}
		newVersion := &models.SecretVersion{
			SecretNodeID:       secret.ID,
			VersionNumber:      nextVersionNumber,
			EncryptedValue:     newValue,
			EncryptionMetadata: []byte("{}"),
			ReadCount:          0,
			CreatedAt:          time.Now(),
		}
		if _, err = c.storage.CreateSecretVersion(ctx, newVersion); err != nil {
			return nil, fmt.Errorf("failed to store rotated secret: %w", err)
		}
	}
	// Update LastRotatedAt
	now := time.Now()
	secret.LastRotatedAt = &now
	secret.UpdatedAt = now
	updatedSecret, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to update rotation timestamp: %w", err)
	}
	return updatedSecret, nil
}

// UpdateSecretWithPermissionCheck updates an existing secret with permission validation
func (c *KeyorixCore) UpdateSecretWithPermissionCheck(ctx context.Context, req *UpdateSecretRequest) (*models.SecretNode, error) {
	if req.UserID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Check if user has write permission
	_, err := c.EnforceSecretWritePermission(ctx, req.ID, req.UserID)
	if err != nil {
		return nil, err
	}

	// Call the original update method
	return c.UpdateSecret(ctx, req)
}

// DeleteSecret deletes a secret by ID
func (c *KeyorixCore) DeleteSecret(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	// Verify secret exists
	_, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Delete secret
	if err := c.storage.DeleteSecret(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// DeleteSecretWithPermissionCheck deletes a secret by ID with permission validation
func (c *KeyorixCore) DeleteSecretWithPermissionCheck(ctx context.Context, id, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Only owners can delete secrets
	_, err := c.EnforceSecretOwnerPermission(ctx, id, userID)
	if err != nil {
		return err
	}

	// Call the original delete method
	return c.DeleteSecret(ctx, id)
}

// ListSecrets lists secrets with filtering options
func (c *KeyorixCore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if filter == nil {
		filter = &storage.SecretFilter{}
	}

	// Set default pagination if not specified
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	}
	if filter.PageSize > 100 {
		filter.PageSize = 100 // Limit maximum page size
	}

	secrets, total, err := c.storage.ListSecrets(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	return secrets, total, nil
}

// Secret Version Management Operations

// GetSecretVersions retrieves all versions of a secret
func (c *KeyorixCore) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	// Verify secret exists
	_, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Get versions
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return versions, nil
}

// GetSecretVersionsWithPermissionCheck retrieves all versions of a secret with permission validation
func (c *KeyorixCore) GetSecretVersionsWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Validate access
	_, err := c.EnforceSecretReadPermission(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Call the original method
	return c.GetSecretVersions(ctx, secretID)
}

// GetSecretVersion retrieves a specific version of a secret
func (c *KeyorixCore) GetSecretVersion(ctx context.Context, secretID uint, versionNumber int) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}

	// Get all versions and find the specific one
	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	for _, version := range versions {
		if version.VersionNumber == versionNumber {
			return version, nil
		}
	}

	return nil, fmt.Errorf("%s: version %d not found", i18n.T("ErrorVersionNotFound", nil), versionNumber)
}

// GetSecretVersionWithPermissionCheck retrieves a specific version of a secret with permission validation
func (c *KeyorixCore) GetSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Validate access
	_, err := c.EnforceSecretReadPermission(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Call the original method
	return c.GetSecretVersion(ctx, secretID, versionNumber)
}

// GetLatestSecretVersion retrieves the latest version of a secret
func (c *KeyorixCore) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	versions, err := c.storage.GetSecretVersions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNoVersionsFound", nil))
	}

	// Versions are ordered by version DESC, so first is latest
	return versions[0], nil
}

// GetLatestSecretVersionWithPermissionCheck retrieves the latest version of a secret with permission validation
func (c *KeyorixCore) GetLatestSecretVersionWithPermissionCheck(ctx context.Context, secretID, userID uint) (*models.SecretVersion, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Validate access
	_, err := c.ValidateSecretAccess(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Call the original method
	return c.GetLatestSecretVersion(ctx, secretID)
}

// GetSecretValue retrieves the decrypted value of the latest version of a secret
func (c *KeyorixCore) GetSecretValue(ctx context.Context, secretID uint) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}

	// Get the secret first to check expiration and max reads
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Check if secret has expired
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}

	// Get the latest version
	version, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}

	// Check max reads if set
	if secret.MaxReads != nil && *secret.MaxReads > 0 {
		if version.ReadCount >= *secret.MaxReads {
			return nil, fmt.Errorf("%s", i18n.T("ErrorMaxReadsExceeded", nil))
		}
		
		// Increment read count
		if err := c.storage.IncrementSecretReadCount(ctx, version.ID); err != nil {
			// Log but don't fail the operation
			// TODO: Add proper logging
		}
	}

	// Decrypt the value if encryption is enabled
	if c.encryption != nil {
		return c.encryption.RetrieveSecret(version.ID)
	}
	
	// Return unencrypted value
	return version.EncryptedValue, nil
}

// GetSecretValueWithPermissionCheck retrieves the decrypted value with permission validation
func (c *KeyorixCore) GetSecretValueWithPermissionCheck(ctx context.Context, secretID, userID uint) ([]byte, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Validate access
	_, err := c.ValidateSecretAccess(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Get the secret to check max reads
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Get the latest version
	version, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}

	// Check max reads if set
	if secret.MaxReads != nil && *secret.MaxReads > 0 {
		if version.ReadCount >= *secret.MaxReads {
			return nil, fmt.Errorf("%s", i18n.T("ErrorMaxReadsExceeded", nil))
		}
		
		// Increment read count
		if err := c.storage.IncrementSecretReadCount(ctx, version.ID); err != nil {
			// Log but don't fail the operation
			// TODO: Add proper logging
		}
	}

	// Decrypt the value if encryption is enabled
	if c.encryption != nil {
		return c.encryption.RetrieveSecret(version.ID)
	}
	
	// Return unencrypted value
	return version.EncryptedValue, nil
}

// GetSecretValueByVersion retrieves the decrypted value of a specific version of a secret
func (c *KeyorixCore) GetSecretValueByVersion(ctx context.Context, secretID uint, versionNumber int) ([]byte, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if versionNumber <= 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "version number must be positive")
	}

	// Get the secret first to check expiration
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Check if secret has expired
	if secret.Expiration != nil && time.Now().After(*secret.Expiration) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorSecretExpired", nil))
	}

	// Get the specific version
	version, err := c.GetSecretVersion(ctx, secretID, versionNumber)
	if err != nil {
		return nil, err
	}

	// Decrypt the value if encryption is enabled
	if c.encryption != nil {
		return c.encryption.RetrieveSecret(version.ID)
	}
	
	// Return unencrypted value
	return version.EncryptedValue, nil
}

// GetSecretValueByVersionWithPermissionCheck retrieves the decrypted value of a specific version with permission validation
func (c *KeyorixCore) GetSecretValueByVersionWithPermissionCheck(ctx context.Context, secretID, userID uint, versionNumber int) ([]byte, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required for permission checking")
	}

	// Validate access
	_, err := c.ValidateSecretAccess(ctx, secretID, userID)
	if err != nil {
		return nil, err
	}

	// Call the original method
	return c.GetSecretValueByVersion(ctx, secretID, versionNumber)
}

// RBAC Management Operations

// AssignRoleToUser assigns a role to a user by email and role name
func (c *KeyorixCore) AssignRoleToUser(ctx context.Context, userEmail, roleName string) error {
	// Find user by email
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	// Find role by name
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}

	// Assign role using storage interface
	if err := c.storage.AssignRole(ctx, user.ID, role.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// RemoveRoleFromUser removes a role from a user by email and role name
func (c *KeyorixCore) RemoveRoleFromUser(ctx context.Context, userEmail, roleName string) error {
	// Find user by email
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	// Find role by name
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}

	// Remove role using storage interface
	if err := c.storage.RemoveRole(ctx, user.ID, role.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// ListUserRolesByEmail lists roles for a user by email
func (c *KeyorixCore) ListUserRolesByEmail(ctx context.Context, userEmail string) ([]*models.Role, error) {
	// Find user by email
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	// Get user roles using storage interface
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	return roles, nil
}

// HasPermissionByEmail checks if a user has a specific permission by email
func (c *KeyorixCore) HasPermissionByEmail(ctx context.Context, userEmail, resource, action string) (bool, error) {
	// Find user by email
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	// Check permission using storage interface
	hasPermission, err := c.storage.CheckPermission(ctx, user.ID, resource, action)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}

	return hasPermission, nil
}

// ListUserPermissionsByEmail lists permissions for a user by email
func (c *KeyorixCore) ListUserPermissionsByEmail(ctx context.Context, userEmail string) ([]*storage.Permission, error) {
	// Find user by email
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	// Get user permissions using storage interface
	permissions, err := c.storage.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	return permissions, nil
}

// User Management Operations

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	IsActive    *bool  `json:"is_active,omitempty"`
}

// UpdateUserRequest represents a request to update an existing user
type UpdateUserRequest struct {
	ID          uint
	Username    string
	Email       string
	DisplayName string
	IsActive    *bool
}

// CreateGroupRequest represents a request to create a new group
type CreateGroupRequest struct {
	Name        string
	Description string
}

// UpdateGroupRequest represents a request to update an existing group
type UpdateGroupRequest struct {
	ID          uint
	Name        string
	Description string
}

// CreateUser creates a new user with business logic validation
func (c *KeyorixCore) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	// Validate request
	if err := c.validateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
	} else if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	existing, err := c.storage.GetUserByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
	}
	if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	now := c.now()
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  displayName,
		PasswordHash: string(hash),
		IsActive:     active,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	createdUser, err := c.storage.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return createdUser, nil
}

// GetUser retrieves a user by ID
func (c *KeyorixCore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	user, err := c.storage.GetUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// UpdateUser updates an existing user
func (c *KeyorixCore) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*models.User, error) {
	if err := c.validateUpdateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	user, err := c.storage.GetUser(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}

	if req.Username != "" && req.Username != user.Username {
		if _, err := c.storage.GetUserByUsername(ctx, req.Username); err == nil {
			return nil, fmt.Errorf("%s: username already exists", i18n.T("ErrorValidation", nil))
		} else if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Username = req.Username
	}
	if req.Email != "" && req.Email != user.Email {
		existing, err := c.storage.GetUserByEmail(ctx, req.Email)
		if err == nil && existing != nil && existing.ID != user.ID {
			return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
		}
		if err != nil && !strings.Contains(err.Error(), i18n.T("ErrorUserNotFound", nil)) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	user.UpdatedAt = c.now()

	updated, err := c.storage.UpdateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updated, nil
}

// DeleteUser deletes a user by ID
func (c *KeyorixCore) DeleteUser(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if _, err := c.storage.GetUser(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if err := c.storage.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListUsers lists users with filtering and pagination
func (c *KeyorixCore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if filter == nil {
		filter = &storage.UserFilter{}
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
	users, total, err := c.storage.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserByEmail retrieves a user by email address
func (c *KeyorixCore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "email is required")
	}
	user, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	return user, nil
}

// CreateGroup creates a new group
func (c *KeyorixCore) CreateGroup(ctx context.Context, req *CreateGroupRequest) (*models.Group, error) {
	if err := c.validateCreateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group := &models.Group{
		Name:        req.Name,
		Description: req.Description,
	}
	created, err := c.storage.CreateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return created, nil
}

// GetGroup retrieves a group by ID
func (c *KeyorixCore) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	if id == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	group, err := c.storage.GetGroup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return group, nil
}

// UpdateGroup updates an existing group
func (c *KeyorixCore) UpdateGroup(ctx context.Context, req *UpdateGroupRequest) (*models.Group, error) {
	if err := c.validateUpdateGroupRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	group, err := c.storage.GetGroup(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}
	updated, err := c.storage.UpdateGroup(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return updated, nil
}

// DeleteGroup deletes a group by ID
func (c *KeyorixCore) DeleteGroup(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	if _, err := c.storage.GetGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if err := c.storage.DeleteGroup(ctx, id); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListGroups lists all groups
func (c *KeyorixCore) ListGroups(ctx context.Context) ([]*models.Group, error) {
	groups, err := c.storage.ListGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group
func (c *KeyorixCore) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if err := c.storage.AddUserToGroup(ctx, userID, groupID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group
func (c *KeyorixCore) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	if userID == 0 || groupID == 0 {
		return fmt.Errorf("%s: user ID and group ID are required", i18n.T("ErrorValidation", nil))
	}
	if err := c.storage.RemoveUserFromGroup(ctx, userID, groupID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// GetGroupMembers returns all users that belong to a group
func (c *KeyorixCore) GetGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if groupID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "group ID is required")
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return members, nil
}

// Validation methods

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

func (c *KeyorixCore) validateUpdateSecretRequest(req *UpdateSecretRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.UpdatedBy == "" {
		return fmt.Errorf("%s", i18n.T("ErrorRequiredField", nil))
	}
	return nil
}

func (c *KeyorixCore) validateCreateUserRequest(req *CreateUserRequest) error {
	if req.Username == "" {
		return fmt.Errorf("%s", i18n.T("LabelUsername", nil))
	}
	if req.Email == "" {
		return fmt.Errorf("%s", i18n.T("LabelEmail", nil))
	}
	if req.Password == "" {
		return fmt.Errorf("%s", i18n.T("LabelPassword", nil))
	}
	return nil
}

func (c *KeyorixCore) validateUpdateUserRequest(req *UpdateUserRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("user ID is required")
	}
	return nil
}

func (c *KeyorixCore) validateCreateGroupRequest(req *CreateGroupRequest) error {
	if req.Name == "" {
		return fmt.Errorf("group name is required")
	}
	return nil
}

func (c *KeyorixCore) validateUpdateGroupRequest(req *UpdateGroupRequest) error {
	if req.ID == 0 {
		return fmt.Errorf("group ID is required")
	}
	return nil
}
// Permission Enforcement Methods

// PermissionLevel represents the level of access a user has to a secret
type PermissionLevel string

const (
	PermissionNone  PermissionLevel = "none"
	PermissionRead  PermissionLevel = "read"
	PermissionWrite PermissionLevel = "write"
	PermissionOwner PermissionLevel = "owner"
)

// PermissionContext contains information about a user's permission for a secret
type PermissionContext struct {
	SecretID   uint
	UserID     uint
	Permission PermissionLevel
	Source     string // "owner", "direct_share", "group_share"
	ShareID    *uint  // ID of the share record if applicable
}

// CheckSecretPermission checks if a user has the required permission for a secret
func (c *KeyorixCore) CheckSecretPermission(ctx context.Context, secretID, userID uint, requiredPermission PermissionLevel) (*PermissionContext, error) {
	if secretID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID is required")
	}
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	// Get the secret to check ownership
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Check if user is the owner (owners have all permissions)
	if secret.OwnerID == userID {
		return &PermissionContext{
			SecretID:   secretID,
			UserID:     userID,
			Permission: PermissionOwner,
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
			permission := PermissionLevel(share.Permission)
			
			// Check if the user's permission meets the required level
			if c.hasRequiredPermission(permission, requiredPermission) {
				return &PermissionContext{
					SecretID:   secretID,
					UserID:     userID,
					Permission: permission,
					Source:     "direct_share",
					ShareID:    &share.ID,
				}, nil
			}
		}
	}

	// Check group shares
	groupPermission, shareID, err := c.CheckGroupPermissions(ctx, secretID, userID, shares)
	if err == nil && groupPermission != PermissionNone {
		if c.hasRequiredPermission(groupPermission, requiredPermission) {
			return &PermissionContext{
				SecretID:   secretID,
				UserID:     userID,
				Permission: groupPermission,
				Source:     "group_share",
				ShareID:    shareID,
			}, nil
		}
	}

	return nil, fmt.Errorf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
}

// hasRequiredPermission checks if the user's permission level meets the required level
func (c *KeyorixCore) hasRequiredPermission(userPermission, requiredPermission PermissionLevel) bool {
	// Define permission hierarchy: owner > write > read > none
	permissionLevels := map[PermissionLevel]int{
		PermissionNone:  0,
		PermissionRead:  1,
		PermissionWrite: 2,
		PermissionOwner: 3,
	}

	userLevel, exists := permissionLevels[userPermission]
	if !exists {
		return false
	}

	requiredLevel, exists := permissionLevels[requiredPermission]
	if !exists {
		return false
	}

	return userLevel >= requiredLevel
}

// CheckGroupPermissions checks if a user has permission through group membership
func (c *KeyorixCore) CheckGroupPermissions(ctx context.Context, secretID, userID uint, shares []*models.ShareRecord) (PermissionLevel, *uint, error) {
	// Get user's groups
	userGroups, err := c.storage.GetUserGroups(ctx, userID)
	if err != nil {
		return PermissionNone, nil, err
	}

	var highestPermission PermissionLevel = PermissionNone
	var shareID *uint

	// Check each group share
	for _, share := range shares {
		if share.IsGroup {
			// Check if user is a member of this group
			for _, group := range userGroups {
				if group.ID == share.RecipientID {
					permission := PermissionLevel(share.Permission)
					
					// Keep track of the highest permission level
					if c.hasRequiredPermission(permission, highestPermission) {
						highestPermission = permission
						shareID = &share.ID
					}
				}
			}
		}
	}

	return highestPermission, shareID, nil
}

// EnforceSecretReadPermission enforces read permission for secret operations
func (c *KeyorixCore) EnforceSecretReadPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
}

// EnforceSecretWritePermission enforces write permission for secret operations
func (c *KeyorixCore) EnforceSecretWritePermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionWrite)
}

// EnforceSecretOwnerPermission enforces owner permission for secret operations
func (c *KeyorixCore) EnforceSecretOwnerPermission(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	return c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
}

// ValidateSecretAccess validates that a user can access a secret and returns the permission context
func (c *KeyorixCore) ValidateSecretAccess(ctx context.Context, secretID, userID uint) (*PermissionContext, error) {
	// Check if user has at least read permission
	return c.EnforceSecretReadPermission(ctx, secretID, userID)
}

// CanUserModifySecret checks if a user can modify a secret (requires write or owner permission)
func (c *KeyorixCore) CanUserModifySecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionWrite)
	if err != nil {
		return false, nil // No error, just no permission
	}
	return permCtx != nil, nil
}

// CanUserShareSecret checks if a user can share a secret (requires owner permission)
func (c *KeyorixCore) CanUserShareSecret(ctx context.Context, secretID, userID uint) (bool, error) {
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionOwner)
	if err != nil {
		return false, nil // No error, just no permission
	}
	return permCtx != nil, nil
}

// GetEffectivePermission returns the effective permission level for a user on a secret
func (c *KeyorixCore) GetEffectivePermission(ctx context.Context, secretID, userID uint) (PermissionLevel, error) {
	// Try to get the highest permission level
	permCtx, err := c.CheckSecretPermission(ctx, secretID, userID, PermissionRead)
	if err != nil {
		return PermissionNone, nil // User has no access
	}

	return permCtx.Permission, nil
}

// ListUserPermissions returns all secrets a user has access to with their permission levels
func (c *KeyorixCore) ListUserPermissions(ctx context.Context, userID uint) ([]*models.UserSecretPermission, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	var permissions []*models.UserSecretPermission

	// Get owned secrets
	ownedSecrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &[]string{fmt.Sprintf("%d", userID)}[0],
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	for _, secret := range ownedSecrets {
		permissions = append(permissions, &models.UserSecretPermission{
			SecretID:   secret.ID,
			UserID:     userID,
			Permission: string(PermissionOwner),
			Source:     "owner",
		})
	}

	// Get directly shared secrets
	directShares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	for _, share := range directShares {
		permissions = append(permissions, &models.UserSecretPermission{
			SecretID:   share.SecretID,
			UserID:     userID,
			Permission: share.Permission,
			Source:     "direct_share",
			ShareID:    &share.ID,
		})
	}

	// TODO: Get group-shared secrets when group functionality is available
	// For now, skip group permissions

	return permissions, nil
}

// HealthCheck checks the health of the core service and its dependencies
func (c *KeyorixCore) HealthCheck(ctx context.Context) error {
	// Check storage health
	if c.storage == nil {
		return fmt.Errorf("storage not initialized")
	}

	// Delegate to storage health check
	return c.storage.HealthCheck(ctx)
}
// LoginRequest holds credentials for login.
type LoginRequest struct {
	Username string
	Password string
}

// Login validates credentials, creates a session, and returns (session, user, error).
func (c *KeyorixCore) Login(ctx context.Context, req *LoginRequest) (*models.Session, *models.User, error) {
	user, err := c.storage.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	token, err := generateSecureToken()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	expiresAt := c.now().Add(24 * time.Hour)
	session := &models.Session{
		UserID:       user.ID,
		SessionToken: token,
		ExpiresAt:    &expiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}
	return created, user, nil
}

// Logout invalidates the session identified by token.
func (c *KeyorixCore) Logout(ctx context.Context, token string) error {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return fmt.Errorf("session not found")
	}
	return c.storage.DeleteSession(ctx, session.ID)
}

// RefreshSession replaces an existing session with a new token.
func (c *KeyorixCore) RefreshSession(ctx context.Context, token string) (*models.Session, error) {
	old, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("session not found or expired")
	}
	newToken, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	expiresAt := c.now().Add(24 * time.Hour)
	session := &models.Session{
		UserID:       old.UserID,
		SessionToken: newToken,
		ExpiresAt:    &expiresAt,
	}
	created, err := c.storage.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	_ = c.storage.DeleteSession(ctx, old.ID)
	return created, nil
}

// RequestPasswordReset initiates a password reset for the given email (best-effort, no error on unknown email).
func (c *KeyorixCore) RequestPasswordReset(ctx context.Context, email string) error {
	// Best-effort: don't reveal whether the email exists.
	_, err := c.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil
	}
	// TODO: send reset email
	return nil
}

// InitializeSystem creates the first admin user; returns error if users already exist.
func (c *KeyorixCore) InitializeSystem(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 || len(users) > 0 {
		return nil, fmt.Errorf("system already initialized")
	}
	return c.CreateUser(ctx, req)
}

// SeedRequest holds credentials and display name for the initial seed.
type SeedRequest struct {
	Username    string
	Email       string
	Password    string
	DisplayName string
}

// SeedResult is returned after a successful seed.
type SeedResult struct {
	User         *models.User
	Namespace    *models.Namespace
	Zone         *models.Zone
	Environments []*models.Environment
}

// seedPermissionDef describes a permission to create during seeding.
type seedPermissionDef struct {
	Name        string
	Description string
	Resource    string
	Action      string
}

// SeedSystem seeds the first admin user, RBAC data, and default namespace/zone/environments.
// Returns an error wrapping "already seeded" if any users already exist.
func (c *KeyorixCore) SeedSystem(ctx context.Context, req *SeedRequest) (*SeedResult, error) {
	_, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: 1, PageSize: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to check existing users: %w", err)
	}
	if total > 0 {
		return nil, fmt.Errorf("system already seeded")
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	user, err := c.CreateUser(ctx, &CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin user: %w", err)
	}

	// ── Permissions ──────────────────────────────────────────────────────────
	permDefs := []seedPermissionDef{
		{"secrets.read", "Read secrets", "secrets", "read"},
		{"secrets.write", "Create and update secrets", "secrets", "write"},
		{"secrets.delete", "Delete secrets", "secrets", "delete"},
		{"users.read", "View user information", "users", "read"},
		{"users.write", "Create and update users", "users", "write"},
		{"users.delete", "Delete users", "users", "delete"},
		{"roles.read", "View roles", "roles", "read"},
		{"roles.write", "Create and update roles", "roles", "write"},
		{"roles.assign", "Assign roles to users", "roles", "assign"},
		{"audit.read", "View audit logs", "audit", "read"},
		{"system.read", "View system information", "system", "read"},
	}

	permIDs := make(map[string]uint, len(permDefs))
	for _, def := range permDefs {
		p, err := c.storage.CreatePermission(ctx, &models.Permission{
			Name:        def.Name,
			Description: def.Description,
			Resource:    def.Resource,
			Action:      def.Action,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create permission %s: %w", def.Name, err)
		}
		permIDs[def.Name] = p.ID
	}

	// ── Roles ─────────────────────────────────────────────────────────────────
	adminRole, err := c.storage.CreateRole(ctx, &models.Role{Name: "admin", Description: "Administrator with full access"})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin role: %w", err)
	}

	viewerRole, err := c.storage.CreateRole(ctx, &models.Role{Name: "viewer", Description: "Read-only access"})
	if err != nil {
		return nil, fmt.Errorf("failed to create viewer role: %w", err)
	}

	// ── Role → permission assignments ────────────────────────────────────────
	adminPerms := []string{
		"secrets.read", "secrets.write", "secrets.delete",
		"users.read", "users.write", "users.delete",
		"roles.read", "roles.write", "roles.assign",
		"audit.read", "system.read",
	}
	for _, name := range adminPerms {
		if err := c.storage.AssignPermissionToRole(ctx, adminRole.ID, permIDs[name]); err != nil {
			return nil, fmt.Errorf("failed to assign permission %s to admin: %w", name, err)
		}
	}

	viewerPerms := []string{"secrets.read", "users.read", "audit.read"}
	for _, name := range viewerPerms {
		if err := c.storage.AssignPermissionToRole(ctx, viewerRole.ID, permIDs[name]); err != nil {
			return nil, fmt.Errorf("failed to assign permission %s to viewer: %w", name, err)
		}
	}

	// ── Assign admin role to the seeded user ─────────────────────────────────
	if err := c.storage.AssignRole(ctx, user.ID, adminRole.ID); err != nil {
		return nil, fmt.Errorf("failed to assign admin role to user: %w", err)
	}

	// ── Catalog data ─────────────────────────────────────────────────────────
	ns, err := c.storage.CreateNamespace(ctx, &models.Namespace{Name: "default", Description: "Default namespace"})
	if err != nil {
		return nil, fmt.Errorf("failed to create namespace: %w", err)
	}

	zone, err := c.storage.CreateZone(ctx, &models.Zone{Name: "default", Description: "Default zone"})
	if err != nil {
		return nil, fmt.Errorf("failed to create zone: %w", err)
	}

	envNames := []string{"development", "staging", "production"}
	envs := make([]*models.Environment, 0, len(envNames))
	for _, name := range envNames {
		env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: name})
		if err != nil {
			return nil, fmt.Errorf("failed to create environment %s: %w", name, err)
		}
		envs = append(envs, env)
	}

	return &SeedResult{User: user, Namespace: ns, Zone: zone, Environments: envs}, nil
}

// generateSecureToken creates a random hex token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

// ExpiringSecret represents a secret that is expiring soon.
type ExpiringSecret struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expiresAt"`
	DaysLeft    int       `json:"daysLeft"`
}

// StatTrend contains trend data for a dashboard stat.
type StatTrend struct {
	Value      float64 `json:"value"`      // % change vs previous snapshot
	IsPositive bool    `json:"isPositive"` // true = grew, false = shrank
}

// DashboardStats contains summary statistics for the dashboard.
type DashboardStats struct {
	TotalSecrets        int64          `json:"totalSecrets"`
	SharedSecrets       int            `json:"sharedSecrets"`
	SecretsSharedWithMe int            `json:"secretsSharedWithMe"`
	TotalSecretsTrend   *StatTrend     `json:"totalSecretsTrend,omitempty"`
	SharedSecretsTrend  *StatTrend     `json:"sharedSecretsTrend,omitempty"`
	SharedWithMeTrend   *StatTrend     `json:"sharedWithMeTrend,omitempty"`
	ExpiringSecrets     []ExpiringSecret `json:"expiringSecrets,omitempty"`
	RecentActivity      []ActivityItem `json:"recentActivity"`
}

// ActivityItem represents a single entry in the activity feed.
type ActivityItem struct {
	ID         uint      `json:"id"`
	Type       string    `json:"type"`
	SecretName string    `json:"secretName"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
}

// ActivityFeed is the paginated response for the activity endpoint.
type ActivityFeed struct {
	Items    []ActivityItem `json:"items"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
}

// GetDashboardStats returns summary counts and recent activity for the authenticated user.
func (c *KeyorixCore) GetDashboardStats(ctx context.Context, userID uint, username string) (*DashboardStats, error) {
	_, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &username,
		Page:      1,
		PageSize:  1,
	})
	if err != nil {
		total = 0
	}

	outgoing, err := c.storage.ListSharesByOwner(ctx, userID)
	sharedSecrets := 0
	if err == nil {
		sharedSecrets = len(outgoing)
	}

	incoming, err := c.storage.ListSharesByUser(ctx, userID)
	sharedWithMe := 0
	if err == nil {
		sharedWithMe = len(incoming)
	}

	uid := userID
	events, _, _ := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		UserID:   &uid,
		Page:     1,
		PageSize: 5,
	})
	recent := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		recent = append(recent, mapAuditEventToActivity(e, username))
	}

	// Find secrets expiring within 30 days owned by this user
	expiringSecrets := c.getExpiringSecrets(ctx, username)

	stats := &DashboardStats{
		TotalSecrets:        total,
		SharedSecrets:       sharedSecrets,
		SecretsSharedWithMe: sharedWithMe,
		RecentActivity:      recent,
		ExpiringSecrets:     expiringSecrets,
	}

	// Compute trends from previous snapshot
	prev, err := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if err == nil && prev != nil {
		stats.TotalSecretsTrend = computeTrend(float64(prev.TotalSecrets), float64(total))
		stats.SharedSecretsTrend = computeTrend(float64(prev.SharedSecrets), float64(sharedSecrets))
		stats.SharedWithMeTrend = computeTrend(float64(prev.SecretsSharedWithMe), float64(sharedWithMe))
	}

	// Save snapshot (once per day — skip if one exists from today)
	today := time.Now().UTC().Truncate(24 * time.Hour)
	existing, _ := c.storage.GetPreviousStatsSnapshot(ctx, userID)
	if existing == nil || existing.SnapshotDate.Before(today) {
		_ = c.storage.SaveStatsSnapshot(ctx, &models.StatsSnapshot{
			UserID:              userID,
			TotalSecrets:        total,
			SharedSecrets:       sharedSecrets,
			SecretsSharedWithMe: sharedWithMe,
			SnapshotDate:        today,
		})
	}

	return stats, nil
}

// getExpiringSecrets returns secrets owned by the user expiring within 30 days.
func (c *KeyorixCore) getExpiringSecrets(ctx context.Context, username string) []ExpiringSecret {
	now := time.Now().UTC()
	cutoff := now.Add(30 * 24 * time.Hour)

	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		CreatedBy: &username,
		Page:      1,
		PageSize:  100,
	})
	if err != nil {
		return nil
	}

	var expiring []ExpiringSecret
	for _, s := range secrets {
		if s.Expiration == nil {
			continue
		}
		exp := s.Expiration.UTC()
		if exp.After(now) && exp.Before(cutoff) {
			daysLeft := int(exp.Sub(now).Hours() / 24)
			// Resolve environment name
			envName := "unknown"
			if envs, err := c.storage.ListEnvironments(ctx); err == nil {
				for _, e := range envs {
					if e.ID == s.EnvironmentID {
						envName = e.Name
						break
					}
				}
			}
			expiring = append(expiring, ExpiringSecret{
				ID:          s.ID,
				Name:        s.Name,
				Environment: envName,
				ExpiresAt:   exp,
				DaysLeft:    daysLeft,
			})
		}
	}
	return expiring
}

// computeTrend calculates percentage change between previous and current values.
func computeTrend(prev, current float64) *StatTrend {
	if prev == 0 {
		if current == 0 {
			return nil
		}
		return &StatTrend{Value: 100, IsPositive: true}
	}
	change := ((current - prev) / prev) * 100
	if change == 0 {
		return nil
	}
	return &StatTrend{
		Value:      math.Round(math.Abs(change)*10) / 10,
		IsPositive: change > 0,
	}
}



// GetActivityFeed returns a paginated activity feed for the given user.
func (c *KeyorixCore) GetActivityFeed(ctx context.Context, userID uint, username string, page, pageSize int) (*ActivityFeed, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}

	uid := userID
	events, total, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		UserID:   &uid,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return &ActivityFeed{Items: []ActivityItem{}, Total: 0, Page: page, PageSize: pageSize}, nil
	}

	items := make([]ActivityItem, 0, len(events))
	for _, e := range events {
		items = append(items, mapAuditEventToActivity(e, username))
	}

	return &ActivityFeed{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func mapAuditEventToActivity(e *models.AuditEvent, actor string) ActivityItem {
	eventType := e.EventType
	switch e.EventType {
	case "secret.read":
		eventType = "accessed"
	case "secret.created":
		eventType = "created"
	case "secret.updated":
		eventType = "updated"
	case "secret.deleted":
		eventType = "deleted"
	}
	return ActivityItem{
		ID:         e.ID,
		Type:       eventType,
		SecretName: e.Description,
		Timestamp:  e.EventTime,
		Actor:      actor,
	}
}

// ValidateSessionToken looks up a session token, checks expiry, and returns the user and
// their role names. Used by the auth middleware to authenticate real session tokens.
func (c *KeyorixCore) ValidateSessionToken(ctx context.Context, token string) (*models.User, []string, error) {
	session, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return nil, nil, fmt.Errorf("session not found")
	}
	if session.ExpiresAt != nil && c.now().After(*session.ExpiresAt) {
		return nil, nil, fmt.Errorf("session expired")
	}
	user, err := c.storage.GetUser(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found")
	}
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return user, []string{}, nil
	}
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	return user, roleNames, nil
}

// ListNamespaces returns all namespaces from storage.
func (c *KeyorixCore) ListNamespaces(ctx context.Context) ([]*models.Namespace, error) {
	return c.storage.ListNamespaces(ctx)
}

// ListZones returns all zones from storage.
func (c *KeyorixCore) ListZones(ctx context.Context) ([]*models.Zone, error) {
	return c.storage.ListZones(ctx)
}

// ListEnvironments returns all environments from storage.
func (c *KeyorixCore) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	return c.storage.ListEnvironments(ctx)
}
