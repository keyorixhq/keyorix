package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	IsActive    bool   `json:"is_active"`
}

// CreateUser creates a new user with business logic validation
func (c *KeyorixCore) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	// Validate request
	if err := c.validateCreateUserRequest(req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Check if user with same email already exists
	existing, err := c.storage.GetUserByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%s: user with email already exists", i18n.T("ErrorValidation", nil))
	}

	// Create user model
	user := &models.User{
		Username:  req.Username,
		Email:     req.Email,
		CreatedAt: time.Now(),
	}

	// Store user
	createdUser, err := c.storage.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return createdUser, nil
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