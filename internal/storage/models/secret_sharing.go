package models

import (
	"errors"
	"fmt"
)

// IsOwner checks if the given user ID is the owner of the secret
func (s *SecretNode) IsOwner(userID uint) bool {
	return s.OwnerID == userID
}

// CanAccess checks if a user has access to this secret
// This is a placeholder - the actual implementation will depend on the storage layer
// which will need to check if there's a share record for this user
func (s *SecretNode) CanAccess(userID uint) bool {
	// Owner always has access
	if s.IsOwner(userID) {
		return true
	}

	// For non-owners, we'll need to check share records
	// This will be implemented in the storage layer
	return false
}

// CanWrite checks if a user has write permission for this secret
// This is a placeholder - the actual implementation will depend on the storage layer
func (s *SecretNode) CanWrite(userID uint) bool {
	// Owner always has write permission
	if s.IsOwner(userID) {
		return true
	}

	// For non-owners, we'll need to check share records with write permission
	// This will be implemented in the storage layer
	return false
}

// SetOwner sets the owner of the secret
func (s *SecretNode) SetOwner(userID uint) error {
	if userID == 0 {
		return errors.New("owner ID cannot be zero")
	}
	s.OwnerID = userID
	return nil
}

// ValidateOwnership ensures the secret has a valid owner
func (s *SecretNode) ValidateOwnership() error {
	if s.OwnerID == 0 {
		return errors.New("secret must have an owner")
	}
	return nil
}

// SharePermissionLevel represents the permission level for a shared secret
type SharePermissionLevel string

const (
	// SharePermissionRead allows reading the secret
	SharePermissionRead SharePermissionLevel = "read"

	// SharePermissionWrite allows reading and writing to the secret
	SharePermissionWrite SharePermissionLevel = "write"
)

// ValidatePermissionLevel validates that a permission level is valid
func ValidatePermissionLevel(permission string) error {
	if permission != string(SharePermissionRead) && permission != string(SharePermissionWrite) {
		return fmt.Errorf("invalid permission level: %s (must be 'read' or 'write')", permission)
	}
	return nil
}
