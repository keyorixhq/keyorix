package models

import (
	"errors"
	"fmt"
)

// IsOwner checks if the given user ID is the owner of the secret
func (s *SecretNode) IsOwner(userID uint) bool {
	return s.OwnerID == userID
}

// CanAccess reports whether userID is the owner of this secret.
// Non-owner access via share records must be checked through the storage interface
// (e.g. storage.Storage.GetSharesForSecret), not this method.
func (s *SecretNode) CanAccess(userID uint) bool {
	return s.IsOwner(userID)
}

// CanWrite reports whether userID may write to this secret.
// At the model layer this is equivalent to ownership; write vs. read permission
// for shared access is determined by the ShareRecord.Permission field.
func (s *SecretNode) CanWrite(userID uint) bool {
	return s.CanAccess(userID)
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
