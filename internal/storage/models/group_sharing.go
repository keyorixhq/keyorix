package models

import (
	"errors"
)

// ValidateGroupShare validates a share record for a group
func ValidateGroupShare(share *ShareRecord) error {
	// First, validate the basic share record
	if err := ValidateShareRecord(share); err != nil {
		return err
	}

	// Ensure it's marked as a group share
	if !share.IsGroup {
		return errors.New("share record must have IsGroup set to true for group sharing")
	}

	return nil
}

// IsGroupMember is a model-layer convenience stub; it always returns false.
// Production group membership checks must go through the storage interface
// (storage.Storage.IsGroupMember), which queries the database.
func IsGroupMember(userID, groupID uint) bool {
	return false
}

// GetGroupMembers is a model-layer convenience stub that validates the zero-ID
// guard and returns an empty slice. Production callers must use the storage interface.
func GetGroupMembers(groupID uint) ([]uint, error) {
	if groupID == 0 {
		return nil, errors.New("group ID cannot be zero")
	}
	return []uint{}, nil
}

// ValidateGroupExists is a model-layer convenience stub that validates the
// zero-ID guard only. Production callers must use the storage interface.
func ValidateGroupExists(groupID uint) error {
	if groupID == 0 {
		return errors.New("group ID cannot be zero")
	}
	return nil
}

// CanAccessViaGroup is a model-layer convenience stub that validates zero-ID
// guards and always returns false. Production callers must use the storage interface.
func CanAccessViaGroup(secretID, userID uint) (bool, string, error) {
	if secretID == 0 {
		return false, "", errors.New("secret ID cannot be zero")
	}
	if userID == 0 {
		return false, "", errors.New("user ID cannot be zero")
	}
	return false, "", nil
}

// GetUserGroups is a model-layer convenience stub that validates the zero-ID
// guard and returns an empty slice. Production callers must use the storage interface.
func GetUserGroups(userID uint) ([]uint, error) {
	if userID == 0 {
		return nil, errors.New("user ID cannot be zero")
	}
	return []uint{}, nil
}

// GetGroupShares is a model-layer convenience stub that validates the zero-ID
// guard and returns an empty slice. Production callers must use the storage interface.
func GetGroupShares(groupID uint) ([]*ShareRecord, error) {
	if groupID == 0 {
		return nil, errors.New("group ID cannot be zero")
	}
	return []*ShareRecord{}, nil
}
