package models

import (
	"errors"
	"fmt"
	"time"
)

// ValidateShareRecord validates a ShareRecord before creating or updating it
func ValidateShareRecord(share *ShareRecord) error {
	if share == nil {
		return errors.New("share record cannot be nil")
	}

	if share.SecretID == 0 {
		return errors.New("secret ID is required")
	}

	if share.OwnerID == 0 {
		return errors.New("owner ID is required")
	}

	if share.RecipientID == 0 {
		return errors.New("recipient ID is required")
	}

	// Set default values if not provided
	if share.Permission == "" {
		share.Permission = "read"
	}

	if share.Permission != "read" && share.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", share.Permission)
	}

	if share.CreatedAt.IsZero() {
		share.CreatedAt = time.Now()
	}

	if share.UpdatedAt.IsZero() {
		share.UpdatedAt = time.Now()
	}

	return nil
}

// ValidateShareUpdate validates a ShareRecord before updating it
func ValidateShareUpdate(share *ShareRecord) error {
	if share == nil {
		return errors.New("share record cannot be nil")
	}

	if share.ID == 0 {
		return errors.New("share ID is required for updates")
	}

	if share.Permission != "read" && share.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", share.Permission)
	}

	// Always update the UpdatedAt timestamp
	share.UpdatedAt = time.Now()

	return nil
}
