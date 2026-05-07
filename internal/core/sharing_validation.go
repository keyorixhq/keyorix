// sharing_validation.go — Request validation helpers used by sharing.go.
package core

import "fmt"

func (c *KeyorixCore) validateShareSecretRequest(req *ShareSecretRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.SecretID == 0 {
		return fmt.Errorf("secret ID is required")
	}
	if req.RecipientID == 0 {
		return fmt.Errorf("recipient ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.SharedBy == 0 {
		return fmt.Errorf("sharedBy is required")
	}
	return nil
}

func (c *KeyorixCore) validateUpdateShareRequest(req *UpdateShareRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.ShareID == 0 {
		return fmt.Errorf("share ID is required")
	}
	if req.Permission != "read" && req.Permission != "write" {
		return fmt.Errorf("invalid permission: %s (must be 'read' or 'write')", req.Permission)
	}
	if req.UpdatedBy == 0 {
		return fmt.Errorf("updatedBy is required")
	}
	return nil
}
