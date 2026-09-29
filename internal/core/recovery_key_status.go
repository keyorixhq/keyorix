// recovery_key_status.go — read-only recovery-key configuration status for
// admin-facing surfaces (F6, recovery-key visibility). Never exposes the key
// itself or its hash — only whether one has been generated and which
// generation, mirroring what the startup WARN and `admin diagnose` already
// report.
package core

import "context"

// RecoveryKeyStatus is a read-only summary of the local admin recovery key's
// configuration state. Never carries the key or its hash.
type RecoveryKeyStatus struct {
	Configured bool `json:"configured"`
	Generation int  `json:"generation,omitempty"`
}

// GetRecoveryKeyStatus reports whether a recovery key has been generated on
// this install, and if so, its generation (rotation count).
func (c *KeyorixCore) GetRecoveryKeyStatus(ctx context.Context) (*RecoveryKeyStatus, error) {
	rec, found, err := c.storage.GetRecoveryKeyRecord(ctx)
	if err != nil {
		return nil, err
	}
	if !found {
		return &RecoveryKeyStatus{Configured: false}, nil
	}
	return &RecoveryKeyStatus{Configured: true, Generation: rec.KeyVersion}, nil
}
