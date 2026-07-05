// auth_encryption_rotate.go — RotateAuthEncryption, delegating to the real DEK rotation.
//
// For encrypt/decrypt see auth_encryption.go. For DB store/retrieve see auth_encryption_store.go.
package encryption

import "fmt"

// RotateAuthEncryption performs a true DEK rotation (ADR-010): a new DEK is generated and
// every DEK-encrypted row — including API client secrets, session tokens, API tokens,
// password reset tokens, secret versions, MFA secrets, and dynamic-secret configs/leases —
// is re-encrypted under it in one atomic sweep, delegating to Service.RotateDEKWithSweep
// (internal/encryption/service_rotation.go → sweep.go's SweepAllTables). That sweep already
// runs inside a single DB transaction, committed only if every row rotates cleanly, so a
// mid-loop failure can never leave a permanent partial-rotation state — and it covers every
// DEK-encrypted table, not just the auth-specific ones a narrower hand-rolled rotator would.
//
// #197: this previously unwrapped the EXISTING on-disk DEK and re-encrypted rows under that
// SAME unchanged key — no new key material was ever generated, despite the command's help
// text and success message claiming otherwise. passphrase is forwarded to the key manager
// for KEK derivation to re-wrap the new DEK — never stored.
func (ae *AuthEncryption) RotateAuthEncryption(passphrase string) error {
	if !ae.service.IsEnabled() {
		return fmt.Errorf("encryption is disabled")
	}
	if _, err := ae.service.RotateDEKWithSweep(passphrase, ae.db); err != nil {
		return fmt.Errorf("failed to rotate auth encryption keys: %w", err)
	}
	return nil
}
