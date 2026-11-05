package core

// auth_lane_read_fault_test.go — AUTH-LANE-FOLDS-1 item 2.
//
// The MFA and WebAuthn account operations read the caller's own account first. They
// folded ANY GetUser error into "user not found", so a storage fault read like a
// deleted account (the handlers then answered 400 "user not found"). A faulted read
// must be the storage-read-unavailable class (503 over HTTP), a real not-found must
// stay a refusal, and the call is refused either way (fail closed).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestAuthLane_GetUserReadFault_IsUnavailableNotNotFound(t *testing.T) {
	t.Parallel()
	ops := []struct {
		name     string
		webauthn bool
		call     func(c *KeyorixCore, userID uint) error
	}{
		{"BeginMFAEnrollment", false, func(c *KeyorixCore, id uint) error {
			_, _, err := c.BeginMFAEnrollment(context.Background(), id)
			return err
		}},
		{"ActivateMFA", false, func(c *KeyorixCore, id uint) error {
			_, err := c.ActivateMFA(context.Background(), id, "123456", mfaTestPassword, "")
			return err
		}},
		{"DisableMFA", false, func(c *KeyorixCore, id uint) error {
			return c.DisableMFA(context.Background(), id, mfaTestPassword, "")
		}},
		{"RegenerateMFARecoveryCodes", false, func(c *KeyorixCore, id uint) error {
			_, err := c.RegenerateMFARecoveryCodes(context.Background(), id, mfaTestPassword)
			return err
		}},
		{"MFARecoveryCodesRemaining", false, func(c *KeyorixCore, id uint) error {
			_, _, err := c.MFARecoveryCodesRemaining(context.Background(), id)
			return err
		}},
		{"FinishWebAuthnRegistration", true, func(c *KeyorixCore, id uint) error {
			_, err := c.FinishWebAuthnRegistration(context.Background(), id, "sess", "key", webauthnTestPassword, nil)
			return err
		}},
		{"DeleteWebAuthnCredential", true, func(c *KeyorixCore, id uint) error {
			return c.DeleteWebAuthnCredential(context.Background(), id, 1, webauthnTestPassword)
		}},
		{"FinishWebAuthnReauth", true, func(c *KeyorixCore, id uint) error {
			return c.FinishWebAuthnReauth(context.Background(), id, "sess", nil)
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			build := func() (*KeyorixCore, *faultstorage.FaultyStorage) {
				var c *KeyorixCore
				if op.webauthn {
					c, _ = newWebAuthnTestCore(t, true)
				} else {
					c, _, _ = newMFATestCore(t)
				}
				faulty := faultstorage.NewFaultyStorage(c.storage, nil)
				c.storage = faulty
				return c, faulty
			}

			t.Run("fault", func(t *testing.T) {
				c, faulty := build()
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				err := op.call(c, 1)
				require.True(t, faulty.Fired(), "the GetUser fault must be reached")
				require.Error(t, err, "a faulted account read must refuse (fail closed)")
				assert.True(t, IsStorageReadUnavailable(err), "want the storage-read-unavailable class, got %v", err)
				assert.NotContains(t, err.Error(), "not found", "a fault must not read as a deleted account")
				assert.NotContains(t, err.Error(), assert.AnError.Error(), "the driver text stays out of the caller-visible error")
			})

			t.Run("not found stays a refusal", func(t *testing.T) {
				c, _ := build()
				err := op.call(c, 999)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err), "a positive not-found is a verdict, got %v", err)
				assert.Contains(t, err.Error(), "user not found")
			})
		})
	}
}
