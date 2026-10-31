package core

// storage_read_class_machine_test.go — STORAGE-ERR-CLASS-1 item 1.
//
// The machine-identity family folded ANY storage read error into "... not found":
// during a database outage, revoking a machine identity, one of its tokens or an
// OIDC binding answered "not found" (HTTP 404, gRPC NotFound) and the operator
// believed the principal was already gone while the revoke was never applied.
//
// Per site: a read fault is ErrStorageReadUnavailable (matched with errors.Is,
// never by text), the row is untouched, and the SAME revoke retried after the
// fault clears succeeds. A true not-found and a cross-project mismatch stay one
// identical "not found" answer (no existence oracle).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func srcFault(f *faultstorage.FaultyStorage, method string) {
	f.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
}

// requireReadFault asserts err is the storage-fault class and NOT a not-found.
func requireReadFault(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, IsStorageReadUnavailable(err), "a storage read fault must be ErrStorageReadUnavailable, got: %v", err)
	assert.NotContains(t, err.Error(), "not found", "a fault must not read as not-found")
	assert.ErrorIs(t, err, assert.AnError, "the cause stays reachable for the server log")
}

func TestStorageReadClass_MachineIdentityFamily(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			other := w.project()

			mint := func(name string) (*models.MachineIdentity, *models.MachineIdentityCredential) {
				m, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name(name), MachineTypeService, "", "", 0, 0)
				require.NoError(t, err)
				raw := machineTokenPrefix + w.name("src-token-"+name)
				cred := &models.MachineIdentityCredential{
					MachineIdentityID: m.ID, Name: name, TokenHash: sha256Hex(raw), TokenPrefix: raw[:len(machineTokenPrefix)+4],
				}
				require.NoError(t, w.db.Create(cred).Error)
				return m, cred
			}
			state := func(id uint) string {
				var m models.MachineIdentity
				require.NoError(t, w.db.First(&m, id).Error)
				return m.State
			}

			t.Run("machineInProject read fault is not a not-found", func(t *testing.T) {
				m, _ := mint("mip")
				srcFault(faulty, "GetMachineIdentity")
				_, err := c.ListMachineTokens(ctx, p.ID, m.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				faulty.Arm(nil)
				_, err = c.ListMachineTokens(ctx, p.ID, m.ID)
				require.NoError(t, err, "the same call succeeds once the fault clears")
			})

			t.Run("true not-found and cross-project mismatch are one identical answer", func(t *testing.T) {
				m, _ := mint("oracle")
				_, errGone := w.core.ListMachineTokens(ctx, p.ID, 9_999_999)
				_, errCross := w.core.ListMachineTokens(ctx, other.ID, m.ID)
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error(), "no existence oracle between absent and foreign")
				assert.Contains(t, errGone.Error(), "not found")
				assert.False(t, IsStorageReadUnavailable(errGone))
				assert.False(t, IsStorageReadUnavailable(errCross))
			})

			t.Run("revoke identity: lock read fault leaves it active and the retry revokes", func(t *testing.T) {
				m, _ := mint("revoke-id")
				srcFault(faulty, "LockMachineIdentityForUpdate")
				_, err := c.TransitionMachineIdentity(ctx, p.ID, m.ID, MachineRevoked, 1)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				assert.Equal(t, MachineActive, state(m.ID), "the revoke was never applied")
				faulty.Arm(nil)
				_, err = c.TransitionMachineIdentity(ctx, p.ID, m.ID, MachineRevoked, 1)
				require.NoError(t, err)
				assert.Equal(t, MachineRevoked, state(m.ID))
			})

			t.Run("revoke identity: true not-found stays not-found", func(t *testing.T) {
				_, err := c.TransitionMachineIdentity(ctx, p.ID, 9_999_999, MachineRevoked, 1)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "machine identity not found")
			})

			t.Run("revoke token: credential read fault is retryable", func(t *testing.T) {
				m, cred := mint("revoke-token")
				srcFault(faulty, "GetMachineIdentityCredentialByID")
				_, err := c.RevokeMachineToken(ctx, p.ID, m.ID, cred.ID, 1)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var row models.MachineIdentityCredential
				require.NoError(t, w.db.First(&row, cred.ID).Error)
				assert.False(t, row.Revoked, "the token was never revoked")
				faulty.Arm(nil)
				_, err = c.RevokeMachineToken(ctx, p.ID, m.ID, cred.ID, 1)
				require.NoError(t, err)
				require.NoError(t, w.db.First(&row, cred.ID).Error)
				assert.True(t, row.Revoked)
			})

			t.Run("revoke token: absent and foreign credential stay not-found", func(t *testing.T) {
				m, _ := mint("tok-a")
				_, otherCred := mint("tok-b")
				_, errGone := c.RevokeMachineToken(ctx, p.ID, m.ID, 9_999_999, 1)
				_, errCross := c.RevokeMachineToken(ctx, p.ID, m.ID, otherCred.ID, 1)
				require.Error(t, errGone)
				require.Error(t, errCross)
				assert.Equal(t, errGone.Error(), errCross.Error())
				assert.Contains(t, errGone.Error(), "token not found")
				assert.False(t, IsStorageReadUnavailable(errGone))
			})

			t.Run("classify token: credential read fault", func(t *testing.T) {
				m, cred := mint("classify-token")
				srcFault(faulty, "GetMachineIdentityCredentialByID")
				_, err := c.ClassifyMachineToken(ctx, p.ID, m.ID, cred.ID, "internal", 1)
				requireReadFault(t, err)
			})

			t.Run("delete OIDC binding: binding read fault is retryable", func(t *testing.T) {
				m, _ := mint("oidc")
				b := &models.MachineIdentityOIDCBinding{MachineIdentityID: m.ID}
				require.NoError(t, w.db.Create(b).Error)
				srcFault(faulty, "GetOIDCBindingByID")
				err := c.DeleteOIDCBinding(ctx, p.ID, m.ID, b.ID, 1)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var n int64
				require.NoError(t, w.db.Model(&models.MachineIdentityOIDCBinding{}).Where("id = ?", b.ID).Count(&n).Error)
				assert.EqualValues(t, 1, n, "the binding was never deleted")
				faulty.Arm(nil)
				require.NoError(t, c.DeleteOIDCBinding(ctx, p.ID, m.ID, b.ID, 1))
			})

			t.Run("delete OIDC binding: absent binding stays not-found", func(t *testing.T) {
				m, _ := mint("oidc-gone")
				err := c.DeleteOIDCBinding(ctx, p.ID, m.ID, 9_999_999, 1)
				require.Error(t, err)
				assert.False(t, IsStorageReadUnavailable(err))
				assert.Contains(t, err.Error(), "binding not found")
			})
		})
	}
}
