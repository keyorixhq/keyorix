package core

// storage_read_class_lease_test.go — STORAGE-ERR-CLASS-1 item 3.
//
// RevokeLease read the lease and its config with "lease not found" / "config not
// found" on ANY error. During an outage the operator was told the lease was already
// gone while the issued database credential was still live. A fault is now
// ErrStorageReadUnavailable, the target is not touched, the lease stays active, and
// the same revoke retried after the fault clears drops the credential.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestStorageReadClass_RevokeLease(t *testing.T) {
	for _, method := range []string{"GetDynamicSecretLease", "GetDynamicSecretConfig"} {
		t.Run(method, func(t *testing.T) {
			base, _, fake, _ := newDynamicTestCore(t)
			ctx := context.Background()
			cfg := mkConfig(t, base, ctx)
			issued, err := base.IssueLease(ctx, cfg.ID, 0, 7)
			require.NoError(t, err)

			faulty := faultstorage.NewFaultyStorage(base.storage, nil)
			c := &KeyorixCore{storage: faulty, now: base.now, passwordPolicy: DefaultPasswordPolicy()}
			c.SetAuthEncryptor(base.authEncryptor)
			c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

			srcFault(faulty, method)
			err = c.RevokeLease(ctx, issued.LeaseID, 7, "outage")
			require.True(t, faulty.Fired(), "the read must be reached")
			requireReadFault(t, err)
			assert.Empty(t, fake.Revoked, "the target credential was not dropped")
			lease, gerr := base.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
			require.NoError(t, gerr)
			assert.Equal(t, "active", lease.Status, "the lease is still active: the revoke was never applied")

			faulty.Arm(nil)
			require.NoError(t, c.RevokeLease(ctx, issued.LeaseID, 7, "retry"), "the retried revoke succeeds")
			lease, gerr = base.storage.GetDynamicSecretLease(ctx, issued.LeaseID)
			require.NoError(t, gerr)
			assert.Equal(t, "revoked", lease.Status)
			assert.Contains(t, fake.Revoked, issued.Username)
		})
	}

	t.Run("true not-found stays lease not found", func(t *testing.T) {
		c, _, _, _ := newDynamicTestCore(t)
		err := c.RevokeLease(context.Background(), "no-such-lease", 7, "x")
		require.Error(t, err)
		assert.False(t, IsStorageReadUnavailable(err))
		assert.Equal(t, "lease not found", err.Error())
	})
}
