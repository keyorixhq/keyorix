package core

// typed_not_found_machine_dynamic_test.go — ERR-CLASS-LEFTOVERS-1 item 1 and 2.
//
// The gRPC mappers mapMachineError, mapDynamicError and mapUserError used to classify
// core's refusals by words in err.Error(). Core now types them: a machine identity or
// token that is absent is ErrMachineIdentityNotFound, an absent dynamic-secret config,
// lease, project or environment is ErrDynamicSecretNotFound, a field-validation refusal
// is ErrValidation. Per site, a storage read FAULT is none of these: it is
// ErrStorageReadUnavailable (the transport answers 503 / Unavailable) and a true
// not-found keeps its sentinel (404 / NotFound).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// requireFaultNotSentinel asserts err is a storage read fault and matches none of the
// not-found / validation sentinels a transport would map to 404 or 400.
func requireFaultNotSentinel(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	requireReadFault(t, err)
	for _, s := range sentinels {
		assert.NotErrorIs(t, err, s, "a fault must not match %v", s)
	}
}

func TestTypedNotFound_MachineIdentityFamily(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			p := w.project()
			other := w.project()
			m, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name("typed"), MachineTypeService, "", "", 0, 0)
			require.NoError(t, err)

			t.Run("machineInProject: true not-found and cross-project are the sentinel", func(t *testing.T) {
				_, errGone := w.core.ListMachineTokens(ctx, p.ID, 9_999_999)
				_, errCross := w.core.ListMachineTokens(ctx, other.ID, m.ID)
				assert.ErrorIs(t, errGone, ErrMachineIdentityNotFound)
				assert.ErrorIs(t, errCross, ErrMachineIdentityNotFound)
				assert.False(t, IsStorageReadUnavailable(errGone))
				assert.Equal(t, errGone.Error(), errCross.Error(), "text unchanged: still no existence oracle")
			})

			t.Run("machineInProject: a storage fault is the retry class, not a 404", func(t *testing.T) {
				srcFault(faulty, "GetMachineIdentity")
				_, err := c.ListMachineTokens(ctx, p.ID, m.ID)
				require.True(t, faulty.Fired())
				requireFaultNotSentinel(t, err, ErrMachineIdentityNotFound)
			})

			t.Run("transition: lock read fault vs absent machine", func(t *testing.T) {
				srcFault(faulty, "LockMachineIdentityForUpdate")
				_, err := c.TransitionMachineIdentity(ctx, p.ID, m.ID, MachineSuspended, 1)
				require.True(t, faulty.Fired())
				requireFaultNotSentinel(t, err, ErrMachineIdentityNotFound, ErrMachineTransitionInvalid)

				_, err = w.core.TransitionMachineIdentity(ctx, p.ID, 9_999_999, MachineSuspended, 1)
				assert.ErrorIs(t, err, ErrMachineIdentityNotFound)
			})

			t.Run("token read: fault vs absent credential", func(t *testing.T) {
				srcFault(faulty, "GetMachineIdentityCredentialByID")
				_, err := c.RevokeMachineToken(ctx, p.ID, m.ID, 1, 1)
				require.True(t, faulty.Fired())
				requireFaultNotSentinel(t, err, ErrMachineIdentityNotFound)

				_, err = w.core.RevokeMachineToken(ctx, p.ID, m.ID, 9_999_999, 1)
				assert.ErrorIs(t, err, ErrMachineIdentityNotFound)
			})

			t.Run("replace_credential_id: fault vs absent credential", func(t *testing.T) {
				srcFault(faulty, "GetMachineIdentityCredentialByID")
				_, err := c.validateReplacementCredential(ctx, m.ID, 1)
				require.True(t, faulty.Fired())
				requireFaultNotSentinel(t, err, ErrMachineIdentityNotFound)

				_, err = w.core.validateReplacementCredential(ctx, m.ID, 9_999_999)
				assert.ErrorIs(t, err, ErrMachineIdentityNotFound)
			})

			t.Run("state refusals and validation", func(t *testing.T) {
				_, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name("bad"), "no-such-type", "", "", 0, 0)
				assert.ErrorIs(t, err, ErrValidation)
				_, err = w.core.CreateMachineIdentity(ctx, p.ID, "", MachineTypeService, "", "", 0, 0)
				assert.ErrorIs(t, err, ErrValidation)
				_, err = w.core.ClassifyMachineIdentity(ctx, p.ID, m.ID, "not-a-level", 1)
				assert.ErrorIs(t, err, ErrValidation)

				s, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name("susp"), MachineTypeService, "", "", 0, 0)
				require.NoError(t, err)
				_, err = w.core.TransitionMachineIdentity(ctx, p.ID, s.ID, MachineSuspended, 1)
				require.NoError(t, err)
				_, err = w.core.IssueMachineToken(ctx, p.ID, s.ID, 1, ActorTypeUser, 1, IssueMachineTokenParams{Name: "x"})
				assert.ErrorIs(t, err, ErrMachineIdentityNotActive)

				r, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name("rev"), MachineTypeService, "", "", 0, 0)
				require.NoError(t, err)
				_, err = w.core.TransitionMachineIdentity(ctx, p.ID, r.ID, MachineRevoked, 1)
				require.NoError(t, err)
				_, err = w.core.TransitionMachineIdentity(ctx, p.ID, r.ID, MachineActive, 1)
				assert.ErrorIs(t, err, ErrMachineTransitionInvalid)
				assert.NotErrorIs(t, err, ErrMachineIdentityNotFound)
			})
		})
	}
}

func TestTypedNotFound_DynamicSecretFamily(t *testing.T) {
	base, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, base, ctx)
	issued, err := base.IssueLease(ctx, cfg.ID, 0, 7)
	require.NoError(t, err)

	faulty := faultstorage.NewFaultyStorage(base.storage, nil)
	c := &KeyorixCore{storage: faulty, now: base.now, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(base.authEncryptor)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	sites := []struct {
		name   string
		method string // the storage read that is faulted
		call   func(c *KeyorixCore, absent bool) error
	}{
		{"ClassifyDynamicSecretConfig", "GetDynamicSecretConfig", func(c *KeyorixCore, absent bool) error {
			id := cfg.ID
			if absent {
				id = 9_999_999
			}
			_, err := c.ClassifyDynamicSecretConfig(ctx, testAdminActorID, id, "internal")
			return err
		}},
		{"SetDynamicSecretConfigEnabled", "GetDynamicSecretConfig", func(c *KeyorixCore, absent bool) error {
			id := cfg.ID
			if absent {
				id = 9_999_999
			}
			_, err := c.SetDynamicSecretConfigEnabled(ctx, testAdminActorID, id, false)
			return err
		}},
		{"IssueLease", "GetDynamicSecretConfig", func(c *KeyorixCore, absent bool) error {
			id := cfg.ID
			if absent {
				id = 9_999_999
			}
			_, err := c.IssueLease(ctx, id, 0, 7)
			return err
		}},
		{"RenewLease lease read", "GetDynamicSecretLease", func(c *KeyorixCore, absent bool) error {
			id := issued.LeaseID
			if absent {
				id = "no-such-lease"
			}
			_, err := c.RenewLease(ctx, id, 0, 7)
			return err
		}},
		{"RevokeLease lease read", "GetDynamicSecretLease", func(c *KeyorixCore, absent bool) error {
			id := issued.LeaseID
			if absent {
				id = "no-such-lease"
			}
			return c.RevokeLease(ctx, id, 7, "typed")
		}},
	}
	for _, s := range sites {
		t.Run(s.name+": fault is the retry class, not a 404", func(t *testing.T) {
			srcFault(faulty, s.method)
			err := s.call(c, false)
			require.True(t, faulty.Fired(), "the read must be reached")
			requireFaultNotSentinel(t, err, ErrDynamicSecretNotFound)
			faulty.Arm(nil)
		})
		t.Run(s.name+": a true not-found is the sentinel", func(t *testing.T) {
			err := s.call(base, true)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrDynamicSecretNotFound)
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}

	t.Run("renew: config read after a good lease read", func(t *testing.T) {
		srcFault(faulty, "GetDynamicSecretConfig")
		_, err := c.RenewLease(ctx, issued.LeaseID, 0, 7)
		require.True(t, faulty.Fired())
		requireFaultNotSentinel(t, err, ErrDynamicSecretNotFound)
		faulty.Arm(nil)
	})

	t.Run("create validation", func(t *testing.T) {
		for _, req := range []*CreateDynamicSecretConfigRequest{
			{},
			{Name: "n", ProjectID: 1, AdminDSN: "x", DefaultTTLSeconds: 10, MaxTTLSeconds: 5},
			{Name: "n", ProjectID: 1, AdminDSN: "x", Classification: "not-a-level"},
		} {
			assert.ErrorIs(t, validateCreateDynamicSecretConfigRequest(req), ErrValidation)
		}
		_, err := base.ClassifyDynamicSecretConfig(ctx, testAdminActorID, 0, "internal")
		assert.ErrorIs(t, err, ErrValidation)
	})
}
