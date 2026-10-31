package core

// storage_read_class_behaviour_test.go — STORAGE-ERR-CLASS-1 red/green proof.
//
// The sentinel tests (storage_read_class_*_test.go) name symbols that do not exist
// before the fix, so against the pre-fix commit they fail to compile: a red, but a
// weak one. This file uses only symbols that exist on both sides, so against the
// pre-fix commit it fails on its ASSERTIONS: during a read fault the revoke must not
// answer "not found", and the driver cause must stay reachable for the log.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStorageReadFaultIsNotReportedAsNotFound_Behaviour(t *testing.T) {
	w := newC4World(t, "sqlite")
	ctx := context.Background()
	faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
	c := NewKeyorixCore(faulty)
	p := w.project()
	admin := w.user()
	require.NoError(t, w.core.storage.AssignRole(ctx, admin.ID, w.role(true).ID, Scope{ProjectID: p.ID}))

	m, err := w.core.CreateMachineIdentity(ctx, p.ID, w.name("beh"), MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	cred := &models.MachineIdentityCredential{MachineIdentityID: m.ID, Name: "c", TokenHash: sha256Hex(w.name("beh-tok")), TokenPrefix: "kx_m"}
	require.NoError(t, w.db.Create(cred).Error)
	membership := &models.ProjectMembership{ProjectID: p.ID, UserID: w.user().ID, Role: "viewer", State: MembershipInvited, InvitedAt: time.Now()}
	require.NoError(t, w.db.Create(membership).Error)
	inv := &models.ProjectInvitation{ProjectID: p.ID, Email: w.name("beh") + "@example.com", Role: "viewer", State: InvitationPending, InvitedBy: admin.ID, CreatedAt: time.Now()}
	require.NoError(t, w.db.Create(inv).Error)

	cases := []struct {
		name, fault string
		call        func() error
	}{
		{"revoke machine identity", "LockMachineIdentityForUpdate", func() error {
			_, e := c.TransitionMachineIdentity(ctx, p.ID, m.ID, MachineRevoked, admin.ID)
			return e
		}},
		{"project-scoped machine lookup", "GetMachineIdentity", func() error {
			_, e := c.ListMachineTokens(ctx, p.ID, m.ID)
			return e
		}},
		{"revoke machine token", "GetMachineIdentityCredentialByID", func() error {
			_, e := c.RevokeMachineToken(ctx, p.ID, m.ID, cred.ID, admin.ID)
			return e
		}},
		{"revoke membership", "GetProjectMembership", func() error {
			_, e := c.TransitionMembership(ctx, p.ID, membership.ID, MembershipRevoked, admin.ID, false)
			return e
		}},
		{"revoke invitation", "GetProjectInvitation", func() error {
			return c.RevokeInvitation(ctx, p.ID, inv.ID, admin.ID)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.fault, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			err := tc.call()
			require.True(t, faulty.Fired(), "the read fault must be reached")
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "not found", "a storage fault must not read as not-found")
			assert.ErrorIs(t, err, assert.AnError, "the cause must stay reachable for the log")
			faulty.Arm(nil)
		})
	}
}
