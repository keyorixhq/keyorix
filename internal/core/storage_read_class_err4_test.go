package core

// storage_read_class_err4_test.go — STORAGE-ERR-CLASS-4 item 4 (handler pre-check sweep).
//
// Core wrappers that turned ANY read error into "<thing> not found" (GetSecret, the parent
// folder read of CreateFolder, RequestProjectAccess's project read, RemoveSelfFromShare's
// secret read, MigrateUserToMachine's user read) made the REST handlers that text-match
// "not found" answer a storage fault 404. A fault is ErrStorageReadUnavailable now; a true
// miss keeps its not-found error.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestStorageReadClass_SweepWrappers(t *testing.T) {
	w := newC4World(t, "sqlite")
	ctx := context.Background()
	faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
	c := NewKeyorixCore(faulty)
	p := w.project()
	e := w.env(p.ID)
	u := w.user()
	missing := uint(987654)

	cases := []struct {
		name, method string
		call         func() error
	}{
		{"GetSecret", "GetSecret", func() error { _, err := c.GetSecret(ctx, missing); return err }},
		{"CreateFolder parent", "GetSecret", func() error {
			_, err := c.CreateFolder(ctx, u.ID, "f", p.ID, e.ID, &missing)
			return err
		}},
		{"RequestProjectAccess", "GetProject", func() error {
			_, err := c.RequestProjectAccess(ctx, missing, u.ID, "", "need it")
			return err
		}},
		{"MigrateUserToMachine", "GetUserByUsername", func() error {
			_, err := c.MigrateUserToMachine(ctx, "no-such-user", p.ID, "service", "m", u.ID, 0, false)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			faulty.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			err := tc.call()
			require.True(t, faulty.Fired(), "%s must be reached", tc.method)
			faulty.Arm(nil)
			requireReadFault(t, err)

			err = tc.call()
			require.Error(t, err)
			assert.False(t, IsStorageReadUnavailable(err), "a true miss is not a storage fault: %v", err)
		})
	}
}
