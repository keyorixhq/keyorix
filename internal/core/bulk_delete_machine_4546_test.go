package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// bulkDeleteMachineWorld is one project with two environments, one secret in each,
// and a machine identity of that project holding project_developer (which bundles
// secrets.delete) at scope.
type bulkDeleteMachineWorld struct {
	c                *KeyorixCore
	st               *store.LocalStorage
	projectID        uint
	devSecret        uint
	prodSecret       uint
	machineID        uint
	machineCtx       context.Context
	ctxWithoutTarget context.Context
}

func newBulkDeleteMachineWorld(t *testing.T, scopeEnv func(dev, prod uint) uint) bulkDeleteMachineWorld {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	p, err := st.CreateProject(ctx, &models.Project{Name: "bulk-delete-machine"})
	require.NoError(t, err)
	envID := map[string]uint{}
	secret := map[string]uint{}
	for _, name := range []string{"dev-4546", "prod-4546"} {
		env, err := st.CreateEnvironment(ctx, &models.Environment{Name: name, ProjectID: p.ID})
		require.NoError(t, err)
		envID[name] = env.ID
		s, err := st.CreateSecret(ctx, &models.SecretNode{
			Name: "db-password-" + name, ProjectID: p.ID, EnvironmentID: env.ID,
			Type: "password", IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		secret[name] = s.ID
	}
	m, err := c.CreateMachineIdentity(ctx, p.ID, "ci-deployer", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, m.ID, role.ID,
		storage.Scope{ProjectID: p.ID, EnvironmentID: scopeEnv(envID["dev-4546"], envID["prod-4546"])}))
	// Tagged as the auth middleware tags a machine-token request (auth.go).
	machineTagged := WithActorType(ctx, ActorTypeMachine)
	return bulkDeleteMachineWorld{
		c: c, st: st, projectID: p.ID,
		devSecret: secret["dev-4546"], prodSecret: secret["prod-4546"],
		machineID:        m.ID,
		machineCtx:       WithMachineActor(machineTagged, m.ID),
		ctxWithoutTarget: machineTagged,
	}
}

func (w bulkDeleteMachineWorld) secretExists(t *testing.T, id uint) bool {
	t.Helper()
	_, err := w.st.GetSecret(context.Background(), id)
	if err == nil {
		return true
	}
	require.True(t, isPositiveNotFound(err), "unexpected read error: %v", err)
	return false
}

// TestBulkDeleteSecrets_MachineRefusedPerSecretOutsideItsScope (#4546, L3 of
// REVIEW-4522-DEEP-1): a machine token reaches BulkDeleteSecrets with actorID 0. It
// used to take the bare local-caller branch, so any secret of the project was
// deleted whatever the machine held. It now gets the rule the singular DELETE route
// applies to a machine: secrets.delete at the secret's own scope. A machine holding
// project_developer in dev only deletes the dev secret; the prod secret is refused
// as "secret not found" (no name) and survives.
func TestBulkDeleteSecrets_MachineRefusedPerSecretOutsideItsScope(t *testing.T) {
	t.Parallel()
	w := newBulkDeleteMachineWorld(t, func(dev, _ uint) uint { return dev })

	res, err := w.c.BulkDeleteSecrets(w.machineCtx, BulkDeleteRequest{SecretIDs: []uint{w.devSecret, w.prodSecret}},
		w.projectID, fmt.Sprintf("machine:%d", w.machineID), 0, "127.0.0.1", "test")
	require.NoError(t, err)
	assert.Equal(t, []uint{w.devSecret}, res.Deleted)
	require.Len(t, res.Failed, 1)
	assert.Equal(t, w.prodSecret, res.Failed[0].SecretID)
	assert.Equal(t, "secret not found", res.Failed[0].Error)
	assert.Empty(t, res.Failed[0].Name, "a refused secret's name is not disclosed")
	assert.False(t, w.secretExists(t, w.devSecret), "the in-scope secret is deleted")
	assert.True(t, w.secretExists(t, w.prodSecret), "the out-of-scope secret must survive")
}

// TestBulkDeleteSecrets_MachineWithProjectRoleDeletesAll is the positive control: a
// machine holding secrets.delete for the whole project (what the route's
// secrets.delete@project gate requires) still deletes every secret of it.
func TestBulkDeleteSecrets_MachineWithProjectRoleDeletesAll(t *testing.T) {
	t.Parallel()
	w := newBulkDeleteMachineWorld(t, func(_, _ uint) uint { return 0 })

	res, err := w.c.BulkDeleteSecrets(w.machineCtx, BulkDeleteRequest{SecretIDs: []uint{w.devSecret, w.prodSecret}},
		w.projectID, fmt.Sprintf("machine:%d", w.machineID), 0, "127.0.0.1", "test")
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{w.devSecret, w.prodSecret}, res.Deleted)
	assert.Empty(t, res.Failed)
}

// TestBulkDeleteSecrets_MachineTagWithoutIdentityFailsClosed: a context tagged as a
// machine but naming no machine identity has no principal to authorize, so every
// item is refused and nothing is deleted.
func TestBulkDeleteSecrets_MachineTagWithoutIdentityFailsClosed(t *testing.T) {
	t.Parallel()
	w := newBulkDeleteMachineWorld(t, func(_, _ uint) uint { return 0 })

	res, err := w.c.BulkDeleteSecrets(w.ctxWithoutTarget, BulkDeleteRequest{SecretIDs: []uint{w.devSecret, w.prodSecret}},
		w.projectID, "machine:?", 0, "127.0.0.1", "test")
	require.NoError(t, err)
	assert.Empty(t, res.Deleted)
	require.Len(t, res.Failed, 2)
	assert.True(t, w.secretExists(t, w.devSecret))
	assert.True(t, w.secretExists(t, w.prodSecret))
}

// TestBulkDeleteSecrets_LocalCallerStillDeletes: the in-process caller with no
// authenticated principal (actorID 0, no machine tag: embedded/local mode) keeps the
// bare delete, with only the project match.
func TestBulkDeleteSecrets_LocalCallerStillDeletes(t *testing.T) {
	t.Parallel()
	w := newBulkDeleteMachineWorld(t, func(dev, _ uint) uint { return dev })

	res, err := w.c.BulkDeleteSecrets(context.Background(), BulkDeleteRequest{SecretIDs: []uint{w.devSecret, w.prodSecret}},
		w.projectID, "local", 0, "", "")
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{w.devSecret, w.prodSecret}, res.Deleted)
	assert.Empty(t, res.Failed)
}

// TestBulkDeleteSecrets_MachineAuthorizationFaultFailsClosed: a failed read of the
// machine's roles is not a pass. The first item's lookup faults and that item is
// refused and survives; the second item, whose lookup succeeds, is deleted.
func TestBulkDeleteSecrets_MachineAuthorizationFaultFailsClosed(t *testing.T) {
	t.Parallel()
	w := newBulkDeleteMachineWorld(t, func(_, _ uint) uint { return 0 })
	faulty := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{
		Method: "ResolveMachinePermissionAt", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("connection reset"),
	})
	c := NewKeyorixCore(faulty)

	res, err := c.BulkDeleteSecrets(w.machineCtx, BulkDeleteRequest{SecretIDs: []uint{w.prodSecret, w.devSecret}},
		w.projectID, fmt.Sprintf("machine:%d", w.machineID), 0, "127.0.0.1", "test")
	require.NoError(t, err)
	assert.Equal(t, []uint{w.devSecret}, res.Deleted)
	require.Len(t, res.Failed, 1)
	assert.Equal(t, w.prodSecret, res.Failed[0].SecretID)
	assert.True(t, w.secretExists(t, w.prodSecret), "a secret whose authorization could not be read must survive")
}
