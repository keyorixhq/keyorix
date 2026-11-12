package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #4025: requireEqualOrGreaterAdminAuthority read the target's scopes
// (GetUserRoleScopes) and then the role set at each scope with separate reads.
// A grant moved between those reads by another administrator (one commit:
// remove at project A, add at project B) left the check looking at A and
// finding nothing there, so an actor who does not outrank the target passed.

// ceilingSnapshotFixture: actor holds users.write globally (no admin role);
// target holds project_admin (an ADR-084 bypass role) at project A.
type ceilingSnapshotFixture struct {
	c              *KeyorixCore
	st             storage.Storage
	actor, target  uint
	projA, projB   uint
	projectAdminID uint
}

func newCeilingSnapshotFixture(t *testing.T, c *KeyorixCore, st storage.Storage) *ceilingSnapshotFixture {
	t.Helper()
	ctx := context.Background()
	f := &ceilingSnapshotFixture{c: c, st: st}
	a, err := st.CreateProject(ctx, &models.Project{Name: "ceiling-snapshot-a"})
	require.NoError(t, err)
	b, err := st.CreateProject(ctx, &models.Project{Name: "ceiling-snapshot-b"})
	require.NoError(t, err)
	f.projA, f.projB = a.ID, b.ID
	pa, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	f.projectAdminID = pa.ID

	writer := snapshotTestRole(t, st, "ceiling_snapshot_users_writer", "users.write")
	f.actor = snapshotTestUser(t, c, "ceiling-snapshot-actor")
	require.NoError(t, st.AssignRole(ctx, f.actor, writer, Scope{}))
	f.target = snapshotTestUser(t, c, "ceiling-snapshot-target")
	require.NoError(t, st.AssignRole(ctx, f.target, f.projectAdminID, Scope{ProjectID: f.projA}))
	return f
}

func snapshotTestUser(t *testing.T, c *KeyorixCore, name string) uint {
	t.Helper()
	u, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: name, Email: name + "@example.com", DisplayName: name,
		Password: "Tr1cky-Passphrase-For-Tests!",
	})
	require.NoError(t, err)
	return u.ID
}

func snapshotTestRole(t *testing.T, st storage.Storage, name string, permNames ...string) uint {
	t.Helper()
	ctx := context.Background()
	folded, err := identity.NewFoldedName(name)
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, folded, "test-only")
	require.NoError(t, err)
	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	found := 0
	for _, p := range perms {
		for _, want := range permNames {
			if p.Name == want {
				require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, p.ID))
				found++
			}
		}
	}
	require.Equal(t, len(permNames), found, "every permission of %s must exist", name)
	return role.ID
}

// moveOnScopeDiscovery wraps inner so that every GetUserRoleScopes read of
// targetID is followed, before it returns, by mover committing a move of the
// target's project_admin grant to the other project in ONE transaction. Every
// committed state holds the grant at exactly one of the two projects; the
// check runs in the window a concurrent administrator's move can land in.
func (f *ceilingSnapshotFixture) moveOnScopeDiscovery(t *testing.T, inner, mover storage.Storage, moves *int) storage.Storage {
	t.Helper()
	at := f.projA
	return hooked(inner, &storeHooks{
		GetUserRoleScopes: func(next storage.Storage, ctx context.Context, userID uint) ([]storage.Scope, error) {
			scopes, err := next.GetUserRoleScopes(ctx, userID)
			if err != nil || userID != f.target {
				return scopes, err
			}
			to := f.projB
			if at == f.projB {
				to = f.projA
			}
			require.NoError(t, mover.WithTransaction(ctx, func(tx storage.Storage) error {
				if err := tx.RemoveRole(ctx, f.target, f.projectAdminID, Scope{ProjectID: at}); err != nil {
					return err
				}
				return tx.AssignRole(ctx, f.target, f.projectAdminID, Scope{ProjectID: to})
			}))
			at = to
			*moves++
			return scopes, nil
		},
	})
}

func runCeilingSnapshotInterleaving(t *testing.T, c *KeyorixCore, st, mover storage.Storage) {
	ctx := context.Background()
	f := newCeilingSnapshotFixture(t, c, st)

	// Control: without a concurrent move the actor is refused.
	err := c.requireAdminRankCeilingForTarget(ctx, f.actor, f.target, "delete")
	require.ErrorIs(t, err, ErrInsufficientAdminAuthority)

	moves := 0
	raced := NewKeyorixCore(f.moveOnScopeDiscovery(t, st, mover, &moves))
	err = raced.requireAdminRankCeilingForTarget(ctx, f.actor, f.target, "delete")
	require.Equal(t, 1, moves, "the move must have landed inside the check")
	require.ErrorIs(t, err, ErrInsufficientAdminAuthority,
		"a grant moved during the check must still be seen: the target held project_admin in every committed state")
	require.False(t, errors.Is(err, errCeilingResolutionFailed))

	// End to end: the delete is refused and the target still exists.
	require.Error(t, raced.DeleteUser(ctx, f.actor, f.target))
	require.Equal(t, 2, moves)
	still, err := st.GetUser(ctx, f.target)
	require.NoError(t, err)
	require.Equal(t, f.target, still.ID)
}

// TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole is the #4025 regression
// (SQLite: the move commits on the same store between the check's reads).
func TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole(t *testing.T) {
	c, st := newBootstrappedCore(t)
	runCeilingSnapshotInterleaving(t, c, st, st)
}

// TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole_Postgres: the same, with the
// move committed through a second connection pool (another replica's
// administrator). Skips without KEYORIX_TEST_PG_DSN.
func TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole_Postgres(t *testing.T) {
	dsn := pgMigratedDatabaseDSN(t, pgTestDSN(t))
	st := store.NewLocalStorage(pgOpen(t, dsn))
	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	mover := store.NewLocalStorage(pgOpen(t, dsn))
	runCeilingSnapshotInterleaving(t, c, st, mover)
}

// legacyAdminAuthorityVerdict is requireEqualOrGreaterAdminAuthority as it was
// before #4025 (scope listing, then per-scope reads), kept as the reference the
// single-read version must agree with when nothing writes concurrently.
func legacyAdminAuthorityVerdict(ctx context.Context, c *KeyorixCore, actorID, targetID uint) error {
	scopes, err := c.storage.GetUserRoleScopes(ctx, targetID)
	if err != nil {
		return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
	}
	for _, scope := range scopes {
		targetRoleIDs, err := c.scopedRoleIDs(ctx, targetID, scope)
		if err != nil {
			return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
		}
		targetBypasses, err := c.roleSetContainsAdmin(ctx, targetRoleIDs)
		if err != nil {
			return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
		}
		if targetBypasses {
			actorRoleIDs, err := c.scopedRoleIDs(ctx, actorID, scope)
			if err != nil {
				return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
			}
			actorBypasses, err := c.roleSetContainsAdmin(ctx, actorRoleIDs)
			if err != nil {
				return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
			}
			if !actorBypasses {
				return errors.New("refused: administrator role")
			}
			continue
		}
		targetPerms := make(map[string]bool)
		for _, roleID := range targetRoleIDs {
			perms, err := c.rolePermissionNameSet(ctx, roleID)
			if err != nil {
				return fmt.Errorf("%w: %w", errCeilingResolutionFailed, err)
			}
			for p := range perms {
				targetPerms[p] = true
			}
		}
		for permName := range targetPerms {
			ok, aerr := c.Authorize(ctx, actorID, permName, scope)
			if aerr != nil {
				return fmt.Errorf("%w: %w", errCeilingResolutionFailed, aerr)
			}
			if !ok {
				return fmt.Errorf("refused: %s", permName)
			}
		}
	}
	return nil
}

// TestAdminRankCeiling_SnapshotVerdictUnchanged pins that #4025 changes no
// verdict for a caller without a concurrent write: over a table of target role
// shapes (none, global admin, project-scoped bypass, custom roles at global,
// project and environment scope, group-inherited and membership-scoped group
// grants, a grant on a deleted project) and actors (bootstrap admin, users.write
// only, project admin at either project, a custom-role peer, actor 0), the new
// check, the legacy reference and requireAdminRankCeilingForTarget agree on
// allow/refuse, and a refusal is never a resolution failure.
func TestAdminRankCeiling_SnapshotVerdictUnchanged(t *testing.T) {
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	f := newCeilingSnapshotFixture(t, c, st)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	globalAdmin, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	env, err := st.CreateEnvironment(ctx, &models.Environment{ProjectID: f.projA, Name: "ceiling-snapshot-env"})
	require.NoError(t, err)
	gone, err := st.CreateProject(ctx, &models.Project{Name: "ceiling-snapshot-gone"})
	require.NoError(t, err)

	secretsReader := snapshotTestRole(t, st, "ceiling_snapshot_secrets_reader", "secrets.read")
	usersAdmin := snapshotTestRole(t, st, "ceiling_snapshot_users_admin", "users.write", "users.delete")

	assign := func(user, role uint, scope Scope) {
		require.NoError(t, st.AssignRole(ctx, user, role, scope))
	}
	group := func(name string, member, memberProject, role uint, scope Scope) {
		g, err := st.CreateGroup(ctx, &models.Group{Name: name, NameFolded: name})
		require.NoError(t, err)
		require.NoError(t, st.AddUserToGroup(ctx, member, g.ID, memberProject))
		require.NoError(t, st.AssignRoleToGroup(ctx, g.ID, role, scope))
	}

	targets := map[string]uint{"project_admin@A": f.target}
	newTarget := func(name string, grant func(id uint)) {
		id := snapshotTestUser(t, c, fmt.Sprintf("ceiling-snapshot-t%d", len(targets)))
		if grant != nil {
			grant(id)
		}
		targets[name] = id
	}
	newTarget("no-roles", nil)
	newTarget("global-admin", func(id uint) { assign(id, globalAdmin.ID, Scope{}) })
	newTarget("users-admin-global", func(id uint) { assign(id, usersAdmin, Scope{}) })
	newTarget("secrets-reader@A", func(id uint) { assign(id, secretsReader, Scope{ProjectID: f.projA}) })
	newTarget("secrets-reader@A/env", func(id uint) {
		assign(id, secretsReader, Scope{ProjectID: f.projA, EnvironmentID: env.ID})
	})
	newTarget("group-project_admin@B", func(id uint) {
		group("ceiling-snapshot-g1", id, 0, f.projectAdminID, Scope{ProjectID: f.projB})
	})
	newTarget("group-global-users-admin-member@A", func(id uint) {
		group("ceiling-snapshot-g2", id, f.projA, usersAdmin, Scope{})
		assign(id, secretsReader, Scope{ProjectID: f.projA})
	})
	newTarget("users-admin@deleted-project", func(id uint) {
		assign(id, usersAdmin, Scope{ProjectID: gone.ID})
		assign(id, secretsReader, Scope{})
	})
	// The scope GetUserRoleScopes still lists for a grant on a deleted
	// environment is the only scope where the membership-scoped group grant
	// applies: dropping that listing (deriving scopes from the snapshot alone)
	// would allow the users.write-only actor here.
	goneEnv, err := st.CreateEnvironment(ctx, &models.Environment{ProjectID: f.projA, Name: "ceiling-snapshot-gone-env"})
	require.NoError(t, err)
	newTarget("group-member@A+grant@deleted-env", func(id uint) {
		group("ceiling-snapshot-g3", id, f.projA, usersAdmin, Scope{})
		assign(id, secretsReader, Scope{ProjectID: f.projA, EnvironmentID: goneEnv.ID})
	})
	require.NoError(t, st.DeleteProject(ctx, gone.ID))
	require.NoError(t, st.DeleteEnvironment(ctx, goneEnv.ID))

	projectAdminA := snapshotTestUser(t, c, "ceiling-snapshot-a-pa")
	assign(projectAdminA, f.projectAdminID, Scope{ProjectID: f.projA})
	projectAdminB := snapshotTestUser(t, c, "ceiling-snapshot-b-pa")
	assign(projectAdminB, f.projectAdminID, Scope{ProjectID: f.projB})
	peer := snapshotTestUser(t, c, "ceiling-snapshot-peer")
	assign(peer, usersAdmin, Scope{})
	actors := map[string]uint{
		"bootstrap-admin": admin.ID, "users.write-only": f.actor,
		"project_admin@A": projectAdminA, "project_admin@B": projectAdminB,
		"users-admin-peer": peer, "actor-0": 0,
	}

	allowed, refused := 0, 0
	for tName, target := range targets {
		for aName, actor := range actors {
			if actor == target {
				continue
			}
			t.Run(aName+"->"+tName, func(t *testing.T) {
				want := legacyAdminAuthorityVerdict(ctx, c, actor, target)
				require.False(t, errors.Is(want, errCeilingResolutionFailed), "reference: %v", want)
				got := c.requireEqualOrGreaterAdminAuthority(ctx, actor, target, "update")
				require.Equal(t, want == nil, got == nil, "verdict changed: reference %v, now %v", want, got)
				require.False(t, errors.Is(got, errCeilingResolutionFailed), "now: %v", got)
				entry := c.requireAdminRankCeilingForTarget(ctx, actor, target, "update")
				require.Equal(t, want == nil, entry == nil, "entry point: %v", entry)
				if entry != nil {
					require.ErrorIs(t, entry, ErrInsufficientAdminAuthority)
				}
			})
			if legacyAdminAuthorityVerdict(ctx, c, actor, target) == nil {
				allowed++
			} else {
				refused++
			}
		}
	}
	require.Error(t, legacyAdminAuthorityVerdict(ctx, c, f.actor, targets["group-member@A+grant@deleted-env"]),
		"premise: the deleted-environment scope is what refuses this pair")
	require.NotZero(t, allowed, "the table must contain allowed pairs")
	require.NotZero(t, refused, "the table must contain refused pairs")
}

// TestAdminRankCeiling_SnapshotReadFaultFailsClosed extends INV-CORE-04 to the
// new read: a fault on the target's grant listing refuses as a resolution
// failure, never as an allow and never as a 403.
func TestAdminRankCeiling_SnapshotReadFaultFailsClosed(t *testing.T) {
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	f := newCeilingSnapshotFixture(t, c, st)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, c.requireAdminRankCeilingForTarget(ctx, admin.ID, f.target, "delete"))

	injected := errors.New("injected: ListUserRoleGrants failed")
	fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "ListUserRoleGrants", NthCall: 1, Kind: faultstorage.KindError, Err: injected,
	})
	err = NewKeyorixCore(fs).requireAdminRankCeilingForTarget(ctx, admin.ID, f.target, "delete")
	require.True(t, fs.Fired(), "the target's grant listing must have been reached")
	require.ErrorIs(t, err, errCeilingResolutionFailed)
	require.ErrorIs(t, err, injected)
	require.False(t, errors.Is(err, ErrInsufficientAdminAuthority))
}
