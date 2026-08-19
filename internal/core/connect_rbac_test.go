package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// connectRBACCore builds a core backed by a real (in-memory) store so per-reference
// grants and role assignments actually resolve through the enforcement path. Every
// connector is wired as scope: platform by default (ADR-082) — a platform
// connector passes ownership for any caller in this branch, matching this suite's
// pre-ADR-082 assumption that any connect.read holder can reach a configured test
// connector; ownership-specific behavior is covered separately
// (connect_ownership_test.go).
func connectRBACCore(t *testing.T, conns ...connect.Connector) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.UserRole{}, &models.MachineIdentityRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.ConnectRefGrant{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
		&models.ConnectorProjectBinding{},
		&models.Permission{}, &models.RolePermission{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	if len(conns) > 0 {
		c.SetConnectManager(connect.NewManager(conns))
		ownership := make(map[string]ConnectOwnership, len(conns))
		for _, conn := range conns {
			ownership[conn.Name()] = ConnectOwnership{Scope: "platform"}
		}
		c.SetConnectOwnership(ownership)
	}
	return c, db
}

func seedRoleForUser(t *testing.T, db *gorm.DB, userID, roleID uint, name string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: name}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: roleID}).Error)
}

// seedConnectPlatformUsePermission grants roleID the connect.platform.use
// permission (ADR-082 branch 4). Every connectRBACCore-based test defaults its
// connectors to scope: platform, and a platform-scope read now requires this
// permission — call this wherever a test's role is meant to actually reach a
// platform connector (i.e. it is exercising something OTHER than the
// platform-permission gate itself, such as ADR-045 ref-grant behavior). Each
// test gets its own in-memory DB (connectRBACCore), so there's no cross-test
// collision creating the same permission name twice.
func seedConnectPlatformUsePermission(t *testing.T, db *gorm.DB, roleID uint) {
	t.Helper()
	perm := models.Permission{Name: "connect.platform.use", Description: "test", Resource: "connect", Action: "platform.use"}
	require.NoError(t, db.Create(&perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: roleID, PermissionID: perm.ID}).Error)
}

func seedGrant(t *testing.T, c *KeyorixCore, roleID uint, connector, prefix string) {
	t.Helper()
	_, err := c.storage.CreateConnectRefGrant(context.Background(), &models.ConnectRefGrant{RoleID: roleID, Connector: connector, RefPrefix: prefix})
	require.NoError(t, err)
}

func seedGrantExpiring(t *testing.T, c *KeyorixCore, roleID uint, connector, prefix string, expiresAt time.Time) {
	t.Helper()
	_, err := c.storage.CreateConnectRefGrant(context.Background(), &models.ConnectRefGrant{RoleID: roleID, Connector: connector, RefPrefix: prefix, ExpiresAt: &expiresAt})
	require.NoError(t, err)
}

// With no grants on a connector, behavior is unchanged — connect.read + allowed_refs
// govern, and the read goes through (backward compatible).
func TestConnectRefRBAC_NoGrantsAllows(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045, not the platform gate
	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "anything/at/all")
	require.NoError(t, err)
	assert.Equal(t, "v", val)
}

// Once a connector has a grant, a ref under a granted prefix held by one of the
// caller's roles is allowed; a ref outside every granted prefix is denied.
func TestConnectRefRBAC_PrefixScopes(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "metrics-reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045, not the platform gate
	seedGrant(t, c, 5, "aws", "metrics/")

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	_, err = c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "db/password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

// A grant for a role the caller does NOT hold does not authorize them (deny-by-default
// once the connector is scoped).
func TestConnectRefRBAC_RoleMismatchDenied(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: role 5 must reach the ref-grant check to prove the ROLE mismatch, not the platform gate, is what denies it
	seedGrant(t, c, 9, "aws", "metrics/")      // granted to role 9, not the user's role 5

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

// An empty-prefix grant authorizes every ref on the connector for that role.
func TestConnectRefRBAC_EmptyPrefixAllowsAll(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "broad-reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045, not the platform gate
	seedGrant(t, c, 5, "aws", "")

	for _, ref := range []string{"metrics/x", "db/y", "anything"} {
		val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", ref)
		require.NoError(t, err, ref)
		assert.Equal(t, "v", val)
	}
}

// Grants on one connector do not constrain a different connector that has none.
func TestConnectRefRBAC_OtherConnectorUnaffected(t *testing.T) {
	c, db := connectRBACCore(t,
		fakeConnector{name: "aws", val: "a"},
		fakeConnector{name: "gcp", val: "g"},
	)
	seedRoleForUser(t, db, 1, 5, "reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045, not the platform gate — covers both connectors, gcp included
	seedGrant(t, c, 5, "aws", "metrics/")      // scopes aws only

	// gcp has no grants → unaffected.
	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "gcp", "projects/p/secrets/x/versions/latest")
	require.NoError(t, err)
	assert.Equal(t, "g", val)

	// aws is scoped → a non-matching ref is denied.
	_, err = c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "db/x")
	require.Error(t, err)
}

// A caller holding multiple roles is allowed if ANY of them has a matching grant.
func TestConnectRefRBAC_MultiRoleUnion(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Role{ID: 5, Name: "metrics"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 6, Name: "db"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 5}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 6}).Error)
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045 role-union matching, not the platform gate — either held role suffices for platform.use
	seedGrant(t, c, 6, "aws", "db/")           // only the db role grants db/

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "db/password")
	require.NoError(t, err)
	assert.Equal(t, "v", val)
}

// A machine identity's grants resolve from machine_identity_roles (not user_roles), so
// the per-reference policy is enforceable for machine principals too (ADR-045).
func TestConnectRefRBAC_MachineIdentityRoles(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "ci-metrics"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 42, RoleID: 7}).Error)
	seedConnectPlatformUsePermission(t, db, 7) // ADR-082 branch 4: this test is about ADR-045, not the platform gate
	seedGrant(t, c, 7, "aws", "metrics/")
	ctx := context.Background()

	// Machine 42 holds role 7, which is granted metrics/* → allowed.
	val, err := c.ReadFederatedSecret(ctx, ActorTypeMachine, 42, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	// Same machine, ref outside the granted prefix → denied.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeMachine, 42, "aws", "db/password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")

	// A different machine holds NO role at all — including no connect.platform.use —
	// so it is now denied at the platform-permission gate itself (ADR-082 branch 4),
	// before ever reaching the per-ref grant check this test otherwise exercises. It
	// is still "deny-by-default", just via an earlier gate than the sibling assertion
	// above; the opaque unknown-connector shape is deliberate (ADR-082 §H), so this
	// no longer asserts "not permitted" specifically.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeMachine, 99, "aws", "metrics/qps")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConnectUnknownConnector)
}

// A grant for a role the caller holds only VIA GROUP MEMBERSHIP must authorize them —
// the per-reference policy resolves effective roles (direct + group-derived) the same
// way connect.read itself is authorized (ADR-045).
func TestConnectRefRBAC_GroupDerivedRole(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	// Role 5 exists; user 1 is NOT directly assigned it — they're in group 3, and
	// group 3 has role 5.
	require.NoError(t, db.Create(&models.Role{ID: 5, Name: "metrics"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 3, Name: "analytics"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 3}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 3, RoleID: 5}).Error)
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045 group-derived role resolution, not the platform gate — scopedRoleIDs unions group-derived roles the same way for both checks
	seedGrant(t, c, 5, "aws", "metrics/")

	// The user reaches the grant through their group-derived role.
	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	// Still deny-by-default outside the granted prefix.
	_, err = c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "db/x")
	require.Error(t, err)
}

// Glob patterns (ADR-045): a pattern with metacharacters matches via path.Match
// (* not crossing '/'); a plain pattern stays a prefix match (backward compatible).
func TestConnectRefRBAC_GlobPatterns(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045 glob matching, not the platform gate
	seedGrant(t, c, 5, "aws", "prod/*/db")     // exactly one segment between prod/ and /db
	ctx := context.Background()

	val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/eu/db")
	require.NoError(t, err)
	assert.Equal(t, "v", val)

	// * does not cross '/', so a two-segment middle does not match.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/eu/west/db")
	require.Error(t, err)
	// A different leaf does not match.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "prod/eu/secrets")
	require.Error(t, err)
}

func TestRefMatches(t *testing.T) {
	cases := []struct {
		pattern, ref string
		want         bool
	}{
		{"", "anything", true},              // empty prefix = all
		{"metrics/", "metrics/qps", true},   // plain prefix
		{"metrics/", "db/x", false},         // prefix miss
		{"metrics/*", "metrics/qps", true},  // glob, one segment
		{"metrics/*", "metrics/a/b", false}, // * does not cross '/'
		{"prod/*/db", "prod/eu/db", true},   // middle wildcard
		{"prod/*/db", "prod/eu/west/db", false},
		{"db?", "db1", true}, // single-char wildcard
		{"db?", "db", false},
		{"[", "anything", false}, // malformed glob matches nothing
		// #326: a traversal-shaped ref must never match, even though a raw
		// strings.HasPrefix(ref, pattern) would report a literal match.
		{"secret/data/myapp/", "secret/data/myapp/../otherapp/secret", false},
		{"secret/data/myapp/", "secret/data/myapp/config", true}, // sibling non-traversal ref still matches
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, refMatches(tc.pattern, tc.ref), "refMatches(%q, %q)", tc.pattern, tc.ref)
	}
}

// TestConnectRefRBAC_CrossTenantTraversalDenied proves the exact exploit trace from
// finding #326 at the ADR-045 per-reference RBAC layer: a role granted only
// "secret/data/myapp/" on the vault connector cannot read
// "secret/data/otherapp/secret" by requesting the ref
// "secret/data/myapp/../otherapp/secret". A raw strings.HasPrefix check would treat
// that ref as matching the grant (the literal string starts with the granted
// prefix); refMatches must reject it outright.
func TestConnectRefRBAC_CrossTenantTraversalDenied(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "vault", val: "myapp-secret"})
	seedRoleForUser(t, db, 1, 5, "myapp-reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045/#326 traversal handling, not the platform gate
	seedGrant(t, c, 5, "vault", "secret/data/myapp/")
	ctx := context.Background()

	_, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "vault", "secret/data/myapp/../otherapp/secret")
	require.Error(t, err, "the cross-tenant traversal ref must be denied by the per-reference grant")
	assert.Contains(t, err.Error(), "not permitted")

	// The legitimate ref within the granted prefix still works through the same
	// code path (connectRefAllowed -> refMatches -> GetSecret).
	val, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "vault", "secret/data/myapp/config")
	require.NoError(t, err)
	assert.Equal(t, "myapp-secret", val)
}

// A Connect ref-grant is otherwise permanent (ADR-045); ExpiresAt makes it time-bound,
// mirroring UserRole/ShareRecord — a grant that has already passed its expiry must stop
// authorizing immediately, even though the row has not yet been swept.
func TestConnectRefRBAC_ExpiredGrantDenied(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "temp-reader")
	seedConnectPlatformUsePermission(t, db, 5)                                  // ADR-082 branch 4: this test is about ADR-045 grant expiry, not the platform gate
	seedGrantExpiring(t, c, 5, "aws", "metrics/", time.Now().Add(-time.Minute)) // already expired
	ctx := context.Background()

	_, err := c.ReadFederatedSecret(ctx, ActorTypeUser, 1, "aws", "metrics/qps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")

	ok, err := c.connectRefAllowed(ctx, ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.False(t, ok)
}

// A grant with a future ExpiresAt still authorizes normally until it passes.
func TestConnectRefRBAC_UnexpiredGrantAllowed(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "temp-reader")
	seedConnectPlatformUsePermission(t, db, 5) // ADR-082 branch 4: this test is about ADR-045 grant expiry, not the platform gate
	seedGrantExpiring(t, c, 5, "aws", "metrics/", time.Now().Add(time.Hour))

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.NoError(t, err)
	assert.Equal(t, "v", val)
}

// CreateConnectRefGrant plumbs an optional expiresAt through to the persisted grant.
// ADR-082 branch 4: unaffected by the connect.platform.use gate — this test never
// calls ReadFederatedSecret/connectOwnershipSatisfied at all, only the grant-
// management path. #1479: connectRBACCore defaults every connector to
// Scope: "platform", which CreateConnectRefGrant now refuses — override to
// "project" here since this test is about expiresAt plumbing, not scope, and
// a platform-scoped grant would be rejected before reaching the code this
// test actually exercises.
func TestCreateConnectRefGrant_PersistsExpiresAt(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "proj-a"}).Error)
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 10}})
	require.NoError(t, db.Create(&models.Role{ID: 5, Name: "temp-reader"}).Error)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)

	g, err := c.CreateConnectRefGrant(context.Background(), 1, 5, "aws", "metrics/", &exp)
	require.NoError(t, err)
	require.NotNil(t, g.ExpiresAt)
	assert.WithinDuration(t, exp, *g.ExpiresAt, time.Second)

	// A nil expiresAt (the common case) still creates a permanent grant.
	g2, err := c.CreateConnectRefGrant(context.Background(), 1, 5, "aws", "db/", nil)
	require.NoError(t, err)
	assert.Nil(t, g2.ExpiresAt)
}

// TestCreateConnectRefGrant_RefusesAgainstPlatformConnector is #1479's fix:
// a platform-scoped connector's ownership check is a terminal deny in
// ReadFederatedSecret (connectOwnershipSatisfied never falls through to
// ConnectRefGrant delegation for one), so a grant created against one would
// be dead configuration — accepted, listed, never once consulted by a read.
// connectRBACCore's default wiring (every connector scope: platform) is
// exactly the case this test needs, no override required.
func TestCreateConnectRefGrant_RefusesAgainstPlatformConnector(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Role{ID: 5, Name: "temp-reader"}).Error)

	g, err := c.CreateConnectRefGrant(context.Background(), 1, 5, "aws", "metrics/", nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrConnectRefGrantAgainstPlatformConnector)
	assert.Nil(t, g)

	grants, err := c.storage.ListConnectRefGrants(context.Background())
	require.NoError(t, err)
	assert.Empty(t, grants, "a refused grant must not be persisted")
}

// TestCreateConnectRefGrant_StillAllowedAgainstProjectConnector confirms the
// #1479 fix is scope-specific, not a blanket new restriction: a project-scoped
// connector's ConnectRefGrant creation is unaffected.
func TestCreateConnectRefGrant_StillAllowedAgainstProjectConnector(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "proj-a"}).Error)
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 10}})
	require.NoError(t, db.Create(&models.Role{ID: 5, Name: "temp-reader"}).Error)

	g, err := c.CreateConnectRefGrant(context.Background(), 1, 5, "aws", "metrics/", nil)
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, "aws", g.Connector)
}

// G33: a machine identity's ConnectRefGrant-referenced role held ONLY at a
// project scope (no global grant) must be honoured exactly like the equivalent
// human user's project-scoped role — actorRoleIDs's machine branch used to stop
// at the global-scope GetMachineRoleIDsAt(ctx, principalID, Scope{}) query,
// silently dropping every project-scoped machine grant (the same
// "helper written for humans, never updated for machines" gap the user branch
// just below it was already fixed for, per CONN-005).
func TestConnectRefRBAC_MachineIdentityProjectScopedRole(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "proj-a"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "ci-metrics"}).Error)
	// Granted to the machine ONLY at project 10 — deliberately no global grant.
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 42, RoleID: 7, ProjectID: 10}).Error)
	seedGrant(t, c, 7, "aws", "metrics/")
	// ADR-082 branch 4: connect.platform.use is checked at Scope{} (global) —
	// intentionally: a platform connector is install-wide, so a purely
	// project-scoped grant of the permission (like role 7 above, deliberately) is
	// a category error and correctly does NOT satisfy it. This test's whole point
	// is proving role 7's PROJECT-scoped grant is honoured for the ref-grant
	// check specifically, so platform.use is granted here via a SEPARATE role
	// held at the true global scope, decoupled from role 7 — not by making role 7
	// global, which would defeat the test.
	require.NoError(t, db.Create(&models.Role{ID: 21, Name: "platform-access"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 42, RoleID: 21}).Error)
	seedConnectPlatformUsePermission(t, db, 21)
	ctx := context.Background()

	val, err := c.ReadFederatedSecret(ctx, ActorTypeMachine, 42, "aws", "metrics/qps")
	require.NoError(t, err, "a machine identity's project-scoped role grant must be honoured, exactly like a user's")
	assert.Equal(t, "v", val)

	// Still deny-by-default outside the granted prefix.
	_, err = c.ReadFederatedSecret(ctx, ActorTypeMachine, 42, "aws", "db/password")
	require.Error(t, err)
}

// actorRoleIDs (G33's detection_idea): a machine identity's project-scoped role
// grant must resolve into the SAME role-ID set as an equivalent human user
// holding the identical role at the identical project scope.
// ADR-082 branch 4: unaffected — calls actorRoleIDs directly, never reaching
// connectOwnershipSatisfied/the platform gate.
func TestActorRoleIDs_MachineMatchesEquivalentUser_ProjectScoped(t *testing.T) {
	c, db := connectRBACCore(t)
	require.NoError(t, db.Create(&models.Project{ID: 10, Name: "proj-a"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 7, Name: "ci-metrics"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 42, RoleID: 7, ProjectID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 7, ProjectID: 10}).Error)
	ctx := context.Background()

	machineRoles, err := c.actorRoleIDs(ctx, ActorTypeMachine, 42)
	require.NoError(t, err)
	userRoles, err := c.actorRoleIDs(ctx, ActorTypeUser, 1)
	require.NoError(t, err)

	assert.True(t, machineRoles[7], "the machine identity's project-scoped role must resolve into actorRoleIDs's result")
	assert.Equal(t, userRoles, machineRoles, "a machine identity holding the same project-scoped role as a human user must resolve to an identical role-ID set")
}

// ADR-082 branch 4: unaffected — calls connectRefAllowed directly, never
// reaching connectOwnershipSatisfied/the platform gate.
func TestConnectRefAllowed_Direct(t *testing.T) {
	c, db := connectRBACCore(t)
	seedRoleForUser(t, db, 1, 5, "reader")
	seedGrant(t, c, 5, "aws", "metrics/")
	ctx := context.Background()

	ok, err := c.connectRefAllowed(ctx, ActorTypeUser, 1, "aws", "metrics/foo")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = c.connectRefAllowed(ctx, ActorTypeUser, 1, "aws", "secrets/foo")
	require.NoError(t, err)
	assert.False(t, ok)

	// A connector with no grants is unconstrained.
	ok, err = c.connectRefAllowed(ctx, ActorTypeUser, 1, "vault", "secret/data/x")
	require.NoError(t, err)
	assert.True(t, ok)
}
