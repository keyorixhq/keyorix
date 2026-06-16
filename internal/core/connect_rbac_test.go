package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// connectRBACCore builds a core backed by a real (in-memory) store so per-reference
// grants and role assignments actually resolve through the enforcement path.
func connectRBACCore(t *testing.T, conns ...connect.Connector) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.UserRole{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	if len(conns) > 0 {
		c.SetConnectManager(connect.NewManager(conns))
	}
	return c, db
}

func seedRoleForUser(t *testing.T, db *gorm.DB, userID, roleID uint, name string) {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: name}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: roleID}).Error)
}

func seedGrant(t *testing.T, c *KeyorixCore, roleID uint, connector, prefix string) {
	t.Helper()
	_, err := c.storage.CreateConnectRefGrant(context.Background(), &models.ConnectRefGrant{RoleID: roleID, Connector: connector, RefPrefix: prefix})
	require.NoError(t, err)
}

// With no grants on a connector, behavior is unchanged — connect.read + allowed_refs
// govern, and the read goes through (backward compatible).
func TestConnectRefRBAC_NoGrantsAllows(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "reader")
	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "anything/at/all")
	require.NoError(t, err)
	assert.Equal(t, "v", val)
}

// Once a connector has a grant, a ref under a granted prefix held by one of the
// caller's roles is allowed; a ref outside every granted prefix is denied.
func TestConnectRefRBAC_PrefixScopes(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "metrics-reader")
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
	seedGrant(t, c, 9, "aws", "metrics/") // granted to role 9, not the user's role 5

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "metrics/qps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

// An empty-prefix grant authorizes every ref on the connector for that role.
func TestConnectRefRBAC_EmptyPrefixAllowsAll(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	seedRoleForUser(t, db, 1, 5, "broad-reader")
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
	seedGrant(t, c, 5, "aws", "metrics/") // scopes aws only

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
	seedGrant(t, c, 6, "aws", "db/") // only the db role grants db/

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

	// A different machine with no matching role → denied (deny-by-default).
	_, err = c.ReadFederatedSecret(ctx, ActorTypeMachine, 99, "aws", "metrics/qps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

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
