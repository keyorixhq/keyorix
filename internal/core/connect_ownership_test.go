// connect_ownership_test.go — ADR-082 branch 2: ownership enforcement in
// ReadFederatedSecret and ConnectReadableConnectorNames. Uses connectRBACCore
// (connect_rbac_test.go) so role scopes actually resolve through GetUserRoleScopes/
// GetMachineRoleScopes against a real (in-memory) store, exactly like production.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestConnectOwnership_ZeroScopeEntryMustSurvive is the ADR-082 invariant test: a
// caller's {0,0} (global-scope) role-scope entry must survive from
// GetUserRoleScopes all the way into the ownership comparison, unfiltered. A
// future "cleanup" that strips ProjectID==0 entries before the comparison —
// exactly what the pre-ADR-082 design did — would silently and completely remove
// every global-scoped caller's Connect reach, with no compile error, and no other
// test in this file would catch it (every other ownership test here uses a caller
// with an explicit project-scoped role). If this test fails, the fix is almost
// never "strip the {0,0} entry, it looks like noise" — read ADR-082 §D/§E first.
func TestConnectOwnership_ZeroScopeEntryMustSurvive(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 99}})

	// The caller holds ONLY a role granted at the GLOBAL scope (ProjectID 0) — no
	// role at project 99 specifically, and the role is deliberately NOT one of the
	// admin-named roles, proving this is a scope check, not a name check.
	seedRoleForUser(t, db, 1, 10, "billing-viewer")

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.NoError(t, err, "a caller with only a global-scoped role must reach a project-scoped connector via the {0,0} wildcard (ADR-082 §E) — if this fails, check whether the raw scope list is being filtered to ProjectID != 0 before the ownership comparison runs")
	assert.Equal(t, "v3ry-secret", val)
}

// TestConnectOwnership_ReadFederatedSecret is the table-driven ownership suite
// (ADR-082 §E): project-scope matching, the {0,0} wildcard, no relevant scope,
// platform connectors, and ConnectRefGrant delegation for an otherwise-denied
// connector.
func TestConnectOwnership_ReadFederatedSecret(t *testing.T) {
	const connectorProjectID = 42

	tests := []struct {
		name      string
		setup     func(t *testing.T, c *KeyorixCore, db *gorm.DB)
		userID    uint
		wantErr   bool
		wantValue string
	}{
		{
			name: "caller with matching project scope is allowed",
			setup: func(t *testing.T, c *KeyorixCore, db *gorm.DB) {
				seedRoleForUserAtProject(t, db, 1, 20, "project-member", connectorProjectID)
			},
			userID:    1,
			wantValue: "v3ry-secret",
		},
		{
			name: "caller with non-matching project scope is denied",
			setup: func(t *testing.T, c *KeyorixCore, db *gorm.DB) {
				seedRoleForUserAtProject(t, db, 2, 21, "other-project-member", connectorProjectID+1)
			},
			userID:  2,
			wantErr: true,
		},
		{
			name: "caller with global {0,0} scope against a project-scoped connector is allowed via the wildcard",
			setup: func(t *testing.T, c *KeyorixCore, db *gorm.DB) {
				seedRoleForUser(t, db, 3, 22, "global-scoped-role")
			},
			userID:    3,
			wantValue: "v3ry-secret",
		},
		{
			name:    "caller with no relevant scope at all is denied",
			setup:   func(t *testing.T, c *KeyorixCore, db *gorm.DB) {},
			userID:  4,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
			c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: connectorProjectID}})
			tt.setup(t, c, db)

			val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, tt.userID, "aws", "ref")
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown connector", "ownership denial must reuse the unknown-connector shape (ADR-082) — do not confirm existence to an unauthorized caller")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, val)
		})
	}
}

// TestConnectOwnership_PlatformConnectorRequiresPlatformUse supersedes the
// pre-branch-4 "any connect.read holder reaches it" behavior this test used to
// assert (its own prior docstring named this as the TODO(ADR-082 branch 4) gap
// explicitly). Now: a caller with zero roles — including no connect.platform.use
// — is denied, terminally (no ConnectRefGrant delegation fallback; see
// connectDenyReasonPlatformPermissionDenied).
func TestConnectOwnership_PlatformConnectorRequiresPlatformUse(t *testing.T) {
	c, _ := connectRBACCore(t, fakeConnector{name: "shared-vault", val: "shared-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"shared-vault": {Scope: "platform"}})

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 999, "shared-vault", "ref")
	require.Error(t, err, "a platform-scoped connector must now deny a caller with no connect.platform.use grant")
	assert.ErrorIs(t, err, ErrConnectUnknownConnector, "the denial must reuse the opaque unknown-connector shape (ADR-082)")
}

// TestConnectOwnership_PlatformConnectorAllowsHolderOfPlatformUse is the allow
// counterpart: a caller who DOES hold connect.platform.use reaches the platform
// connector, same as any other allow path.
func TestConnectOwnership_PlatformConnectorAllowsHolderOfPlatformUse(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "shared-vault", val: "shared-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"shared-vault": {Scope: "platform"}})
	seedRoleForUser(t, db, 1, 10, "platform-caller")
	seedConnectPlatformUsePermission(t, db, 10)

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "shared-vault", "ref")
	require.NoError(t, err)
	assert.Equal(t, "shared-secret", val)
}

// TestConnectOwnership_ConnectRefGrantDelegatesForNonOwnedCaller proves the
// delegation path (ADR-082 §F): a caller with NO ownership claim on the
// connector's project is still allowed through an explicit ConnectRefGrant
// covering their role and the requested ref.
func TestConnectOwnership_ConnectRefGrantDelegatesForNonOwnedCaller(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})

	// Caller has a role at a DIFFERENT project — not owned.
	seedRoleForUserAtProject(t, db, 5, 30, "borrower", 99)
	// But that role holds an explicit delegation grant on "aws".
	seedGrant(t, c, 30, "aws", "prod/")

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 5, "aws", "prod/db")
	require.NoError(t, err, "a non-owned caller with a matching ConnectRefGrant must be allowed (ADR-082 §F delegation)")
	assert.Equal(t, "v3ry-secret", val)

	// The same caller, same role, but a ref OUTSIDE the grant's prefix: no
	// ownership and no matching delegation — denied. connectRefGrantDelegates
	// (unlike connectRefAllowed) must not treat "grants exist but none match" as
	// an allow for a non-owned caller.
	_, err = c.ReadFederatedSecret(context.Background(), ActorTypeUser, 5, "aws", "dev/db")
	require.Error(t, err)
}

// TestConnectOwnership_NonOwnedCallerNoGrantsAtAllIsDenied proves
// connectRefGrantDelegates' polarity is the OPPOSITE of connectRefAllowed's: for
// a non-owned caller, a connector with ZERO ref-grants configured means NO
// delegation path (deny), not "no additional narrowing" (allow) — the shortcut
// that's correct only for an already-owned caller.
func TestConnectOwnership_NonOwnedCallerNoGrantsAtAllIsDenied(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
	seedRoleForUserAtProject(t, db, 6, 31, "not-owner", 99) // no grant seeded at all

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 6, "aws", "ref")
	require.Error(t, err, "a non-owned caller must be denied when the connector has no ref-grants at all — no grants means no delegation path, not an automatic allow")
}

// TestConnectOwnership_MissingFromOwnershipMapDenies proves the structural
// invariant (ADR-082 §E): a connector absent from the ownership map is denied,
// never silently skipped or treated as owned. server/main.go's boot-time key-set
// check exists to guarantee this never happens for a correctly-booted server;
// this proves connectOwnershipSatisfied's own runtime backstop independently.
func TestConnectOwnership_MissingFromOwnershipMapDenies(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	// connectRBACCore defaults every connector to scope: platform (always-owned) —
	// explicitly clear that here to exercise the genuinely-missing-entry case.
	c.SetConnectOwnership(nil)
	seedRoleForUser(t, db, 1, 10, "global-role") // even a global-scoped caller...

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
	require.Error(t, err, "a connector missing from the ownership map must deny, never fall back to allow")
}

// TestConnectOwnership_MachineIdentityProjectScopedRoleNotGlobal proves ADR-082
// §E's machine-identity composition claim in code: a machine identity holding an
// admin-equivalent role at a SPECIFIC project's scope produces that project's
// scope entry from GetMachineRoleScopes, not {0,0} — so it does NOT get the
// global wildcard, and is correctly bounded to that one project.
func TestConnectOwnership_MachineIdentityProjectScopedRoleNotGlobal(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})

	require.NoError(t, db.Create(&models.Role{ID: 40, Name: "admin"}).Error) // admin-NAMED, but scoped below
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: 7, RoleID: 40, ProjectID: 99, // a DIFFERENT project than the connector's
	}).Error)

	_, err := c.ReadFederatedSecret(context.Background(), ActorTypeMachine, 7, "aws", "ref")
	require.Error(t, err, "a machine identity holding an admin-named role at a SPECIFIC project's scope must be bounded to that project, not treated as global — GetMachineRoleScopes must return {ProjectID:99}, not {0,0}, for this grant")

	// The same machine identity DOES reach the connector once its role is granted
	// at the connector's OWN project — proving the denial above is genuinely
	// about scope, not a broken machine-identity path in general.
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: 7, RoleID: 40, ProjectID: 42,
	}).Error)
	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeMachine, 7, "aws", "ref")
	require.NoError(t, err)
	assert.Equal(t, "v3ry-secret", val)
}

// TestConnectOwnership_MachineIdentityGlobalRoleGetsWildcard is the machine-
// identity counterpart to TestConnectOwnership_ZeroScopeEntryMustSurvive: a
// machine identity granted a role at the TRUE global scope ({0,0}) receives the
// same ownership wildcard a user would (ADR-082 §E) — roleSetContainsAdmin-style
// actor-agnostic behavior extended consistently to Connect ownership.
func TestConnectOwnership_MachineIdentityGlobalRoleGetsWildcard(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v3ry-secret"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})

	require.NoError(t, db.Create(&models.Role{ID: 41, Name: "global-machine-role"}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: 8, RoleID: 41, ProjectID: 0, // global scope
	}).Error)

	val, err := c.ReadFederatedSecret(context.Background(), ActorTypeMachine, 8, "aws", "ref")
	require.NoError(t, err)
	assert.Equal(t, "v3ry-secret", val)
}

// TestConnectReadableConnectorNames_FiltersToOwnedSubset proves ListConnectors
// discovery (ADR-082 §E) filters by ownership: a caller who is a member of only
// one of two connectors' owning projects sees just that one connector, not both —
// a discovery endpoint that lists an unreachable connector leaks its existence to
// a caller who cannot use it.
func TestConnectReadableConnectorNames_FiltersToOwnedSubset(t *testing.T) {
	c, db := connectRBACCore(t,
		fakeConnector{name: "aws-payments", val: "v1"},
		fakeConnector{name: "aws-billing", val: "v2"},
	)
	c.SetConnectOwnership(map[string]ConnectOwnership{
		"aws-payments": {Scope: "project", ProjectID: 42},
		"aws-billing":  {Scope: "project", ProjectID: 99},
	})
	seedRoleForUserAtProject(t, db, 1, 10, "payments-member", 42)

	names, err := c.ConnectReadableConnectorNames(context.Background(), ActorTypeUser, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"aws-payments"}, names, "caller must see only the connector whose project they're a member of")
}

// TestConnectReadableConnectorNames_GlobalScopedCallerSeesAll proves a
// global-scoped caller (the {0,0} wildcard — ADR-082 §E) sees every
// scope: project connector via the SAME per-connector filter loop, not a
// separate "if admin, return everything" branch — ConnectReadableConnectorNames
// has no such branch, so this is exercising the loop's actual behavior.
func TestConnectReadableConnectorNames_GlobalScopedCallerSeesAll(t *testing.T) {
	c, db := connectRBACCore(t,
		fakeConnector{name: "aws-payments", val: "v1"},
		fakeConnector{name: "aws-billing", val: "v2"},
	)
	c.SetConnectOwnership(map[string]ConnectOwnership{
		"aws-payments": {Scope: "project", ProjectID: 42},
		"aws-billing":  {Scope: "project", ProjectID: 99},
	})
	seedRoleForUser(t, db, 2, 20, "global-scoped-role")

	names, err := c.ConnectReadableConnectorNames(context.Background(), ActorTypeUser, 2)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"aws-payments", "aws-billing"}, names, "a global-scoped caller must see every project-scoped connector via the {0,0} wildcard")
}

// TestConnectReadableConnectorNames_PlatformFilteredWithoutPlatformUse proves
// ListConnectors filtering (ADR-082 branch 4) via the SAME per-connector filter
// ReadFederatedSecret uses (connectOwnershipSatisfied) — no separate branch: a
// caller lacking connect.platform.use sees a platform connector disappear from
// discovery, exactly like ReadFederatedSecret would deny an actual read of it.
func TestConnectReadableConnectorNames_PlatformFilteredWithoutPlatformUse(t *testing.T) {
	c, db := connectRBACCore(t,
		fakeConnector{name: "shared-vault", val: "v1"},
		fakeConnector{name: "aws-payments", val: "v2"},
	)
	c.SetConnectOwnership(map[string]ConnectOwnership{
		"shared-vault": {Scope: "platform"},
		"aws-payments": {Scope: "project", ProjectID: 42},
	})
	seedRoleForUserAtProject(t, db, 1, 10, "payments-member", 42) // no connect.platform.use

	names, err := c.ConnectReadableConnectorNames(context.Background(), ActorTypeUser, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"aws-payments"}, names, "the platform connector must be filtered out without connect.platform.use, even though the project connector (a genuine ownership match) is still visible")
}

// TestConnectReadableConnectorNames_PlatformVisibleWithPlatformUse is the allow
// counterpart: a caller holding connect.platform.use sees the platform
// connector in discovery too.
func TestConnectReadableConnectorNames_PlatformVisibleWithPlatformUse(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "shared-vault", val: "v1"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"shared-vault": {Scope: "platform"}})
	seedRoleForUser(t, db, 1, 10, "platform-caller")
	seedConnectPlatformUsePermission(t, db, 10)

	names, err := c.ConnectReadableConnectorNames(context.Background(), ActorTypeUser, 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"shared-vault"}, names)
}

// seedRoleForUserAtProject mirrors seedRoleForUser (connect_rbac_test.go) but
// grants the role at a specific project scope instead of global. ADR-084:
// same reserved-name-sets-the-flag behavior as seedRoleForUser.
func seedRoleForUserAtProject(t *testing.T, db *gorm.DB, userID, roleID uint, name string, projectID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.Role{ID: roleID, Name: name, BypassesPermissionChecks: isAdminRoleName(name)}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: roleID, ProjectID: projectID}).Error)
}
