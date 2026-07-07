// remote_storage_connect_grants_test.go — end-to-end coverage for backlog #527:
// RemoteStorage's ListConnectRefGrantsByConnector/ListConnectRefGrants/
// CreateConnectRefGrant/DeleteConnectRefGrant (Keyorix Connect per-reference
// grants, ADR-045) were entirely stubbed, so connectRefAllowed — called
// unconditionally by every ReadFederatedSecret — failed closed on EVERY
// federated read on EVERY connector whenever Connect was configured on a
// storage.type: remote node. Mirrors remote_storage_setup_tokens_test.go's
// (#510) and remote_storage_machine_identities_test.go's harness exactly: a
// real "upstream" exercised through the production NewRouter/handlers
// (including the new /api/v1/system/connect-grants routes,
// server/http/handlers/connect_grants_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote pointed at "upstream"
// over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConnectGrantsConnector is a minimal connect.Connector for exercising
// ReadFederatedSecret end-to-end without a real external secret store.
type fakeConnectGrantsConnector struct {
	name string
	val  string
}

func (f fakeConnectGrantsConnector) Name() string { return f.name }
func (f fakeConnectGrantsConnector) Type() string { return "fake" }
func (f fakeConnectGrantsConnector) GetSecret(_ context.Context, _ string) (string, error) {
	return f.val, nil
}

// newUpstreamDownstreamForConnectGrants builds the standard #510/#527-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers, and a "downstream" *core.KeyorixCore configured with
// storage.type: remote (ADR-049), pointed at "upstream" over real HTTP via
// store.RemoteStorage.
func newUpstreamDownstreamForConnectGrants(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// TestRemoteStorageConnectGrants_CreateListDeleteByConnector_RealServer proves the
// #527 fix for ListConnectRefGrantsByConnector/ListConnectRefGrants/
// CreateConnectRefGrant/DeleteConnectRefGrant: grants are genuinely persisted on
// the upstream via the DOWNSTREAM's RemoteStorage, filterable by connector, and
// deletable — all via storage.type: remote against a real router, not a protocol
// mock.
func TestRemoteStorageConnectGrants_CreateListDeleteByConnector_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForConnectGrants(t)
	ctx := context.Background()

	roleAWS, err := upstream.Storage().CreateRole(ctx, &models.Role{Name: "connect-grant-role-aws"})
	require.NoError(t, err)
	roleGCP, err := upstream.Storage().CreateRole(ctx, &models.Role{Name: "connect-grant-role-gcp"})
	require.NoError(t, err)

	g1, err := downstream.Storage().CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID: roleAWS.ID, Connector: "aws", RefPrefix: "prod/",
	})
	require.NoError(t, err, "creating a connect ref-grant must succeed via storage.type: remote")
	require.NotZero(t, g1.ID, "the upstream must assign a real ID")

	g2, err := downstream.Storage().CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID: roleAWS.ID, Connector: "aws", RefPrefix: "staging/",
	})
	require.NoError(t, err)

	g3, err := downstream.Storage().CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID: roleGCP.ID, Connector: "gcp", RefPrefix: "",
	})
	require.NoError(t, err)

	// Confirm these are REAL rows in the upstream's own storage (not just "the
	// call didn't error"), by reading back directly against upstream.
	all, err := upstream.Storage().ListConnectRefGrants(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// ListConnectRefGrants via the downstream round-trips every grant.
	allViaDownstream, err := downstream.Storage().ListConnectRefGrants(ctx)
	require.NoError(t, err)
	assert.Len(t, allViaDownstream, 3)

	// ListConnectRefGrantsByConnector filters correctly — the exact call
	// connectRefAllowed makes on every federated read.
	awsGrants, err := downstream.Storage().ListConnectRefGrantsByConnector(ctx, "aws")
	require.NoError(t, err)
	require.Len(t, awsGrants, 2)
	awsIDs := []uint{awsGrants[0].ID, awsGrants[1].ID}
	assert.Contains(t, awsIDs, g1.ID)
	assert.Contains(t, awsIDs, g2.ID)

	gcpGrants, err := downstream.Storage().ListConnectRefGrantsByConnector(ctx, "gcp")
	require.NoError(t, err)
	require.Len(t, gcpGrants, 1)
	assert.Equal(t, g3.ID, gcpGrants[0].ID)

	// A connector with no grants at all returns an empty (not error) result.
	noneGrants, err := downstream.Storage().ListConnectRefGrantsByConnector(ctx, "azure")
	require.NoError(t, err)
	assert.Empty(t, noneGrants)

	// DeleteConnectRefGrant removes exactly the targeted grant.
	require.NoError(t, downstream.Storage().DeleteConnectRefGrant(ctx, g1.ID))
	awsGrantsAfter, err := upstream.Storage().ListConnectRefGrantsByConnector(ctx, "aws")
	require.NoError(t, err)
	require.Len(t, awsGrantsAfter, 1)
	assert.Equal(t, g2.ID, awsGrantsAfter[0].ID)
}

// TestReadFederatedSecret_RemoteStorage_NoGrantsSucceeds_RealServer is the core
// #527 regression test: before this fix, ReadFederatedSecret failed
// UNCONDITIONALLY on a storage.type: remote node whenever Connect was
// configured, even for a connector with NO ref-grants at all, because
// connectRefAllowed's ListConnectRefGrantsByConnector call hard-errored on
// RemoteStorage's stub. This proves the read now succeeds end-to-end over a
// real HTTP hop.
func TestReadFederatedSecret_RemoteStorage_NoGrantsSucceeds_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForConnectGrants(t)
	downstream.SetConnectManager(connect.NewManager([]connect.Connector{
		fakeConnectGrantsConnector{name: "aws", val: "v3ry-secret"},
	}))
	require.True(t, downstream.ConnectEnabled())

	val, err := downstream.ReadFederatedSecret(context.Background(), core.ActorTypeUser, 1, "aws", "prod/db")
	require.NoError(t, err, "a federated read on storage.type: remote must not fail closed for a connector with no ref-grants (backlog #527)")
	assert.Equal(t, "v3ry-secret", val)
}

// TestReadFederatedSecret_RemoteStorage_PerRefEnforcement_RealServer proves the
// per-reference RBAC policy (ADR-045) itself round-trips correctly over
// storage.type: remote once a connector has a ref-grant: a machine identity
// holding the granted role can read a ref under the granted prefix, but is
// denied a ref outside it — enforced via the real upstream, not a protocol
// mock. Uses a machine-identity actor (not a user) because actorRoleIDs's
// underlying GetMachineRoleIDsAt is already proxied for RemoteStorage; the
// user-role equivalent (GetUserRoleIDsAt/GetUserGroupRoleIDsAt) is a separate,
// pre-existing, out-of-scope gap this fix does not touch.
func TestReadFederatedSecret_RemoteStorage_PerRefEnforcement_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForConnectGrants(t)
	ctx := context.Background()

	downstream.SetConnectManager(connect.NewManager([]connect.Connector{
		fakeConnectGrantsConnector{name: "aws", val: "v3ry-secret"},
	}))

	project, err := upstream.CreateProject(ctx, "Connect Grants Test Project", "")
	require.NoError(t, err)

	m, err := downstream.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID:    project.ID,
		Name:         "connect-grant-machine",
		IdentityType: core.MachineTypeCI,
		State:        core.MachineActive,
	})
	require.NoError(t, err)

	role, err := upstream.Storage().CreateRole(ctx, &models.Role{Name: "connect-grant-enforcement-role"})
	require.NoError(t, err)

	// Connect ref-grants are resolved at GLOBAL scope (internal/core/connect.go's
	// actorRoleIDs), mirroring the production grant scope exactly.
	globalScope := corestorage.Scope{}
	require.NoError(t, downstream.Storage().AssignMachineRole(ctx, m.ID, role.ID, globalScope))

	_, err = downstream.Storage().CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID: role.ID, Connector: "aws", RefPrefix: "prod/",
	})
	require.NoError(t, err)

	// A ref under the granted prefix succeeds.
	val, err := downstream.ReadFederatedSecret(ctx, core.ActorTypeMachine, m.ID, "aws", "prod/db")
	require.NoError(t, err)
	assert.Equal(t, "v3ry-secret", val)

	// A ref outside the granted prefix is denied — deny-by-default once the
	// connector is scoped.
	_, err = downstream.ReadFederatedSecret(ctx, core.ActorTypeMachine, m.ID, "aws", "dev/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}
