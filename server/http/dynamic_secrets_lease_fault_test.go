// dynamic_secrets_lease_fault_test.go — STORAGE-ERR-CLASS-2 item 3.
//
// The lease routes resolve their authorization scope by reading the lease
// (ScopeFromDynamicSecretLeaseParam) BEFORE the handler runs. That resolver folded
// every read error into "target not found", so a storage fault answered a global
// holder 404 "Resource not found" (the lease may still be live and the revoke was
// never applied) and everyone else 403. A fault now answers a global holder 503
// storage_unavailable + Retry-After; the 403 for a caller without global standing
// is unchanged, so no existence signal is added for them, and a true not-found is
// still 404 for a global holder.
//
// Only the real router + middleware chain can show this: the decision is made in
// RequireScopedPermission, not in the handler.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestDynamicSecretLeaseRoutes_ReadFaultIs503ForGlobalHolders(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	var faulty *faultstorage.FaultyStorage
	testCore := newTestCoreWrapped(t, func(real storage.Storage) storage.Storage {
		faulty = faultstorage.NewFaultyStorage(real, nil) // unarmed: setup runs fault-free
		return faulty
	})
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	ctx := context.Background()
	adminToken := createTestToken(t, testCore) // global admin; also project A + its default env
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projA := projects[0]
	envs, err := testCore.Storage().ListEnvironments(ctx)
	require.NoError(t, err)
	var envA uint
	for _, e := range envs {
		if e.ProjectID == projA.ID {
			envA = e.ID
			break
		}
	}
	require.NotZero(t, envA)

	cfg, err := testCore.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name: "lease-fault-target", ProjectID: projA.ID, EnvironmentID: envA,
		BackendType: "postgres", AdminDSN: "postgres://admin@db/x",
		DefaultTTLSeconds: 300, MaxTTLSeconds: 3600, MaxActiveLeases: 10,
		CreatedBy: "testadmin", ActorID: admin.ID,
	})
	require.NoError(t, err)
	lease, err := testCore.Storage().CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: "lease-fault-1", ProjectID: projA.ID, EnvironmentID: envA,
		Status: "active", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	// A caller with secrets.read+write in ANOTHER project only: no global standing.
	projB, err := testCore.CreateProject(ctx, "leaseFaultB", "other project")
	require.NoError(t, err)
	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var readID, writeID uint
	for _, p := range perms {
		switch p.Name {
		case "secrets.read":
			readID = p.ID
		case "secrets.write":
			writeID = p.ID
		}
	}
	require.NotZero(t, readID)
	require.NotZero(t, writeID)
	roleName, err := identity.NewFoldedName("lease-fault-limited")
	require.NoError(t, err)
	role, err := testCore.Storage().CreateRole(ctx, roleName, "limited")
	require.NoError(t, err)
	require.NoError(t, testCore.AssignPermissionToRole(ctx, admin.ID, role.ID, readID, false))
	require.NoError(t, testCore.AssignPermissionToRole(ctx, admin.ID, role.ID, writeID, false))
	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{Username: "leasefaultlim", Email: "leasefaultlim@example.com", Password: "Xk9#mQ7zLp2!vR4t"})
	require.NoError(t, err)
	limited, err := testCore.GetUserByEmail(ctx, "leasefaultlim@example.com")
	require.NoError(t, err)
	require.NoError(t, testCore.Storage().AssignRole(ctx, limited.ID, role.ID, core.Scope{ProjectID: projB.ID}))
	session, _, err := testCore.Login(ctx, &core.LoginRequest{Username: "leasefaultlim", Password: "Xk9#mQ7zLp2!vR4t"})
	require.NoError(t, err)
	limitedToken := session.SessionToken

	revoke := func(token, leaseID string) (*http.Response, string) {
		t.Helper()
		req, rerr := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/dynamic-secrets/leases/%s/revoke", server.URL, leaseID), nil)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, rerr := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		require.NoError(t, rerr)
		defer func() { _ = resp.Body.Close() }()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp, buf.String()
	}

	// The scope resolver is the first reader of the lease on these routes.
	arm := func() {
		faulty.Arm(&faultstorage.FaultSpec{Method: "GetDynamicSecretLease", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
	}

	t.Run("global holder: a lease-read fault is 503 storage_unavailable", func(t *testing.T) {
		arm()
		resp, body := revoke(adminToken, lease.LeaseID)
		require.True(t, faulty.Fired(), "the resolver's lease read must be reached")
		faulty.Arm(nil)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, body)
		assert.NotEmpty(t, resp.Header.Get("Retry-After"))
		var parsed struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &parsed))
		assert.Equal(t, "storage_unavailable", parsed.Error)
		assert.Equal(t, core.StorageReadUnavailableMessage, parsed.Message)
		assert.NotContains(t, body, assert.AnError.Error(), "the driver cause must not reach the client")

		var row models.DynamicSecretLease
		got, gerr := testCore.Storage().GetDynamicSecretLease(ctx, lease.LeaseID)
		require.NoError(t, gerr)
		row = *got
		assert.Equal(t, "active", row.Status, "the 503 means the revoke was not applied")
	})

	t.Run("caller without global standing: the 403 is unchanged", func(t *testing.T) {
		arm()
		respFault, bodyFault := revoke(limitedToken, lease.LeaseID)
		require.True(t, faulty.Fired())
		faulty.Arm(nil)
		respGone, bodyGone := revoke(limitedToken, "no-such-lease")
		assert.Equal(t, http.StatusForbidden, respFault.StatusCode, bodyFault)
		assert.Equal(t, http.StatusForbidden, respGone.StatusCode, bodyGone)
		assert.Equal(t, bodyGone, bodyFault, "a fault and an absent lease are one answer for a non-holder (no oracle)")
		assert.Empty(t, respFault.Header.Get("Retry-After"))
	})

	t.Run("a true not-found is still 404 for a global holder", func(t *testing.T) {
		resp, body := revoke(adminToken, "no-such-lease")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, body)
		assert.Empty(t, resp.Header.Get("Retry-After"))
	})

	t.Run("the retried revoke reaches the handler after the fault clears", func(t *testing.T) {
		resp, body := revoke(adminToken, lease.LeaseID)
		assert.NotEqual(t, http.StatusServiceUnavailable, resp.StatusCode, body)
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, body)
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, body)
	})
}
