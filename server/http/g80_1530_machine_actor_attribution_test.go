// g80_1530_machine_actor_attribution_test.go — closes #1530: a security-relevant
// mutation reachable by a machine identity produced an audit event correctly
// tagged ActorType="machine_identity" but with no field to say WHICH machine
// (UserID is nil for every machine caller, by construction -- machine tokens
// carry no human user ID). The audit model had no field that could hold a
// machine-identity actor; MachineIdentityID (internal/storage/models/models.go)
// is that field. Reproduces the exact triage repro: a MachineTypeService
// identity (deliberately non-node, since the underlying gap was never
// node-specific) holding only system.write creates a group and the resulting
// audit event must record which machine did it.
package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
)

func TestG80_1530_MachineActorAttribution_NonNodeServiceIdentity(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, testCore)
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)

	mi, err := testCore.CreateMachineIdentity(ctx, projects[0].ID, "attribution-probe-service", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)

	g801530SystemWriterName, err := identity.NewFoldedName("g80_1530_system_writer")
	require.NoError(t, err)
	role, err := testCore.Storage().CreateRole(ctx, g801530SystemWriterName, "")
	require.NoError(t, err)
	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID uint
	for _, p := range perms {
		if p.Name == "system.write" {
			systemWriteID = p.ID
		}
	}
	require.NotZero(t, systemWriteID)
	require.NoError(t, testCore.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID, false))
	require.NoError(t, testCore.Storage().AssignMachineRole(ctx, mi.ID, role.ID, coreStorage.Scope{}))

	result, err := testCore.IssueMachineToken(ctx, projects[0].ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "g80-1530-probe-token"})
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/system/groups",
		bytes.NewReader([]byte(`{"name":"g80-1530-attribution-probe"}`)))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+result.PlainToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a system.write-holding service machine identity must reach this route")

	action := string(core.EventGroupCreated)
	logs, _, err := testCore.Storage().GetAuditLogs(ctx, &coreStorage.AuditFilter{Action: &action})
	require.NoError(t, err)
	require.NotEmpty(t, logs, "the create must have produced an audit event")
	last := logs[len(logs)-1]

	require.Equal(t, core.ActorTypeMachine, last.ActorType, "sanity: this event must be actor-typed as a machine")
	require.Nil(t, last.UserID, "sanity: UserID must still be nil for a machine caller -- confirms this isn't accidentally attributing to a human field")
	require.NotNil(t, last.MachineIdentityID,
		"CEILING VIOLATED: a security-relevant mutation by a machine identity produced an audit event "+
			"with no record of WHICH machine acted -- ActorType said 'a machine did this' but nothing said which one")
	require.Equal(t, mi.ID, *last.MachineIdentityID, "the attributed machine identity must be the one that actually made the call, not an arbitrary non-nil value")
}
