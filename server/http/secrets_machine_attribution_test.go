// secrets_machine_attribution_test.go — coordinator follow-up on #2319 (W1,
// 2026-09-29): the isMachine split proven by secrets_machine_permission_test.go
// gets a machine caller PAST the userID==0 guard, but neither that file nor any
// other test asserted WHAT the resulting audit trail records the actor as. The
// mutation itself succeeding is not proof of correct attribution — a machine
// caller's UserID is 0 by construction (ADR-030), so a naive audit write would
// silently land as "user 0" (or, worse, a real user's ID if 0 were ever
// mistaken for "unknown") unless the machine-actor context tags
// (core.WithActorType/WithMachineActor, set by buildRequestContext) are
// correctly threaded through to emitAudit (service.go), which is the single
// choke point that stamps ActorType/MachineIdentityID and nils UserID for a
// machine-attributed event (ADR-092).
//
// This file drives the real HTTP router with a real, issued machine bearer
// token end-to-end (auth middleware -> buildRequestContext's context tagging
// -> route-scoped permission gate -> handler -> core -> emitAudit), then reads
// the persisted audit_events rows back and asserts the actor recorded there is
// the machine identity, never UserID 0. There is no separate "creator" column
// on SecretVersion itself (OwnerID/OwnerMachineIdentityID/CreatedBy on
// SecretNode are creation-time-only, see that struct's doc comments) — the
// audit_events row IS the durable per-mutation attribution record, so that is
// what this test verifies for update, delete, and rollback (rollback also
// writes a version, through RotateSecret, same as update).
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// machineAttributionFixture is machineSecretFixture's sibling: same shape (a
// real router, a real issued machine bearer token, project_developer granted
// at the secret's own project), but also returns the core service and the
// bootstrap admin's ID so the test can read back the audit trail afterward
// via ListSecretAuditEvents (which requires a caller with read access to the
// secret -- the admin, as its owner, always has that).
func machineAttributionFixture(t *testing.T) (srv *httptest.Server, token string, secretID uint, c *core.KeyorixCore, adminID, machineID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c = newFullSchemaTestCore(t)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	project := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "w1-attribution-target", Value: []byte("v1-initial"),
		ProjectID: project.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	mi, err := c.CreateMachineIdentity(ctx, project.ID, "w1-attribution-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, project.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "w1-attribution-token"})
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	var roleID uint
	for _, r := range roles {
		if r.Name == "project_developer" {
			roleID = r.ID
			break
		}
	}
	require.NotZero(t, roleID, "builtin role project_developer must exist")
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID, core.Scope{ProjectID: project.ID}, admin.ID, false))

	srv = newSecretsMachineTestServer(t, c)
	return srv, tok.PlainToken, secret.ID, c, admin.ID, mi.ID
}

// findAuditEvent returns the first (newest-first order, so effectively the
// most recent) event of eventType in events, or nil.
func findAuditEvent(events []*models.AuditEvent, eventType string) *models.AuditEvent {
	for _, e := range events {
		if e.EventType == eventType {
			return e
		}
	}
	return nil
}

// assertAttributedToMachine asserts ev records the given machine identity as
// actor -- ActorType stamped machine_identity, MachineIdentityID pointing at
// exactly that machine, and UserID nil (never a zero-value "user 0", which
// would be indistinguishable from a real user were a future user ID 0 ever
// possible, and is simply wrong regardless).
func assertAttributedToMachine(t *testing.T, ev *models.AuditEvent, eventType string, machineID uint) {
	t.Helper()
	if !assert.NotNil(t, ev, "expected a %q audit event to have been written", eventType) {
		return
	}
	assert.Equal(t, core.ActorTypeMachine, ev.ActorType, "%s: ActorType must be machine_identity, not default to user", eventType)
	if assert.NotNil(t, ev.MachineIdentityID, "%s: MachineIdentityID must be set for a machine-attributed event", eventType) {
		assert.Equal(t, machineID, *ev.MachineIdentityID, "%s: MachineIdentityID must name the acting machine", eventType)
	}
	assert.Nil(t, ev.UserID, "%s: UserID must be nil for a machine actor, never user 0", eventType)
}

// TestUpdateSecret_MachineActor_AuditAttributedToMachine drives the real HTTP
// UpdateSecret handler as an authorized machine principal and confirms the
// resulting secret.updated audit event is attributed to that machine, not to
// UserID 0 (updateReq.UserID is always 0 for a machine caller -- see
// secrets_crud.go's UpdateSecret comment -- so a naive read of that field
// alone would be wrong; the audit row's own attribution, stamped by
// core.emitAudit from the request's machine-actor context tag, is the
// authority here).
func TestUpdateSecret_MachineActor_AuditAttributedToMachine(t *testing.T) {
	srv, token, secretID, c, adminID, machineID := machineAttributionFixture(t)
	defer srv.Close()

	body, err := json.Marshal(map[string]any{"value": "v2-machine-updated"})
	require.NoError(t, err)
	status, respBody := doMachineRequest(t, srv, token, http.MethodPut, "/api/v1/secrets/"+strconv.FormatUint(uint64(secretID), 10), body)
	require.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to update: %s", respBody)

	core.DrainBackgroundGoroutines()

	events, err := c.ListSecretAuditEvents(context.Background(), secretID, adminID, 10)
	require.NoError(t, err)

	assertAttributedToMachine(t, findAuditEvent(events, "secret.updated"), "secret.updated", machineID)
}

// TestDeleteSecret_MachineActor_AuditAttributedToMachine is the delete
// counterpart: DeleteSecret's audit call (LogSecretDeletedWithProject) is
// passed userCtx.UserID (0) directly too, same shape as update.
func TestDeleteSecret_MachineActor_AuditAttributedToMachine(t *testing.T) {
	srv, token, secretID, c, _, machineID := machineAttributionFixture(t)
	defer srv.Close()

	status, respBody := doMachineRequest(t, srv, token, http.MethodDelete, "/api/v1/secrets/"+strconv.FormatUint(uint64(secretID), 10), nil)
	require.Equal(t, http.StatusNoContent, status, "machine with secrets.delete must be able to delete: %s", respBody)

	core.DrainBackgroundGoroutines()

	// DeleteSecret is a hard delete (core.DeleteSecret -> storage.DeleteSecret),
	// so the secret row is gone and ListSecretAuditEvents' own permission check
	// (EnforceSecretReadPermission, which needs to load the secret) would fail
	// with "not found" even for the admin -- read the persisted audit_events row
	// straight from storage instead, same table ListSecretAuditEvents queries,
	// just without the now-impossible permission check.
	events, _, err := c.Storage().GetAuditLogs(context.Background(), &storage.AuditFilter{SecretID: &secretID, PageSize: 10})
	require.NoError(t, err)

	assertAttributedToMachine(t, findAuditEvent(events, "secret.deleted"), "secret.deleted", machineID)
}

// TestRollbackSecret_MachineActor_AuditAttributedToMachine covers the third
// version-writing mutation the coordinator's review named explicitly:
// RollbackSecret calls RotateSecret (writing a new version) and then its own
// writeAuditEvent(EventSecretRolledBack, ...) with actorID passed straight
// through -- 0 for a machine caller -- so it shares update/delete's exact
// attribution shape and must be proven the same way.
func TestRollbackSecret_MachineActor_AuditAttributedToMachine(t *testing.T) {
	srv, token, secretID, c, adminID, machineID := machineAttributionFixture(t)
	defer srv.Close()

	path := "/api/v1/secrets/" + strconv.FormatUint(uint64(secretID), 10)

	// Rotate first so there is a version 2 to roll back FROM (rollback to the
	// current version is rejected as a no-op by core.RollbackSecret).
	rotateBody, err := json.Marshal(map[string]any{"new_value": "v2-rotated-before-rollback"})
	require.NoError(t, err)
	status, respBody := doMachineRequest(t, srv, token, http.MethodPost, path+"/rotate", rotateBody)
	require.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to rotate: %s", respBody)

	rollbackBody, err := json.Marshal(map[string]any{"version": 1})
	require.NoError(t, err)
	status, respBody = doMachineRequest(t, srv, token, http.MethodPost, path+"/rollback", rollbackBody)
	require.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to roll back: %s", respBody)

	core.DrainBackgroundGoroutines()

	events, err := c.ListSecretAuditEvents(context.Background(), secretID, adminID, 10)
	require.NoError(t, err)

	assertAttributedToMachine(t, findAuditEvent(events, core.EventSecretRolledBack), core.EventSecretRolledBack, machineID)
}
