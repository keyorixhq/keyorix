package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #4657, the siblings of TestSuspendProjectSecrets_ProjectGate: core decides the
// route gate of resume-all, extend-expiring and bulk-rename (secrets.write at the
// project) before any secret is read or written. A project viewer holding a
// per-secret ACL write passes the per-secret re-check on that secret but not the
// project gate, so the whole request is refused: nothing changes and no audit row
// is written. A project developer and the bootstrap admin, who hold
// secrets.write@project, still succeed.

// projectGateWorld is a project with a developer (secrets.write@project), a viewer
// (project_viewer) and two developer-owned secrets; the viewer holds an ACL
// secrets.write on aclGranted only.
type projectGateWorld struct {
	c                 *KeyorixCore
	st                *store.LocalStorage
	projectID         uint
	developer, viewer *models.User
	aclGranted, other *models.SecretNode
	admin             *models.User
}

func newProjectGateWorld(t *testing.T, name string, status string, expiration *time.Time) *projectGateWorld {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	proj, err := st.CreateProject(ctx, &models.Project{Name: "bulk-gate-" + name})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	assign := func(login, roleName string) *models.User {
		u, err := st.CreateUser(ctx, foldedTestUser(t, login, login+"@example.com"))
		require.NoError(t, err)
		role, err := st.GetRoleByName(ctx, roleName)
		require.NoError(t, err)
		require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, storage.Scope{ProjectID: proj.ID}))
		return u
	}
	w := &projectGateWorld{c: c, st: st, projectID: proj.ID}
	w.developer = assign("bulk-gate-dev-"+name, "project_developer")
	w.viewer = assign("bulk-gate-viewer-"+name, "project_viewer")
	mk := func(secretName string) *models.SecretNode {
		s, err := st.CreateSecret(ctx, &models.SecretNode{
			Name: secretName, ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
			IsSecret: true, OwnerID: w.developer.ID, Status: status, Expiration: expiration,
		})
		require.NoError(t, err)
		return s
	}
	w.aclGranted = mk("acl-granted")
	w.other = mk("other")
	require.NoError(t, st.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
		SecretID: w.aclGranted.ID, UserID: w.viewer.ID, Permissions: `["secrets.read","secrets.write"]`, GrantedBy: w.developer.ID,
	}))
	w.admin, err = st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	return w
}

func (w *projectGateWorld) stored(t *testing.T, id uint) *models.SecretNode {
	t.Helper()
	s, err := w.st.GetSecret(context.Background(), id)
	require.NoError(t, err)
	return s
}

func (w *projectGateWorld) auditRows(t *testing.T, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.st.DB().Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

// requirePerSecretPass is the precondition that makes each refusal below the
// project gate's: the op's own per-secret re-check alone admits the viewer on
// aclGranted (same actions as the op passes to enforceSecretWriteGate).
func (w *projectGateWorld) requirePerSecretPass(t *testing.T, checkAction, gateAction SecretAction) {
	t.Helper()
	require.NoError(t, w.c.enforceSecretWriteGate(context.Background(), w.aclGranted.ID, w.viewer.ID, checkAction, gateAction),
		"precondition: the per-secret ACL write passes the per-secret re-check")
}

func TestResumeProjectSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newProjectGateWorld(t, "resume", SecretStatusSuspended, nil)
	w.requirePerSecretPass(t, SecretActionResume, SecretActionResume)

	n, err := w.c.ResumeProjectSecrets(ctx, w.projectID, w.viewer.ID)
	require.ErrorIs(t, err, ErrPermissionDenied, "a per-secret ACL write is not secrets.write@project")
	require.Zero(t, n)
	for _, s := range []*models.SecretNode{w.aclGranted, w.other} {
		require.Equal(t, SecretStatusSuspended, w.stored(t, s.ID).Status, "%s: nothing is resumed", s.Name)
	}
	require.Zero(t, w.auditRows(t, "secret.bulk_resume_attempted"), "a refused request writes no bulk row")
	require.Zero(t, w.auditRows(t, EventSecretResumed), "and no per-secret row")

	n, err = w.c.ResumeProjectSecrets(ctx, w.projectID, w.developer.ID)
	require.NoError(t, err)
	require.Equal(t, 2, n, "the developer resumes both secrets")

	_, err = w.c.SuspendProjectSecrets(ctx, w.projectID, w.admin.ID, "re-suspend")
	require.NoError(t, err)
	n, err = w.c.ResumeProjectSecrets(ctx, w.projectID, w.admin.ID)
	require.NoError(t, err)
	require.Equal(t, 2, n, "the admin resumes both secrets")
}

func TestExtendExpiringSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	soon := time.Now().UTC().Add(5 * 24 * time.Hour)
	w := newProjectGateWorld(t, "extend", SecretStatusActive, &soon)
	w.requirePerSecretPass(t, SecretActionUpdateLifecycle, SecretActionUpdateLifecycle)
	expiry := func(id uint) time.Time {
		e := w.stored(t, id).Expiration
		require.NotNil(t, e)
		return e.UTC()
	}
	before := map[uint]time.Time{w.aclGranted.ID: expiry(w.aclGranted.ID), w.other.ID: expiry(w.other.ID)}

	n, _, err := w.c.ExtendExpiringSecrets(ctx, w.projectID, 30, 60, w.viewer.Username, w.viewer.ID)
	require.ErrorIs(t, err, ErrPermissionDenied, "a per-secret ACL write is not secrets.write@project")
	require.Zero(t, n)
	for id, was := range before {
		require.True(t, expiry(id).Equal(was), "secret %d: nothing is extended", id)
	}
	require.Zero(t, w.auditRows(t, "secret.bulk_extend_expiring_attempted"), "a refused request writes no bulk row")
	require.Zero(t, w.auditRows(t, evtSecretUpdated), "and no per-secret row")

	n, _, err = w.c.ExtendExpiringSecrets(ctx, w.projectID, 30, 60, w.developer.Username, w.developer.ID)
	require.NoError(t, err)
	require.Equal(t, 2, n, "the developer extends both secrets")
	n, _, err = w.c.ExtendExpiringSecrets(ctx, w.projectID, 365, 365, w.admin.Username, w.admin.ID)
	require.NoError(t, err)
	require.Equal(t, 2, n, "the admin extends both secrets")
}

func TestBulkRenameSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newProjectGateWorld(t, "rename", SecretStatusActive, nil)
	w.requirePerSecretPass(t, "", SecretActionUpdateMetadata)
	renames := func(suffix string) []SecretRename {
		return []SecretRename{{ID: w.aclGranted.ID, NewName: "acl-granted-" + suffix}, {ID: w.other.ID, NewName: "other-" + suffix}}
	}

	for _, dryRun := range []bool{true, false} {
		report, err := w.c.BulkRenameSecrets(ctx, w.projectID, renames("viewer"), dryRun, w.viewer.Username, w.viewer.ID, "127.0.0.1", "test")
		require.ErrorIs(t, err, ErrPermissionDenied, "dry_run=%v: a per-secret ACL write is not secrets.write@project", dryRun)
		require.Nil(t, report, "dry_run=%v: a refused request reports no outcomes", dryRun)
	}
	require.Equal(t, "acl-granted", w.stored(t, w.aclGranted.ID).Name, "nothing is renamed")
	require.Equal(t, "other", w.stored(t, w.other.ID).Name, "nothing is renamed")
	require.Zero(t, w.auditRows(t, evtSecretUpdated), "a refused request writes no per-secret row")

	report, err := w.c.BulkRenameSecrets(ctx, w.projectID, renames("dev"), false, w.developer.Username, w.developer.ID, "127.0.0.1", "test")
	require.NoError(t, err)
	require.Equal(t, 2, report.Renamed, "the developer renames both secrets")
	report, err = w.c.BulkRenameSecrets(ctx, w.projectID, renames("admin"), false, w.admin.Username, w.admin.ID, "127.0.0.1", "test")
	require.NoError(t, err)
	require.Equal(t, 2, report.Renamed, "the admin renames both secrets")
}
