package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #4666, the last two siblings of TestSuspendProjectSecrets_ProjectGate: core decides
// the route gate of bulk-rotate (secrets.write at the project) and bulk-delete
// (secrets.delete at the project) before any secret is read. A grant that admits the
// caller on one secret (a per-secret ACL write for rotate, a role held only in the
// secret's environment for delete) is not the project gate, so the whole request is
// refused and nothing changes. A project developer, the bootstrap admin and the
// internal pseudo-actor 0 still succeed.

func (w *projectGateWorld) versions(t *testing.T, id uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.st.DB().Model(&models.SecretVersion{}).Where("secret_node_id = ?", id).Count(&n).Error)
	return n
}

func TestBulkRotateSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newProjectGateWorld(t, "rotate", SecretStatusActive, nil)
	ids := []uint{w.aclGranted.ID, w.other.ID}
	require.NoError(t, w.st.DB().Model(&models.SecretNode{}).Where("id IN ?", ids).
		Updates(map[string]any{"auto_rotate": true, "rotation_length": 20}).Error)
	// Precondition: the per-secret rotate gate alone admits the viewer on aclGranted.
	require.NoError(t, w.c.requireSecretActionGate(ctx, w.viewer.ID, w.stored(t, w.aclGranted.ID), permSecretsWrite, SecretActionRotate),
		"precondition: the per-secret ACL write passes the per-secret rotate gate")
	before := map[uint]int64{}
	for _, id := range ids {
		before[id] = w.versions(t, id)
	}

	for _, req := range []BulkRotateRequest{
		{ProjectID: w.projectID, SecretIDs: ids, RotatedBy: w.viewer.Username},
		{ProjectID: w.projectID, RotatedBy: w.viewer.Username}, // project-wide
	} {
		res, err := w.c.BulkRotateSecrets(ctx, w.viewer.ID, req)
		require.ErrorIs(t, err, ErrPermissionDenied, "explicit=%v: a per-secret ACL write is not secrets.write@project", len(req.SecretIDs) > 0)
		require.Nil(t, res)
	}
	for id, was := range before {
		require.Equal(t, was, w.versions(t, id), "secret %d: nothing is rotated", id)
	}
	require.Zero(t, w.auditRows(t, "secret.bulk_rotate_attempted"), "a refused request writes no bulk row")

	for _, actor := range []struct {
		name string
		id   uint
	}{{"developer", w.developer.ID}, {"admin", w.admin.ID}, {"pseudo-actor 0", 0}} {
		res, err := w.c.BulkRotateSecrets(ctx, actor.id, BulkRotateRequest{ProjectID: w.projectID, SecretIDs: ids, RotatedBy: actor.name})
		require.NoError(t, err, actor.name)
		require.ElementsMatch(t, ids, res.Triggered, "%s rotates both secrets", actor.name)
	}
}

func TestBulkDeleteSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	w := newProjectGateWorld(t, "delete", SecretStatusActive, nil)
	envID := w.aclGranted.EnvironmentID
	envDev, err := w.st.CreateUser(ctx, foldedTestUser(t, "bulk-gate-envdev-delete", "bulk-gate-envdev-delete@example.com"))
	require.NoError(t, err)
	role, err := w.st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, w.st.AssignRole(ctx, envDev.ID, role.ID, storage.Scope{ProjectID: w.projectID, EnvironmentID: envID}))
	// Precondition: the per-item checks alone admit the environment developer (role
	// at the secret's {project, environment}); the project gate does not.
	for _, perm := range []string{permSecretsRead, permSecretsDelete} {
		ok, err := w.c.AuthorizePrincipal(ctx, ActorTypeUser, envDev.ID, perm, Scope{ProjectID: w.projectID, EnvironmentID: envID})
		require.NoError(t, err)
		require.True(t, ok, "precondition: %s held in the secret's environment", perm)
	}
	ok, err := w.c.AuthorizePrincipal(ctx, ActorTypeUser, envDev.ID, permSecretsDelete, Scope{ProjectID: w.projectID})
	require.NoError(t, err)
	require.False(t, ok, "precondition: secrets.delete is not held at the project")

	res, err := w.c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{w.aclGranted.ID}}, w.projectID, envDev.Username, envDev.ID, "127.0.0.1", "test")
	require.ErrorIs(t, err, ErrPermissionDenied, "an environment-scoped secrets.delete is not secrets.delete@project")
	require.Nil(t, res)
	w.stored(t, w.aclGranted.ID) // still there
	require.Zero(t, w.auditRows(t, "secret.deleted"), "a refused request writes no per-secret row")

	res, err = w.c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{w.aclGranted.ID}}, w.projectID, w.developer.Username, w.developer.ID, "127.0.0.1", "test")
	require.NoError(t, err)
	require.Equal(t, []uint{w.aclGranted.ID}, res.Deleted, "the developer deletes")
	res, err = w.c.BulkDeleteSecrets(ctx, BulkDeleteRequest{SecretIDs: []uint{w.other.ID}}, w.projectID, "local", 0, "127.0.0.1", "test")
	require.NoError(t, err)
	require.Equal(t, []uint{w.other.ID}, res.Deleted, "the internal pseudo-actor 0 deletes, unchanged")
}
