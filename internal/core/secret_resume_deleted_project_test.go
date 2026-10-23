package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #2794, project half: the sibling of TestResumeSecret_RefusedInDeletedEnvironment. A
// suspended secret does not block a forced project delete, and ResumeSecret then flipped
// it to active inside the deleted project. The Postgres cross-replica twin is
// TestCTAReview_ResumeSecret_vs_DeleteProject_CrossReplicaPostgres; this one needs no
// database server, so it also runs in the default suite.
func TestResumeSecret_RefusedInDeletedProject(t *testing.T) {
	ctx := context.Background()
	c, projectID, _, secretID := newResumeLiveParentFixture(t)
	// The storage-level delete: the core DeleteProject also sweeps machine identities,
	// which this fixture does not migrate, and the cascade is the part under test.
	require.NoError(t, c.storage.DeleteProject(ctx, projectID), "the project delete cascades over its suspended secret")

	_, err := c.ResumeSecret(ctx, secretID, 1)
	require.Error(t, err, "resume must refuse while the parent project is deleted")

	got, gerr := c.storage.GetSecret(ctx, secretID)
	if gerr == nil {
		assert.Equal(t, SecretStatusSuspended, got.Status, "the secret must not become active under a deleted project")
	}
}
