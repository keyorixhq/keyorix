package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #2794, project half: the sibling of TestResumeSecret_RefusedInDeletedEnvironment. It
// pins the LockLiveProject re-read in ResumeSecret. A sequential DeleteProject cascades
// over the suspended secret too, so ResumeSecret would fail at GetSecret before any
// project check; the state the re-read exists for is the losing cross-replica
// interleaving, where the project row is already soft-deleted but the secret row is
// still readable. This test builds that state directly by soft-deleting only the project
// row. The real interleaving is TestCTAReview_ResumeSecret_vs_DeleteProject_CrossReplicaPostgres
// (pg-gated).
func TestResumeSecret_RefusedInDeletedProject(t *testing.T) {
	ctx := context.Background()
	c, projectID, _, secretID := newResumeLiveParentFixture(t)
	ls, ok := c.storage.(*store.LocalStorage)
	require.True(t, ok)
	require.NoError(t, ls.DB().Model(&models.Project{}).Where("id = ?", projectID).
		Update("deleted_at", time.Now().UTC()).Error, "soft-delete only the project row")

	_, err := c.ResumeSecret(ctx, secretID, 1)
	require.Error(t, err, "resume must refuse while the parent project is deleted")
	assert.ErrorIs(t, err, storage.ErrProjectNotFound, "the project re-read must refuse")

	got, gerr := c.storage.GetSecret(ctx, secretID)
	require.NoError(t, gerr, "only the project row is deleted, the secret row stays readable")
	assert.Equal(t, SecretStatusSuspended, got.Status, "the secret must not become active under a deleted project")
}
