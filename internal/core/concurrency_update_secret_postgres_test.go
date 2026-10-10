// concurrency_update_secret_postgres_test.go — #2695.
//
// LocalStorage.UpdateSecret was a bare GORM Save(...) of a struct the caller had
// read earlier, unlocked — and it was the SHARED primitive for eight distinct
// operations, so every one of them inherited both of its defects at once. Three
// subtests, chosen to cover both defects across different callers rather than
// one caller three ways:
//
//  1. RESURRECTION. ClassifySecret landing after DeleteSecret brings the secret
//     back. DeleteSecret also revokes the secret's shares and ACLs, so it comes
//     back WITHOUT them, with no secret.restored audit event and without going
//     through RestoreSecret — a live secret value nobody can see in the restore
//     UI and that the purge will never reclaim.
//  2. LOST UPDATE on an incident freeze. A rename (BulkRenameSecrets) whose read
//     predated SuspendSecret writes status=active back, un-freezing a secret an
//     operator had just frozen.
//  3. LOST UPDATE on ownership offboarding. SetSecretDescription whose read
//     predated ClearProjectSecretOwnership writes the old owner_id back, handing
//     the owner short-circuit to a departed user.
//
// Each uses a DIFFERENT one of the eight callers on purpose: the point of the
// issue is that the defect lived in the primitive, so demonstrating it through
// three callers is the evidence that it is not a per-call-site slip.
//
// Reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package);
// see that file's header for what the GORM-callback interleaving technique
// does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCTAReview_ClassifySecret_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("sec2695-owner", "project_admin")
	s := f.secret("sec-2695-classify", owner.ID)

	var delErr error
	fired := f.beforeA("update", "secret_nodes", func() {
		delErr = f.coreB.DeleteSecret(f.ctx, s.ID)
	})

	_, classifyErr := f.coreA.ClassifySecret(f.ctx, f.adminID, "admin", s.ID, ClassificationRestricted)

	require.True(t, fired(), "replica A never reached its secret_nodes UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	assert.Equal(t, int64(1), f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NOT NULL", s.ID),
		"a delete that returned success must stay deleted: ClassifySecret must not resurrect the secret (classify err: %v)", classifyErr)
	// A resurrected secret is a live secret VALUE outside every restore and purge
	// path, so assert the row is actually gone from the live set, not just that
	// deleted_at is set somewhere.
	assert.Zero(t, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NULL", s.ID),
		"no live secret row may exist for a secret whose shares and ACLs have already been revoked")
}

func TestCTAReview_BulkRenameSecrets_vs_SuspendSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("sec2695-rename-owner", "project_admin")
	s := f.secret("sec-2695-rename", owner.ID)

	var suspendErr error
	fired := f.beforeA("update", "secret_nodes", func() {
		_, suspendErr = f.coreB.SuspendSecret(f.ctx, s.ID, f.adminID, "incident")
	})

	_, renameErr := f.coreA.BulkRenameSecrets(f.ctx, f.projectID,
		[]SecretRename{{ID: s.ID, NewName: "sec-2695-renamed"}}, false, "admin", f.adminID, "", "")

	require.True(t, fired(), "replica A never reached its secret_nodes UPDATE — the interleaving under test never happened")
	require.NoError(t, suspendErr, "replica B's suspend must report success; the whole point is that it did")

	var persisted models.SecretNode
	require.NoError(t, f.setupDB.First(&persisted, s.ID).Error)
	assert.Equal(t, SecretStatusSuspended, persisted.Status,
		"a suspend that returned success must stay suspended: a rename must not write status=active back (rename err: %v)", renameErr)
}

func TestCTAReview_SetSecretDescription_vs_ClearOwnership_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("sec2695-offboard", "project_admin")
	s := f.secret("sec-2695-owner", owner.ID)
	require.NotZero(t, s.OwnerID)

	var clearErr error
	fired := f.beforeA("update", "secret_nodes", func() {
		clearErr = f.coreB.Storage().ClearProjectSecretOwnership(f.ctx, owner.ID, f.projectID)
	})

	_, descErr := f.coreA.SetSecretDescription(f.ctx, f.adminID, s.ID, "a note")

	require.True(t, fired(), "replica A never reached its secret_nodes UPDATE — the interleaving under test never happened")
	require.NoError(t, clearErr, "replica B's ownership clear must report success; the whole point is that it did")

	var persisted models.SecretNode
	require.NoError(t, f.setupDB.First(&persisted, s.ID).Error)
	assert.Zero(t, persisted.OwnerID,
		"an offboarding ownership clear that returned success must hold: a description edit must not write the old owner_id back, "+
			"which would hand the departed user the owner short-circuit again (description err: %v)", descErr)
}
