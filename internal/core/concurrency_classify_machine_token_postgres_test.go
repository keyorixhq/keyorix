// concurrency_classify_machine_token_postgres_test.go — #2696.
//
// ClassifyMachineToken read a machine credential unlocked, set one field on the
// struct in memory, and persisted it with UpdateMachineIdentityCredential, a
// bare GORM Save of the WHOLE row. Every column the struct carried from that
// earlier read was written back, `revoked` included — so a RevokeMachineToken
// that committed on another replica in between was silently undone and the
// revoked (possibly leaked) token authenticated again, with nothing in the
// audit trail showing the un-revoke.
//
// This reuses the two-replica fixture in
// concurrency_check_then_act_exempt_review_postgres_test.go (same package):
// two independent *gorm.DB pools into one isolated Postgres schema, with a
// one-shot GORM callback on replica A's own connection choosing WHEN replica
// B's real, complete operation runs. The hook only picks the moment; both
// replicas run their genuine production entry points on their own connections.
// See that file's header for what the technique does and does not prove.
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_ClassifyMachineToken_vs_RevokeMachineToken_CrossReplicaPostgres
// asserts the EFFECT, not the return value: after an admin's revoke has
// returned success, the token must not authenticate. Asserting that
// ClassifyMachineToken returned an error would be the wrong contract — it is
// allowed to succeed or to fail closed, but it must never resurrect the
// credential.
func TestCTAReview_ClassifyMachineToken_vs_RevokeMachineToken_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)

	m, err := f.setup.CreateMachineIdentity(f.ctx, f.projectID, "ci-bot-2696", MachineTypeService, "", "", f.adminID, 0)
	require.NoError(t, err)
	issued, err := f.setup.IssueMachineToken(f.ctx, f.projectID, m.ID, f.adminID, IssueMachineTokenParams{Name: "tok-2696"})
	require.NoError(t, err)
	credID := issued.Credential.ID

	// Sanity: the token authenticates before anything races it, so a later
	// "revoked" verdict is the revoke's effect and not a broken fixture.
	_, _, _, _, err = f.coreA.ValidateMachineToken(f.ctx, issued.PlainToken)
	require.NoError(t, err, "the freshly issued token must authenticate before the race")

	// Replica B's admin revoke commits between A's unlocked read of the
	// credential and A's own UPDATE of it.
	var revokeErr error
	fired := f.beforeA("update", "machine_identity_credentials", func() {
		_, revokeErr = f.coreB.RevokeMachineToken(f.ctx, f.projectID, m.ID, credID, f.adminID)
	})

	// A's classify: a legitimate, authorized operation (roles.assign at the
	// project), reading a credential that was live at read time.
	_, classifyErr := f.coreA.ClassifyMachineToken(f.ctx, f.projectID, m.ID, credID, ClassificationRestricted, f.adminID)

	require.True(t, fired(), "replica A never reached its credential UPDATE — the interleaving under test never happened")
	require.NoError(t, revokeErr, "replica B's revoke must report success; the whole point is that it did")

	var persisted models.MachineIdentityCredential
	require.NoError(t, f.setupDB.First(&persisted, credID).Error)
	assert.True(t, persisted.Revoked,
		"a revoke that returned success must stay revoked: ClassifyMachineToken's write must not carry the stale revoked=false back (classify err: %v)", classifyErr)

	// The assertion that actually matters to an attacker holding the leaked
	// token: it must not authenticate any more.
	_, _, _, _, err = f.coreA.ValidateMachineToken(f.ctx, issued.PlainToken)
	require.Error(t, err, "the revoked token must not authenticate")
	assert.ErrorIs(t, err, ErrMachineTokenRevoked)
}
