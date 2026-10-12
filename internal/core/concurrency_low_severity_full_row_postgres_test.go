// concurrency_low_severity_full_row_postgres_test.go — #2700.
//
// The three remaining bare-GORM-Save writers from C-GUARD-3 guard 1, batched
// because the shape is identical and the impact is lower than #2695/#2697's.
// Four subtests, one per distinct consequence:
//
//  1. UpdateRotationPolicy after DeleteRotationPolicy. RotationPolicy IS
//     soft-deletable, so Save's 0-rows upsert fallback writes deleted_at=NULL:
//     the policy comes back ACTIVE and resumes driving rotation and breach
//     alerts, although the delete reported success.
//  2. UpdateRotationPolicy after the executor stamped rotation_state=failed.
//     The full-row write reverts it to the stale value, hiding a failed
//     rotation from the posture view that reads it.
//  3. UpdateSecretTemplate after DeleteSecretTemplate. SecretTemplate is
//     HARD-deleted (no DeletedAt), so the upsert fallback re-INSERTS the row
//     with its old ID. Integrity only — a template mints nothing by itself.
//  4. markWebAuthnCredentialClonedDisabled after the user deleted the passkey.
//     Also a hard delete, so the credential row is re-inserted — with
//     Disabled=true, so it fails closed for authentication. What it corrupts is
//     the credential count and the webauthn_enabled bookkeeping derived from it.
//
// Severity is genuinely low for 3 and 4 and that is stated rather than inflated:
// neither re-grants access. 1 is the one with real operational weight — a
// deleted rotation policy coming back active.
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

func TestCTAReview_UpdateRotationPolicy_vs_DeleteRotationPolicy_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	pol, err := f.setup.CreateRotationPolicy(f.ctx, f.adminID, &CreateRotationPolicyRequest{
		Name: "pol-2700-del", Scope: "project", ProjectID: &f.projectID,
		IntervalDays: 30, AlertDaysBefore: 7, CreatedBy: "admin",
	})
	require.NoError(t, err)

	var delErr error
	fired := f.beforeA("update", "rotation_policies", func() {
		delErr = f.coreB.DeleteRotationPolicy(f.ctx, f.adminID, pol.ID)
	})

	_, upErr := f.coreA.UpdateRotationPolicy(f.ctx, f.adminID, &UpdateRotationPolicyRequest{
		ID: pol.ID, Name: "pol-2700-renamed", IntervalDays: 30, AlertDaysBefore: 7, IsActive: true,
	})

	require.True(t, fired(), "replica A never reached its rotation_policies UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	assert.Zero(t, f.countLive(&models.RotationPolicy{}, "id = ? AND deleted_at IS NULL", pol.ID),
		"a delete that returned success must stay deleted: the policy must not come back live and resume driving rotation (update err: %v)", upErr)
}

func TestCTAReview_UpdateRotationPolicy_vs_RotationStateFailed_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	pol, err := f.setup.CreateRotationPolicy(f.ctx, f.adminID, &CreateRotationPolicyRequest{
		Name: "pol-2700-state", Scope: "project", ProjectID: &f.projectID,
		IntervalDays: 30, AlertDaysBefore: 7, CreatedBy: "admin",
	})
	require.NoError(t, err)

	// Replica B is the rotation executor recording that a rotation failed.
	var stampErr error
	fired := f.beforeA("update", "rotation_policies", func() {
		stampErr = f.coreB.Storage().UpdateRotationState(f.ctx, pol.ID, "failed", "backend refused")
	})

	_, upErr := f.coreA.UpdateRotationPolicy(f.ctx, f.adminID, &UpdateRotationPolicyRequest{
		ID: pol.ID, Name: "pol-2700-state", Description: "an edit", IntervalDays: 30, AlertDaysBefore: 7, IsActive: true,
	})

	require.True(t, fired(), "replica A never reached its rotation_policies UPDATE — the interleaving under test never happened")
	require.NoError(t, stampErr, "the executor's state stamp must report success; the whole point is that it did")

	var persisted models.RotationPolicy
	require.NoError(t, f.setupDB.First(&persisted, pol.ID).Error)
	assert.Equal(t, "failed", persisted.RotationState,
		"an ordinary policy edit must not revert the executor's recorded failure — that hides a failed rotation (update err: %v)", upErr)
	assert.Equal(t, "backend refused", persisted.LastRotationError,
		"the recorded failure reason must survive too")
}

func TestCTAReview_UpdateSecretTemplate_vs_DeleteSecretTemplate_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	tmpl, err := f.setup.CreateSecretTemplate(f.ctx, &CreateSecretTemplateRequest{
		Name: "tmpl-2700", Description: "d", CreatedBy: f.adminID,
	})
	require.NoError(t, err)

	var delErr error
	fired := f.beforeA("update", "secret_templates", func() {
		delErr = f.coreB.DeleteSecretTemplate(f.ctx, tmpl.ID)
	})

	_, upErr := f.coreA.UpdateSecretTemplate(f.ctx, tmpl.ID, &UpdateSecretTemplateRequest{
		Name: "tmpl-2700-renamed", Description: "d2",
	})

	require.True(t, fired(), "replica A never reached its secret_templates UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	// Hard delete, so the row must simply be absent — Unscoped counts every row.
	assert.Zero(t, f.countLive(&models.SecretTemplate{}, "id = ?", tmpl.ID),
		"a hard delete that returned success must stay deleted: the update's upsert fallback must not re-insert the template (update err: %v)", upErr)
}

func TestCTAReview_MarkWebAuthnCloned_vs_DeleteCredential_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("wa2700", "")
	cred := &models.WebAuthnCredential{
		UserID: u.ID, CredentialID: []byte("cred-2700"), Name: "YubiKey",
		CredentialBlob: []byte(`{"Authenticator":{"SignCount":5}}`),
	}
	require.NoError(t, f.setupDB.Create(cred).Error)

	var delErr error
	fired := f.beforeA("update", "web_authn_credentials", func() {
		delErr = f.coreB.Storage().DeleteWebAuthnCredential(f.ctx, u.ID, cred.ID)
	})

	// Replica A's clone-signal disable, reached through the real production entry
	// point (it is unexported, so called directly — same package).
	upErr := f.coreA.markWebAuthnCredentialClonedDisabled(f.ctx, cred, "203.0.113.5")

	require.True(t, fired(), "replica A never reached its web_authn_credentials UPDATE — the interleaving under test never happened")
	require.NoError(t, delErr, "replica B's delete must report success; the whole point is that it did")

	assert.Zero(t, f.countLive(&models.WebAuthnCredential{}, "id = ?", cred.ID),
		"a hard delete that returned success must stay deleted: the disable's upsert fallback must not re-insert the passkey row, "+
			"which corrupts the credential count and the webauthn_enabled bookkeeping derived from it (update err: %v)", upErr)
}
