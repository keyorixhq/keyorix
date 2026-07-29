package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedClassificationGateFixture creates a project, a requester (owner of the
// secret and project viewer, so ValidateSecretAccess passes the owner + live-
// membership check introduced in #1205/RBAC-001), an admin approver, and a
// secret at the given classification with one version.
func seedClassificationGateFixture(t *testing.T, st *store.LocalStorage, classification string) (secretID, requesterID, approverID, projectID uint) {
	t.Helper()
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "classification-gate-" + classification + "-test"})
	require.NoError(t, err)

	requester, err := st.CreateUser(ctx, &models.User{Username: "requester-" + classification, Email: "requester-" + classification + "@example.com", IsActive: true})
	require.NoError(t, err)

	// Assign the requester a project-scoped viewer role so IsProjectMember
	// (added as an owner-bypass gate in #1205) returns true. Without this the
	// owner shortcut in CheckSecretPermission falls through to "permission denied".
	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, requester.ID, viewerRole.ID, storage.Scope{ProjectID: proj.ID}))

	approver, err := st.CreateUser(ctx, &models.User{Username: "approver-" + classification, Email: "approver-" + classification + "@example.com", IsActive: true})
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, adminRole.ID, storage.Scope{}))
	// IsProjectMember (RBAC-001): requester must be a project member or the owner
	// gate short-circuits before returning PermissionOwner.
	viewerRole, err = st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, requester.ID, viewerRole.ID, storage.Scope{ProjectID: proj.ID}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: requester.ID, Status: "active", Classification: classification,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t-value"),
	})
	require.NoError(t, err)

	return secret.ID, requester.ID, approver.ID, proj.ID
}

// Requirement (1): the setting defaults to false, so a "restricted" secret reads
// exactly like any other, for both a permission-checked user read and a direct
// (machine-shaped) read with no user ID at all.
func TestClassificationGate_OffByDefault_RestrictedSecretUnaffected(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	// c.classificationRestrictedRequiresApproval is the zero value (false) —
	// never touched in this test, pinning the true out-of-the-box default.
	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err, "restricted must read like any other secret while the gate is off")
	assert.Equal(t, "s3cr3t-value", string(val))

	// Machine-shaped direct read (no user ID) is likewise unaffected.
	val, err = c.GetSecretValue(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))

	// Metadata reads were never gated and stay that way.
	secret, err := c.GetSecret(ctx, secretID)
	require.NoError(t, err)
	assert.Equal(t, ClassificationRestricted, secret.Classification)
}

// Requirement (2): with the setting on, an unapproved read of a restricted
// secret is denied — even for a user who otherwise has full (owner) read rights.
func TestClassificationGate_OnAndUnapproved_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), "approved access request")
}

// Requirement (2)/machine consideration: a read with no identifiable user (the
// same shape server/http uses for a machine-principal read, or the embedded
// CLI) must be denied too — fail-closed, no silent bypass for automation.
func TestClassificationGate_OnAndNoUser_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err, "a read with no identifiable user must be denied, not silently allowed")
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement (3): with an approved, valid AccessRequest scoped to that secret,
// the read succeeds.
func TestClassificationGate_OnAndApproved_Succeeds(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)

	// Sanity: unapproved is still denied at this point.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.Error(t, err)

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "need it for an incident")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestPending, req.State)
	require.NotNil(t, req.SecretID)
	assert.Equal(t, secretID, *req.SecretID)

	approved, err := c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, approved.State)
	// No role is granted for a secret-scoped request.
	assert.Empty(t, approved.GrantedRole)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
	require.NoError(t, err, "an approved, secret-scoped access request must let the read through")
	assert.Equal(t, "s3cr3t-value", string(val))

	// By-version read is gated (and unblocked) the same way.
	val, err = c.GetSecretValueByVersionWithPermissionCheck(ctx, secretID, requesterID, 1)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement (4): a lower-tier classified secret is never gated, regardless of
// the setting.
func TestClassificationGate_LowerTierNeverGated(t *testing.T) {
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		level := level
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, requesterID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresApproval(true)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, requesterID)
			require.NoError(t, err, "only the highest tier is gated")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// ApproveSecretAccessRequest's own guards: maker != checker, admin-authority
// ceiling, pending-only, and refusing a project/role (SecretID nil) request.
func TestApproveSecretAccessRequest_Guards(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	req, err := c.RequestSecretAccess(ctx, secretID, requesterID, "")
	require.NoError(t, err)

	// Maker != checker.
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, requesterID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot approve their own")

	// A non-admin approver is refused.
	nonAdmin, err := st.CreateUser(ctx, &models.User{Username: "nonadmin", Email: "nonadmin@example.com", IsActive: true})
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, nonAdmin.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "administrator")

	// A project/role (SecretID nil) request is refused by this function.
	roleReq, err := c.RequestProjectAccess(ctx, projectID, requesterID, "viewer", "")
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, roleReq.ID, approverID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a secret-scoped")

	// The real approval succeeds and is idempotent-refusing on a second attempt.
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, req.ID, approverID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
}

// ── restricted_requires_permission tests ─────────────────────────────────────

// seedRestrictedPermissionFixture extends the base fixture with a second user who
// owns a restricted secret and holds an explicit secrets.read.restricted grant at
// the project scope — used to verify that the explicit-grant path allows reads.
func seedRestrictedPermissionFixture(t *testing.T, st *store.LocalStorage) (secretID, ownerID, grantedUserID, projectID uint) {
	t.Helper()
	ctx := context.Background()

	secretID, ownerID, _, projectID = seedClassificationGateFixture(t, st, ClassificationRestricted)

	// Create a role with secrets.read.restricted and assign it to grantedUser at
	// the project scope. The user also needs to pass ValidateSecretAccess, so we
	// share the secret with them at read level.
	perm, err := st.CreatePermission(ctx, &models.Permission{Name: PermSecretReadRestricted})
	require.NoError(t, err)

	role, err := st.CreateRole(ctx, &models.Role{Name: "restricted-reader"})
	require.NoError(t, err)

	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))

	grantedUser, err := st.CreateUser(ctx, &models.User{Username: "granted-user", Email: "granted@example.com", IsActive: true})
	require.NoError(t, err)

	require.NoError(t, st.AssignRole(ctx, grantedUser.ID, role.ID, storage.Scope{ProjectID: projectID}))

	// Share the secret with grantedUser so ValidateSecretAccess passes.
	secret, err := st.GetSecret(ctx, secretID)
	require.NoError(t, err)
	_, err = st.CreateShareRecord(ctx, &models.ShareRecord{
		SecretID:    secretID,
		OwnerID:     secret.OwnerID,
		RecipientID: grantedUser.ID,
		Permission:  "read",
		IsGroup:     false,
	})
	require.NoError(t, err)

	return secretID, ownerID, grantedUser.ID, projectID
}

// Requirement: off by default — owner (no secrets.read.restricted grant) can still read.
func TestClassificationPermissionGate_OffByDefault_OwnerCanRead(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	// gate is off (zero value); owner has no secrets.read.restricted grant
	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "permission gate off: owner must read unrestricted")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: when on, a user without secrets.read.restricted is denied.
func TestClassificationPermissionGate_On_NoPermission_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), PermSecretReadRestricted)
}

// Requirement: machine/no-user read is always denied when the gate is active.
func TestClassificationPermissionGate_On_NoUser_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement: admin role bypass — an admin who owns the secret passes both
// ValidateSecretAccess (as owner) and the RBAC check (admin bypass in Authorize).
func TestClassificationPermissionGate_On_AdminAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	// Seed a project and an admin who OWNS the restricted secret.
	proj, err := st.CreateProject(ctx, &models.Project{Name: "admin-restricted-gate-test"})
	require.NoError(t, err)

	admin, err := st.CreateUser(ctx, &models.User{Username: "admin-owner", Email: "admin-owner@example.com", IsActive: true})
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, admin.ID, adminRole.ID, storage.Scope{}))

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "top-secret", ProjectID: proj.ID, EnvironmentID: 1, Type: "password",
		IsSecret: true, OwnerID: admin.ID, Status: "active", Classification: ClassificationRestricted,
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("top-secret-value"),
	})
	require.NoError(t, err)

	c.SetClassificationRestrictedRequiresPermission(true)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secret.ID, admin.ID)
	require.NoError(t, err, "admin bypass must let an admin owner read a restricted secret")
	assert.Equal(t, "top-secret-value", string(val))
}

// Requirement: explicit secrets.read.restricted grant allows the read.
func TestClassificationPermissionGate_On_ExplicitGrantAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, _, grantedUserID, _ := seedRestrictedPermissionFixture(t, st)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, grantedUserID)
	require.NoError(t, err, "explicit secrets.read.restricted grant must allow the read")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: lower-tier secrets are never gated by the permission check.
func TestClassificationPermissionGate_On_LowerTierUnaffected(t *testing.T) {
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		level := level
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresPermission(true)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
			require.NoError(t, err, "permission gate must not affect non-restricted secrets")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// Requirement: when both gates are on, BOTH must be satisfied. A user who holds
// the permission but lacks an approved access request is still denied.
func TestClassificationPermissionGate_Combined_BothRequired(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, _, grantedUserID, _ := seedRestrictedPermissionFixture(t, st)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresPermission(true)
	c.SetClassificationRestrictedRequiresApproval(true)

	// grantedUser has the secrets.read.restricted permission but no approved request.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, grantedUserID)
	require.Error(t, err, "both gates active: permission alone is insufficient without approval")
	assert.Contains(t, err.Error(), "access request")
}

// ── restricted_requires_mfa_stepup tests ─────────────────────────────────────

// Requirement: off by default — no change even for a user without a step-up token.
func TestClassificationMFAStepUp_OffByDefault_OwnerCanRead(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "MFA step-up gate off: owner must read unrestricted")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: when on, a user without an active step-up token is denied.
func TestClassificationMFAStepUp_On_NoToken_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), "MFA")
}

// Requirement: machine/no-user read is always denied when the gate is active.
func TestClassificationMFAStepUp_On_NoUser_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, _, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	_, err := c.GetSecretValue(ctx, secretID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
}

// Requirement: a user with an active (non-expired) step-up grant can read.
func TestClassificationMFAStepUp_On_ActiveToken_Allowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Directly seed the step-up grant (as VerifyMFAStepUp would).
	expiresAt := c.now().Add(15 * time.Minute)
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, ExpiresAt: expiresAt}))

	val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.NoError(t, err, "active MFA step-up grant must allow the read")
	assert.Equal(t, "s3cr3t-value", string(val))
}

// Requirement: an expired step-up grant is treated as absent — denied.
func TestClassificationMFAStepUp_On_ExpiredToken_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Seed an already-expired grant.
	expiredAt := c.now().Add(-1 * time.Minute)
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, ExpiresAt: expiredAt}))

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err, "expired step-up grant must not grant access")
	assert.Contains(t, err.Error(), "MFA")
}

// Requirement: lower-tier secrets are never gated by the MFA step-up check.
func TestClassificationMFAStepUp_On_LowerTierUnaffected(t *testing.T) {
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		level := level
		t.Run("classification="+level, func(t *testing.T) {
			c, st := newBootstrappedCore(t)
			secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, level)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

			val, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
			require.NoError(t, err, "MFA step-up gate must not affect non-restricted secrets")
			assert.Equal(t, "s3cr3t-value", string(val))
		})
	}
}

// Requirement: combined with approval gate — both must pass. A user with a valid
// step-up token but no approved access request is still denied.
func TestClassificationMFAStepUp_Combined_BothRequired(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresApproval(true)
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Give the owner an active step-up grant.
	require.NoError(t, st.CreateMFAStepUpGrant(ctx, &models.MFAStepUpGrant{UserID: ownerID, ExpiresAt: c.now().Add(15 * time.Minute)}))

	// No approved access request yet → denied.
	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err, "approval gate must still deny even with a valid MFA step-up token")
	assert.Contains(t, err.Error(), "access request")
}

// Requirement: when windowMinutes > 0 the custom duration is applied and surfaced in
// the denial message, exercising the positive-windowMinutes branch of
// SetClassificationRestrictedRequiresMFAStepUp.
func TestClassificationMFAStepUp_On_CustomWindow_Denied(t *testing.T) {
	c, st := newBootstrappedCore(t)
	secretID, ownerID, _, _ := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 5) // positive windowMinutes

	_, err := c.GetSecretValueWithPermissionCheck(ctx, secretID, ownerID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "5m0s", "denial must mention the custom 5-minute window")
}
