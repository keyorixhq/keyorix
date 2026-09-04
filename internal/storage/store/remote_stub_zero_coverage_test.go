package store_test

// remote_stub_zero_coverage_test.go exercises every RemoteStorage method that
// was still at 0% coverage as of the coverage-raising pass this file was
// added in: one-line remoteUnsupported (or plain fmt.Errorf) stubs across
// MFA step-up grants, secret ACLs, RBAC, WebAuthn, billing, connector-project
// bindings, dynamic secrets, and several maintenance-sweep/lock proxies. Each
// stub is documented at its own definition as intentionally unsupported in
// remote (client) mode — see the corresponding remote_unsupported_registry_test.go
// / remote_<feature>_completeness_test.go entries for the "why". This file's
// job is narrower: actually CALL each stub (with zero-value/empty args, since
// none of them touch rs.client or inspect their arguments before returning)
// so the one line of real logic in each — "return the documented sentinel" —
// is verified, not just asserted-to-exist by a static allowlist.

import (
	"context"
	"errors"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStubTestRemoteStorage(t *testing.T) *store.RemoteStorage {
	t.Helper()
	rs, err := store.NewRemoteStorage(testConfigNoRetry("http://127.0.0.1:0"))
	require.NoError(t, err)
	return rs
}

func assertRemoteUnsupported(t *testing.T, err error) {
	t.Helper()
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported), "expected ErrRemoteUnsupported, got %v", err)
}

// --- remote_access_review_campaigns.go ---

func TestRemoteStorage_UpdateAccessReviewCampaign_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	matched, err := rs.UpdateAccessReviewCampaign(context.Background(), &models.AccessReviewCampaign{})
	assert.False(t, matched)
	assertRemoteUnsupported(t, err)
}

// --- remote_anomaly_config.go ---

func TestRemoteStorage_GetAnomalyConfig_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	cfg, err := rs.GetAnomalyConfig(context.Background())
	assert.Nil(t, cfg)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_SaveAnomalyConfig_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.SaveAnomalyConfig(context.Background(), &models.AnomalyConfigRecord{})
	assertRemoteUnsupported(t, err)
}

// --- remote_audit.go ---

func TestRemoteStorage_GetSecretReadCounts_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	entries, err := rs.GetSecretReadCounts(context.Background(), 1, time.Now(), time.Now(), 10)
	assert.Nil(t, entries)
	assertRemoteUnsupported(t, err)
}

// --- remote_billing.go ---

func TestRemoteStorage_GetBillingReport_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	report, err := rs.GetBillingReport(context.Background(), time.Now(), time.Now(), nil)
	assert.Nil(t, report)
	assertRemoteUnsupported(t, err)
}

// --- remote_bootstrap_lock.go ---

func TestRemoteStorage_WithBootstrapLock_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	ran := false
	err := rs.WithBootstrapLock(context.Background(), func() error {
		ran = true
		return nil
	})
	assertRemoteUnsupported(t, err)
	assert.False(t, ran, "fn must never run — RemoteStorage has no cross-process guarantee to offer it")
}

// --- remote_break_glass.go ---

func TestRemoteStorage_CreateBreakGlassActivation_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	activation, err := rs.CreateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{})
	assert.Nil(t, activation)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ReconcileExpiredBreakGlassActivation_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.ReconcileExpiredBreakGlassActivation(context.Background(), 1, 2)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_UpdateBreakGlassActivation_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.UpdateBreakGlassActivation(context.Background(), &models.BreakGlassActivation{})
	assertRemoteUnsupported(t, err)
}

// --- remote_compliance.go ---

func TestRemoteStorage_ListCompliancePostureSnapshots_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	snapshots, err := rs.ListCompliancePostureSnapshots(context.Background(), 10)
	assert.Nil(t, snapshots)
	assertRemoteUnsupported(t, err)
}

// --- remote_connector_project_bindings.go ---

func TestRemoteStorage_GetConnectorProjectBinding_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	binding, err := rs.GetConnectorProjectBinding(context.Background(), "connector-1")
	assert.Nil(t, binding)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListConnectorProjectBindings_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	bindings, err := rs.ListConnectorProjectBindings(context.Background())
	assert.Nil(t, bindings)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_CreateConnectorProjectBinding_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	binding, err := rs.CreateConnectorProjectBinding(context.Background(), &models.ConnectorProjectBinding{})
	assert.Nil(t, binding)
	assertRemoteUnsupported(t, err)
}

// --- remote_dynamic.go ---

func TestRemoteStorage_UpdateDynamicSecretConfig_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.UpdateDynamicSecretConfig(context.Background(), &models.DynamicSecretConfig{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_TransitionDynamicSecretConfigDisabled_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	matched, err := rs.TransitionDynamicSecretConfigDisabled(context.Background(), &models.DynamicSecretConfig{}, true)
	assert.False(t, matched)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_CreateDynamicSecretLease_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	lease, err := rs.CreateDynamicSecretLease(context.Background(), &models.DynamicSecretLease{})
	assert.Nil(t, lease)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_UpdateDynamicSecretLease_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.UpdateDynamicSecretLease(context.Background(), &models.DynamicSecretLease{})
	assertRemoteUnsupported(t, err)
}

// --- remote_inactivity_suspend.go ---

func TestRemoteStorage_ListInactiveUsers_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	users, err := rs.ListInactiveUsers(context.Background(), time.Now())
	assert.Nil(t, users)
	assertRemoteUnsupported(t, err)
}

// --- remote_machine_identities.go ---

// GetMachineRoleScopes predates the remoteUnsupported/ErrRemoteUnsupported
// convention and still returns a plain fmt.Errorf, so it's checked for a
// non-nil error only, not the sentinel.
func TestRemoteStorage_GetMachineRoleScopes_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	scopes, err := rs.GetMachineRoleScopes(context.Background(), 1)
	assert.Nil(t, scopes)
	require.Error(t, err)
}

// --- remote_mfa.go ---

func TestRemoteStorage_UpsertMFASecret_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.UpsertMFASecret(context.Background(), &models.MFASecret{})
	assertRemoteUnsupported(t, err)
}

// --- remote_mfa_stepup_grant.go ---

func TestRemoteStorage_CreateMFAStepUpGrant_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.CreateMFAStepUpGrant(context.Background(), &models.MFAStepUpGrant{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteMFAStepUpGrantsFor_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteMFAStepUpGrantsFor(context.Background(), 1)
	assertRemoteUnsupported(t, err)
}

// --- remote_named_lock.go ---
//
// Unlike the rest of this file, WithNamedLock is NOT a stub: it always runs
// fn, passthrough (no distributed named-lock exists over HTTP; see the
// method's own doc comment). Covered here for the same reason as the stubs —
// it was still at 0% — but the assertion is the opposite: fn DOES run, and
// its error/return value propagates untouched.
func TestRemoteStorage_WithNamedLock_RunsFnAndPropagates(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	ran := false
	err := rs.WithNamedLock(context.Background(), "some-lock", func(_ context.Context) error {
		ran = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ran)

	sentinel := errors.New("boom")
	err = rs.WithNamedLock(context.Background(), "some-lock", func(_ context.Context) error {
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
}

// --- remote_rbac.go ---

func TestRemoteStorage_SetRoleBypassesPermissionChecks_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.SetRoleBypassesPermissionChecks(context.Background(), 1, true)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListAllUserRoleGrants_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	grants, err := rs.ListAllUserRoleGrants(context.Background())
	assert.Nil(t, grants)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListAllGroupRoleGrants_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	grants, err := rs.ListAllGroupRoleGrants(context.Background())
	assert.Nil(t, grants)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_CreateConnectRefGrant_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	grant, err := rs.CreateConnectRefGrant(context.Background(), &models.ConnectRefGrant{})
	assert.Nil(t, grant)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteConnectRefGrant_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteConnectRefGrant(context.Background(), 1)
	assertRemoteUnsupported(t, err)
}

// IsGroupProjectScoped predates the remoteUnsupported convention too — plain
// fmt.Errorf, same treatment as GetMachineRoleScopes above.
func TestRemoteStorage_IsGroupProjectScoped_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	scoped, err := rs.IsGroupProjectScoped(context.Background(), 1, 2)
	assert.False(t, scoped)
	require.Error(t, err)
}

func TestRemoteStorage_RoleSetBypassesPermissionChecks_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	bypasses, err := rs.RoleSetBypassesPermissionChecks(context.Background(), []uint{1, 2})
	assert.False(t, bypasses)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_GetProjectByName_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	project, err := rs.GetProjectByName(context.Background(), "proj")
	assert.Nil(t, project)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_UpdateProject_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	project, err := rs.UpdateProject(context.Background(), &models.Project{})
	assert.Nil(t, project)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_RestoreProject_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	envs, secrets, err := rs.RestoreProject(context.Background(), 1)
	assert.Zero(t, envs)
	assert.Zero(t, secrets)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_RestoreEnvironment_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.RestoreEnvironment(context.Background(), 1, 2)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListGlobalAdminAssignmentsForUpdate_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	assignments, err := rs.ListGlobalAdminAssignmentsForUpdate(context.Background(), []uint{1})
	assert.Nil(t, assignments)
	assertRemoteUnsupported(t, err)
}

// --- remote_role_expiry.go ---

func TestRemoteStorage_ListExpiringUserRoles_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	roles, err := rs.ListExpiringUserRoles(context.Background(), time.Now())
	assert.Nil(t, roles)
	assertRemoteUnsupported(t, err)
}

// --- remote_scheduler_lock.go ---

func TestRemoteStorage_WithSchedulerLock_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	ran := false
	acquired, err := rs.WithSchedulerLock(context.Background(), 42, func() error {
		ran = true
		return nil
	})
	assert.False(t, acquired)
	assertRemoteUnsupported(t, err)
	assert.False(t, ran)
}

func TestRemoteStorage_TryAcquireSchedulerLock_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	acquired, err := rs.TryAcquireSchedulerLock(context.Background(), 42, "holder", time.Second)
	assert.False(t, acquired)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ReleaseSchedulerLock_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.ReleaseSchedulerLock(context.Background(), 42, "holder")
	assertRemoteUnsupported(t, err)
}

// --- remote_secret_acl.go ---

func TestRemoteStorage_CreateOrUpdateSecretACL_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.CreateOrUpdateSecretACL(context.Background(), &models.SecretACL{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListSecretACLs_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	acls, err := rs.ListSecretACLs(context.Background(), 1)
	assert.Nil(t, acls)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListSecretACLsByUser_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	acls, err := rs.ListSecretACLsByUser(context.Background(), 1)
	assert.Nil(t, acls)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_GetSecretACL_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	acl, err := rs.GetSecretACL(context.Background(), 1, 2)
	assert.Nil(t, acl)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteSecretACL_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteSecretACL(context.Background(), 1)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_GetSecretAncestors_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	ancestors, err := rs.GetSecretAncestors(context.Background(), 1)
	assert.Nil(t, ancestors)
	assertRemoteUnsupported(t, err)
}

// --- remote_secret_dependencies.go ---

func TestRemoteStorage_CreateSecretDependency_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	dep, err := rs.CreateSecretDependency(context.Background(), &models.SecretDependency{})
	assert.Nil(t, dep)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListSecretDependenciesForProjectForUpdate_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	deps, err := rs.ListSecretDependenciesForProjectForUpdate(context.Background(), 1)
	assert.Nil(t, deps)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteSecretDependency_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteSecretDependency(context.Background(), 1)
	assertRemoteUnsupported(t, err)
}

// --- remote_secrets.go (maintenance-sweep stubs) ---

func TestRemoteStorage_DeleteAnomalyAlertsBefore_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	n, err := rs.DeleteAnomalyAlertsBefore(context.Background(), time.Now(), time.Now())
	assert.Zero(t, n)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteClosedAccessReviewsBefore_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	campaigns, items, err := rs.DeleteClosedAccessReviewsBefore(context.Background(), time.Now())
	assert.Zero(t, campaigns)
	assert.Zero(t, items)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteExpiredBreakGlassBefore_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	n, err := rs.DeleteExpiredBreakGlassBefore(context.Background(), time.Now())
	assert.Zero(t, n)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteResolvedAccessRequestsBefore_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	requests, approvals, err := rs.DeleteResolvedAccessRequestsBefore(context.Background(), time.Now())
	assert.Zero(t, requests)
	assert.Zero(t, approvals)
	assertRemoteUnsupported(t, err)
}

// --- remote_stats.go ---

func TestRemoteStorage_SaveDeploymentStatsSnapshot_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.SaveDeploymentStatsSnapshot(context.Background(), &models.DeploymentStatsSnapshot{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_GetPreviousDeploymentStatsSnapshot_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	snapshot, err := rs.GetPreviousDeploymentStatsSnapshot(context.Background())
	assert.Nil(t, snapshot)
	assertRemoteUnsupported(t, err)
}

// --- remote_usage.go ---

func TestRemoteStorage_GetProjectUsageStats_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	stats, err := rs.GetProjectUsageStats(context.Background(), []uint{1}, 10)
	assert.Nil(t, stats)
	assertRemoteUnsupported(t, err)
}

// --- remote_users.go ---

func TestRemoteStorage_UpdateLoginLockoutState_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	now := time.Now()
	err := rs.UpdateLoginLockoutState(context.Background(), 1, 3, &now, &now, 5)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListAllUserGroupMemberships_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	memberships, err := rs.ListAllUserGroupMemberships(context.Background())
	assert.Nil(t, memberships)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_GetUserGroupsAt_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	groups, err := rs.GetUserGroupsAt(context.Background(), 1, corestorage.Scope{})
	assert.Nil(t, groups)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListGroupMembersAt_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	members, err := rs.ListGroupMembersAt(context.Background(), 1, corestorage.Scope{})
	assert.Nil(t, members)
	assertRemoteUnsupported(t, err)
}

// --- remote_version_comments.go ---

func TestRemoteStorage_CreateSecretVersionComment_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.CreateSecretVersionComment(context.Background(), &models.SecretVersionComment{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_ListSecretVersionComments_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	comments, err := rs.ListSecretVersionComments(context.Background(), 1, 2)
	assert.Nil(t, comments)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteSecretVersionComment_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteSecretVersionComment(context.Background(), 1, 2, 3)
	assertRemoteUnsupported(t, err)
}

// --- remote_webauthn.go ---

func TestRemoteStorage_CreateWebAuthnCredential_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.CreateWebAuthnCredential(context.Background(), &models.WebAuthnCredential{})
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_DeleteWebAuthnCredential_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.DeleteWebAuthnCredential(context.Background(), 1, 2)
	assertRemoteUnsupported(t, err)
}

func TestRemoteStorage_SetUserWebAuthnEnabled_Unsupported(t *testing.T) {
	rs := newStubTestRemoteStorage(t)
	err := rs.SetUserWebAuthnEnabled(context.Background(), 1, true)
	assertRemoteUnsupported(t, err)
}
