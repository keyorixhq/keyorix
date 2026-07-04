package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// #420: before the fix, a per-user GetUserPermissions error was silently
// swallowed (a bare `continue`, no logging, no signal) — a user whose
// permissions couldn't be read was dropped from the SoD scan with the report
// looking exactly like a clean, complete one. This proves the failing user is
// still skipped (nothing else can be done without the data) but the report now
// flags Degraded with a reason, while the other user's real violation is still
// correctly detected.
func TestDetectSoDViolations_DegradedOnUserPermissionsError(t *testing.T) {
	ctx := context.Background()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	store.On("ListSoDPolicies", ctx).Return([]*models.SoDPolicy{
		{ID: 1, Name: "write-vs-useradmin", PermissionA: "secrets.write", PermissionB: "users.read"},
	}, nil)
	store.On("ListUsers", ctx, mock.Anything).Return([]*models.User{
		{ID: 10, Username: "alice", IsActive: true},
		{ID: 11, Username: "bob", IsActive: true},
	}, int64(2), nil)

	// Neither user holds an admin permission-bypass role.
	store.On("GetUserRoles", ctx, uint(10)).Return([]*models.Role{}, nil)
	store.On("GetUserRoles", ctx, uint(11)).Return([]*models.Role{}, nil)

	// alice: a real, detectable violation.
	store.On("GetUserPermissions", ctx, uint(10)).Return([]*storage.Permission{
		{Name: "secrets.write"}, {Name: "users.read"},
	}, nil)
	store.On("GetUserGroupPermissions", ctx, uint(10)).Return([]*storage.Permission{}, nil)

	// bob: permissions can't be read at all.
	store.On("GetUserPermissions", ctx, uint(11)).Return(nil, errors.New("simulated: permission lookup unavailable"))

	// No machine identities to scan.
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{}, nil)

	report, err := c.DetectSoDViolations(ctx)
	require.NoError(t, err)

	require.True(t, report.Degraded, "a user whose permissions couldn't be read must flip Degraded")
	require.NotEmpty(t, report.DegradedReasons)
	assert.Contains(t, report.DegradedReasons[0], "user=11")

	var users []string
	for _, v := range report.Violations {
		users = append(users, v.Username)
	}
	assert.Contains(t, users, "alice", "alice's real violation must still be detected")
	assert.NotContains(t, users, "bob", "bob can't be evaluated without his permissions")

	// bob's group permissions must never be consulted once his direct permission
	// lookup already failed.
	store.AssertNotCalled(t, "GetUserGroupPermissions", ctx, uint(11))
}

// #492: machineSoDViolations is the sibling of userSoDViolations/#420 for
// machine identities, but its sub-check errors (GetMachineRoles,
// RoleSetHasPermission) were previously folded into a bare `continue` — a
// machine that couldn't be evaluated was silently dropped with the report
// still looking clean. This proves a GetMachineRoles error now flips Degraded
// with a reason naming the machine, while a real human violation is still
// correctly detected.
func TestDetectSoDViolations_DegradedOnMachineRolesError(t *testing.T) {
	ctx := context.Background()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	store.On("ListSoDPolicies", ctx).Return([]*models.SoDPolicy{
		{ID: 1, Name: "write-vs-useradmin", PermissionA: "secrets.write", PermissionB: "users.read"},
	}, nil)
	store.On("ListUsers", ctx, mock.Anything).Return([]*models.User{
		{ID: 10, Username: "alice", IsActive: true},
	}, int64(1), nil)
	store.On("GetUserRoles", ctx, uint(10)).Return([]*models.Role{}, nil)
	store.On("GetUserPermissions", ctx, uint(10)).Return([]*storage.Permission{
		{Name: "secrets.write"}, {Name: "users.read"},
	}, nil)
	store.On("GetUserGroupPermissions", ctx, uint(10)).Return([]*storage.Permission{}, nil)

	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{
		{ID: 20, Name: "ci-runner", State: "active"},
	}, nil)
	store.On("GetMachineRoles", ctx, uint(20)).Return(nil, errors.New("simulated: machine role lookup unavailable"))

	report, err := c.DetectSoDViolations(ctx)
	require.NoError(t, err)

	require.True(t, report.Degraded, "a machine whose roles couldn't be read must flip Degraded")
	require.NotEmpty(t, report.DegradedReasons)
	assert.Contains(t, report.DegradedReasons[len(report.DegradedReasons)-1], "machine=20")

	var users []string
	for _, v := range report.Violations {
		users = append(users, v.Username)
	}
	assert.Contains(t, users, "alice", "alice's real violation must still be detected")
	assert.NotContains(t, users, "ci-runner", "ci-runner can't be evaluated without its roles")
}

// A RoleSetHasPermission error (rather than GetMachineRoles) must also flip
// Degraded, named for the machine and policy that couldn't be evaluated.
func TestDetectSoDViolations_DegradedOnMachinePermissionError(t *testing.T) {
	ctx := context.Background()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	store.On("ListSoDPolicies", ctx).Return([]*models.SoDPolicy{
		{ID: 1, Name: "write-vs-useradmin", PermissionA: "secrets.write", PermissionB: "users.read"},
	}, nil)
	store.On("ListUsers", ctx, mock.Anything).Return([]*models.User{}, int64(0), nil)

	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{
		{ID: 21, Name: "deploy-bot", State: "active"},
	}, nil)
	store.On("GetMachineRoles", ctx, uint(21)).Return([]*models.Role{{ID: 5, Name: "deployer"}}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "secrets.write").
		Return(false, errors.New("simulated: permission check unavailable"))

	report, err := c.DetectSoDViolations(ctx)
	require.NoError(t, err)

	require.True(t, report.Degraded, "a machine whose permission check errored must flip Degraded")
	require.NotEmpty(t, report.DegradedReasons)
	assert.Contains(t, report.DegradedReasons[0], "machine=21")
	assert.Contains(t, report.DegradedReasons[0], "policy=1")
	assert.Empty(t, report.Violations, "no violation can be confirmed without a successful permission check")
}

// A clean scan (every principal's permissions resolve) must not be marked
// Degraded — the signal must not fire on the happy path.
func TestDetectSoDViolations_NotDegradedOnCleanScan(t *testing.T) {
	ctx := context.Background()
	store := new(MockStorage)
	c := NewKeyorixCore(store)

	store.On("ListSoDPolicies", ctx).Return([]*models.SoDPolicy{
		{ID: 1, Name: "write-vs-useradmin", PermissionA: "secrets.write", PermissionB: "users.read"},
	}, nil)
	store.On("ListUsers", ctx, mock.Anything).Return([]*models.User{
		{ID: 10, Username: "alice", IsActive: true},
	}, int64(1), nil)
	store.On("GetUserRoles", ctx, uint(10)).Return([]*models.Role{}, nil)
	store.On("GetUserPermissions", ctx, uint(10)).Return([]*storage.Permission{
		{Name: "secrets.read"},
	}, nil)
	store.On("GetUserGroupPermissions", ctx, uint(10)).Return([]*storage.Permission{}, nil)
	store.On("ListAllMachineIdentities", ctx).Return([]*models.MachineIdentity{}, nil)

	report, err := c.DetectSoDViolations(ctx)
	require.NoError(t, err)
	assert.False(t, report.Degraded)
	assert.Empty(t, report.DegradedReasons)
	assert.Empty(t, report.Violations)
}
