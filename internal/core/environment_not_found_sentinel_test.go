package core

// environment_not_found_sentinel_test.go — ERRLOSS-MFA-1 item 3: the
// GetEnvironment callers on an authorization or audit decision (the role scope
// guard, the machine-role environment check, the environment-without-project
// grants report) tell a missing environment from a storage failure by the
// storage.ErrEnvironmentNotFound sentinel, not by the error's text. A storage
// error that happens to read "environment not found" used to be taken for a
// missing environment: a 400 refusal instead of a 500, and in the access-review
// report a live grant described as "environment no longer exists: remove the
// grant". The fault is injected with internal/faultstorage over a real
// LocalStorage.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// envLookalikeErr has exactly the legacy not-found text but is NOT the sentinel.
var envLookalikeErr = errors.New("environment not found")

func envLookalikeCore(t *testing.T, st storage.Storage) (*KeyorixCore, *faultstorage.FaultyStorage) {
	t.Helper()
	fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "GetEnvironment", NthCall: 1, Kind: faultstorage.KindError, Err: envLookalikeErr,
	})
	return NewKeyorixCore(fs), fs
}

func TestRoleScopeGuard_EnvironmentLookalikeErrorIsAStorageFailure(t *testing.T) {
	c, st := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	ctx := context.Background()

	fc, fs := envLookalikeCore(t, st)
	err := fc.requireScopeValidForRoleModel(ctx, w.projectDeveloper, Scope{ProjectID: w.p1, EnvironmentID: w.e1})
	require.True(t, fs.Fired(), "precondition: the scope check must hit the injected fault")
	require.Error(t, err)
	var rse *RoleScopeError
	assert.False(t, errors.As(err, &rse), "a storage failure must not read as \"no such environment\" (400): %v", err)

	// A genuinely missing environment is still refused as a scope error.
	err = c.requireScopeValidForRoleModel(ctx, w.projectDeveloper, Scope{ProjectID: w.p1, EnvironmentID: 99999})
	require.ErrorAs(t, err, &rse)
}

func TestMachineRoleEnvironmentCheck_EnvironmentLookalikeErrorIsAStorageFailure(t *testing.T) {
	c, st := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	ctx := context.Background()

	fc, fs := envLookalikeCore(t, st)
	err := fc.requireEnvironmentInProject(ctx, Scope{ProjectID: w.p1, EnvironmentID: w.e1})
	require.True(t, fs.Fired(), "precondition: the environment check must hit the injected fault")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify target environment", "a storage failure must not read as a validation refusal")

	err = c.requireEnvironmentInProject(ctx, Scope{ProjectID: w.p1, EnvironmentID: 99999})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "failed to verify", "a genuinely missing environment is a validation refusal")
}

func TestListEnvironmentWithoutProjectGrants_EnvironmentLookalikeErrorFails(t *testing.T) {
	c, st := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)
	seedEnvironmentWithoutProjectGrants(t, w)

	fc, fs := envLookalikeCore(t, st)
	got, err := fc.ListEnvironmentWithoutProjectGrants(context.Background())
	require.True(t, fs.Fired(), "precondition: the report must hit the injected fault")
	require.Error(t, err, "a storage failure must fail the report, not describe a live grant's environment as gone: %+v", got)
}

func TestGetEnvironmentInProject_OtherProjectReadsAsNotFound(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	w := newRoleScopeWorld(t, c)

	_, err := c.GetEnvironmentInProject(context.Background(), w.p2, w.e1)
	require.Error(t, err)
	assert.True(t, storage.IsEnvironmentNotFound(err), "another project's environment must read exactly like a missing one")
	assert.Equal(t, "environment not found", err.Error())
}
