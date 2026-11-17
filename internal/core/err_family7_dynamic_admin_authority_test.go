package core

// CORE-ERR-FAMILY-7 item 1: binding a dynamic-secret backend without admin authority is an
// authorization refusal (ErrPermissionDenied), not an untyped error that the gRPC mapper's
// default branch answers Unavailable ("retry later"). Failing to resolve the actor's roles
// is a storage read fault (ErrStorageReadUnavailable), never a refusal.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestErrFamily7_DynamicSecretAdminAuthority_DenialIsPermissionDenied(t *testing.T) {
	t.Parallel()
	ms := new(MockStorage)
	scope := Scope{ProjectID: 2, EnvironmentID: 3}
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(7), scope).Return([]uint{40}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(7), scope).Return([]uint{}, nil)
	ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{40}).Return(false, nil)

	err := NewKeyorixCore(ms).requireDynamicSecretAdminAuthority(context.Background(), 7, 2, 3)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPermissionDenied)
	assert.False(t, IsStorageReadUnavailable(err), "a refusal is not an outage")
}

func TestErrFamily7_DynamicSecretAdminAuthority_RoleReadFaultIsUnavailable(t *testing.T) {
	t.Parallel()
	scope := Scope{ProjectID: 2, EnvironmentID: 3}
	for name, arm := range map[string]func(ms *MockStorage){
		"role ids": func(ms *MockStorage) {
			ms.On("GetUserRoleIDsAt", mock.Anything, uint(7), scope).Return(nil, errors.New("connection reset"))
		},
		"admin flag": func(ms *MockStorage) {
			ms.On("GetUserRoleIDsAt", mock.Anything, uint(7), scope).Return([]uint{40}, nil)
			ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(7), scope).Return([]uint{}, nil)
			ms.On("RoleSetBypassesPermissionChecks", mock.Anything, []uint{40}).Return(false, errors.New("connection reset"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ms := new(MockStorage)
			arm(ms)
			err := NewKeyorixCore(ms).requireDynamicSecretAdminAuthority(context.Background(), 7, 2, 3)
			require.Error(t, err)
			assert.True(t, IsStorageReadUnavailable(err), "a role read fault must be a storage fault: %v", err)
			assert.NotErrorIs(t, err, ErrPermissionDenied, "an outage is not a denial")
			assert.Contains(t, StorageReadFaultDetail(err), "connection reset", "the driver cause stays in the log text")
		})
	}
}
