package services

// family_mappers_storage_fault_test.go — ERRMAP-GRPC-NOV-3 item 3. The family mappers
// answer through coreErrorStatus, so one typed storage READ fault is the same answer on
// every one of them: Unavailable with the fixed message and the storage_unavailable
// ErrorInfo (REST answers 503 since #4077), never Internal and never the driver text.
// The group, project and share mappers answered it Internal before they moved onto the
// adapter. A permission refusal stays PermissionDenied on each.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestFamilyMappers_TypedStorageReadFaultIsUnavailable(t *testing.T) {
	mappers := map[string]func(error) error{
		"mapRoleError":      mapRoleError,
		"mapMachineError":   mapMachineError,
		"mapUserError":      mapUserError,
		"mapProjectError":   mapProjectError,
		"mapShareError":     mapShareError,
		"mapDynamicError":   mapDynamicError,
		"mapSecretACLError": mapSecretACLError,
		"groupError":        groupError,
	}
	for name, m := range mappers {
		t.Run(name, func(t *testing.T) {
			fault := core.ReadFault(errors.New("driver: connection reset by peer"))
			require.Error(t, fault)

			got := m(fmt.Errorf("read: %w", fault))
			st, ok := status.FromError(got)
			require.True(t, ok)
			assert.Equal(t, codes.Unavailable, st.Code(), got.Error())
			assert.Equal(t, core.StorageReadUnavailableMessage, st.Message())
			assert.True(t, hasErrorInfoReason(got, storageUnavailableReason), "the storage_unavailable ErrorInfo")
			assert.NotContains(t, st.Message(), "connection reset", "the driver cause must not reach the client")
		})
	}
}

func TestFamilyMappers_PermissionRefusalIsPermissionDenied(t *testing.T) {
	mappers := map[string]func(error) error{
		"mapRoleError":      mapRoleError,
		"mapMachineError":   mapMachineError,
		"mapUserError":      mapUserError,
		"mapProjectError":   mapProjectError,
		"mapShareError":     mapShareError,
		"mapDynamicError":   mapDynamicError,
		"mapSecretACLError": mapSecretACLError,
		"groupError":        groupError,
	}
	for name, m := range mappers {
		t.Run(name, func(t *testing.T) {
			got := m(fmt.Errorf("grant: %w", core.ErrPermissionDenied))
			assert.Equal(t, codes.PermissionDenied, status.Code(got), got.Error())
		})
	}
}
