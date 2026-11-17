package services

// family_mappers_canceled_ctx_test.go — GRPC-MAPPER-TAILS-1 item 2. The family mappers
// take the RPC ctx and hand it to coreErrorStatus, so a request whose context was
// canceled while a core call ran is an outage (Unavailable, retry), as it is on the REST
// side (503), not an Internal answer. Before the ctx was threaded the mappers passed
// context.Background(): an error that does not itself wrap context.Canceled (a driver's
// "interrupted" text after the cancel) was not recognised as an authorize outage and
// came out Internal.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// familyMappers is the eight mappers migrated onto coreErrorStatus.
var familyMappers = map[string]func(context.Context, error) error{
	"mapRoleError":      mapRoleError,
	"mapMachineError":   mapMachineError,
	"mapUserError":      mapUserError,
	"mapProjectError":   mapProjectError,
	"mapShareError":     mapShareError,
	"mapDynamicError":   mapDynamicError,
	"mapSecretACLError": mapSecretACLError,
	"groupError":        groupError,
}

func TestFamilyMappers_CanceledContextIsUnavailable(t *testing.T) {
	for name, m := range familyMappers {
		t.Run(name, func(t *testing.T) {
			// The error carries no context sentinel: only the canceled ctx says it is an outage.
			cause := fmt.Errorf("op: %w", errors.New("driver: operation interrupted"))

			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			got := m(canceled, cause)
			st, ok := status.FromError(got)
			require.True(t, ok)
			assert.Equal(t, codes.Unavailable, st.Code(), got.Error())
			assert.NotContains(t, st.Message(), "interrupted", "the driver text must not reach the client")

			live := m(context.Background(), cause)
			if name == "mapDynamicError" {
				// Issue/renew/revoke reach the target database: this mapper already answers
				// any error the classifier does not know Unavailable (its own backend text),
				// on a live ctx too, so the ctx changes nothing here.
				assert.Equal(t, "dynamic-secret backend operation failed", st.Message())
				assert.Equal(t, codes.Unavailable, status.Code(live), live.Error())
				return
			}
			assert.Equal(t, authorizeUnavailableMessage, st.Message(), "the gates' fixed text, as REST's 503")
			// Fail closed on a live ctx: the same untyped error stays Internal.
			assert.Equal(t, codes.Internal, status.Code(live), live.Error())
		})
	}
}

// A typed storage read fault under a canceled ctx keeps the storage_unavailable
// ErrorInfo (the fault check comes before the ctx check).
func TestFamilyMappers_CanceledContextTypedReadFaultKeepsDetail(t *testing.T) {
	for name, m := range familyMappers {
		t.Run(name, func(t *testing.T) {
			fault := core.ReadFault(errors.New("driver: context canceled"))
			require.Error(t, fault)

			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			got := m(canceled, fmt.Errorf("read: %w", fault))
			assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
			assert.True(t, hasErrorInfoReason(got, storageUnavailableReason), "the storage_unavailable ErrorInfo")
		})
	}
}
