package services

// user_error_outage_first_test.go — REVIEW-4214 L3. mapUserError answers an outage
// before its typed pre-checks (STORAGE-ERR-CLASS-2): a refusal that wraps a failed
// storage read or an audit outage is Unavailable (retry), not the terminal refusal.

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestMapUserError_OutageBeforeTypedRefusal(t *testing.T) {
	fault := core.ReadFault(errors.New("driver: connection reset by peer"))
	for name, refusal := range map[string]error{
		"insufficient admin authority": core.ErrInsufficientAdminAuthority,
		"cannot act on self":           core.ErrCannotActOnSelf,
		"setup base url required":      core.ErrSetupBaseURLRequired,
	} {
		t.Run(name, func(t *testing.T) {
			got := mapUserError(context.Background(), fmt.Errorf("%w: %w", refusal, fault))
			assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
			assert.True(t, hasErrorInfoReason(got, storageUnavailableReason), "the storage_unavailable ErrorInfo")
		})
	}
	// Without an outage the typed refusal keeps its own answer.
	got := mapUserError(context.Background(), fmt.Errorf("op: %w", core.ErrInsufficientAdminAuthority))
	assert.Equal(t, codes.PermissionDenied, status.Code(got), got.Error())
}
