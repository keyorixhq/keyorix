package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestAuditUnavailableStatus covers the helper itself: the sentinel, wrapped, maps;
// an unrelated error and a partial mutation (its own richer answer) do not.
func TestAuditUnavailableStatus(t *testing.T) {
	wrapped := errors.Join(errors.New("ctx"), core.ErrMutationAuditUnavailable)
	out, ok := auditUnavailableStatus(wrapped)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, status.Code(out))

	_, ok = auditUnavailableStatus(errors.New("boom"))
	assert.False(t, ok)
	_, ok = auditUnavailableStatus(context.Canceled)
	assert.False(t, ok)
}
