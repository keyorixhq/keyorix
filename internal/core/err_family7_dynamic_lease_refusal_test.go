package core

// CORE-ERR-FAMILY-7 item 2: every lease-state refusal matches ErrDynamicSecretPrecondition
// with its text unchanged, and the ttl_seconds overflow refusal is a validation refusal.
// The transports classify these by sentinel (REST 409 / gRPC FailedPrecondition, 400 /
// InvalidArgument), not by text.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestErrFamily7_DynamicLeaseRefusalsAreTyped(t *testing.T) {
	t.Parallel()
	c := NewKeyorixCore(new(MockStorage))

	_, err := c.dynamicTTL(&models.DynamicSecretConfig{}, maxDynamicTTLSecondsAsInt+1)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrValidation)
	assert.Contains(t, err.Error(), "ttl_seconds")

	// The clock-regression refusal reuses RenewLease's own expired text so it is no
	// oracle; it must also carry the same sentinel.
	c.dynamicSecretsClockWatermark = time.Now().Add(time.Hour)
	err = c.checkLeaseRenewClockNotRegressed(time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDynamicSecretPrecondition)
	assert.Equal(t, "lease has expired; issue a new lease instead", err.Error())
}
