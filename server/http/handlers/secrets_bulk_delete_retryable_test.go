package handlers

// GRPC-OUTAGE-TAILS-1 item 3 (#3912): the 200 body of a bulk delete marks an item that
// failed on an outage as retryable (code + retryable), says how many are retryable in
// the data and the envelope message, and leaves a non-retryable failure unmarked.

import (
	"encoding/json"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

func TestBulkDeleteSecrets_RetryableItemOnTheWire(t *testing.T) {
	t.Run("a transient storage outage is retryable and counted", func(t *testing.T) {
		down := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		body, failed := bulkDeleteFailures(t, &faultstorage.FaultSpec{Method: "DeleteSecret", NthCall: 1, Kind: faultstorage.KindError, Err: down})
		assert.Equal(t, core.BulkErrCodeStorageUnavailable, failed[0].Code)
		assert.True(t, failed[0].Retryable)

		var env struct {
			Message string `json:"message"`
			Data    struct {
				Retryable int `json:"retryable"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &env))
		assert.Equal(t, 1, env.Data.Retryable)
		assert.Contains(t, env.Message, "1 of 1 secrets were not deleted")
		assert.Contains(t, env.Message, "retry")
	})
	t.Run("a non-outage failure is not retryable", func(t *testing.T) {
		body, failed := bulkDeleteFailures(t, &faultstorage.FaultSpec{Method: "DeleteSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errSchemaLeak})
		assert.Empty(t, failed[0].Code)
		assert.False(t, failed[0].Retryable)

		var env struct {
			Message string `json:"message"`
			Data    struct {
				Retryable int `json:"retryable"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &env))
		assert.Zero(t, env.Data.Retryable)
		assert.NotContains(t, env.Message, "retry")
	})
}
