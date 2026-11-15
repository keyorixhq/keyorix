package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SUSPEND-TAILS-NOV-1 item 1: when the best-effort audit of a plain suspend fails, the
// suspension stands and the error line names the actor and the request (ids only, no
// secret material), so an operator can join it with the request's other log lines.
// Not parallel: captures the global logger.
func TestSuspendSecret_PlainSuspendAuditFailureLogNamesUserAndRequest(t *testing.T) {
	w := newOwedAuditWorld(t)
	id := w.secret(t, "traced", 1, SecretStatusActive, false)
	logs := captureOwedAuditLog(t)
	defer refuseSuspendAudit(t, w)()

	_, err := w.c.SuspendSecret(owedRequestCtx(owedReqIDA), id, 7, "trace me")
	require.NoError(t, err)
	assert.Equal(t, SecretStatusSuspended, w.stored(t, id).Status, "the suspension stands")
	assert.Contains(t, logs.String(), "user=7")
	assert.Contains(t, logs.String(), "request="+owedReqIDA)

	// A request without an id logs a placeholder rather than an empty field.
	id2 := w.secret(t, "untraced", 1, SecretStatusActive, false)
	logs.Reset()
	_, err = w.c.SuspendSecret(context.Background(), id2, 7, "no request")
	require.NoError(t, err)
	assert.Contains(t, logs.String(), "request=-")
}
