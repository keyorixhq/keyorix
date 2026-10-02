package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMintSession_EnforceSessionLimitPanicDoesNotFailAnOtherwiseSuccessfulLogin
// is the regression test for a panic in EnforceSessionLimit: mintSession calls
// it AFTER CreateSession has already committed the new session row (auth.go),
// discarding only its returned error ("Best-effort — never fail a login on
// it"). A panic isn't stopped by that discard — it unwinds past mintSession
// entirely, reaching only the transport layer's Recovery middleware, which
// reports the whole login as a 500 even though a real session now exists.
// Same "best-effort helper, primary operation already succeeded" shape as
// evictUserSessionCache (account.go) and notifySecretAccessRequested
// (classification_gate.go).
func TestMintSession_EnforceSessionLimitPanicDoesNotFailAnOtherwiseSuccessfulLogin(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)

	faulty := faultstorage.NewFaultyStorage(st, nil)
	c.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{
		Method: "EnforceSessionLimit", NthCall: 1, Kind: faultstorage.KindPanic,
	})

	session, err := c.mintSession(ctx, admin.ID, "test-agent/1.0", "203.0.113.5")

	require.NoError(t, err, "a panic in the best-effort session-limit enforcement must not surface as an error from an otherwise-successful login")
	require.NotNil(t, session)
	assert.NotZero(t, session.ID)

	// Confirm via a fresh, unfaulted read — not just the in-memory return value.
	reread, err := st.GetSession(ctx, session.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, session.ID, reread.ID)
}
