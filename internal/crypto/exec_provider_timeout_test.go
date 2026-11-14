package crypto

// PR #4213 review (Reviewer-2, MEDIUM): a helper that times out must keep
// context.DeadlineExceeded in the error chain, so the server's boot classifies
// it as a dependency that may come back (exit 75), not an operator fix.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecKEK_TimeoutWrapsDeadlineExceeded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 30 s exec timeout")
	}
	_, err := NewExecKeyProvider([]string{"/bin/sleep", "120"}).KEK()
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), `exec key provider: command "/bin/sleep" timed out after 30s`)
}
