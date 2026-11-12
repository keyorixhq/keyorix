package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// createExpiredOwnPATForTest mints a PAT that has already expired at expiresAt.
// CreateOwnPAT refuses an expiry at or before now (core.ErrPATExpiresInPast), so
// the token is issued on a clock an hour before expiresAt, the state a real token
// reaches with time, and the core's clock is then put back on time.Now.
func createExpiredOwnPATForTest(t *testing.T, c *core.KeyorixCore, ctx context.Context, userID uint, name string, expiresAt time.Time) *core.CreatePATResult {
	t.Helper()
	c.SetClockForTesting(func() time.Time { return expiresAt.Add(-time.Hour) })
	defer c.SetClockForTesting(time.Now)
	res, err := c.CreateOwnPAT(ctx, userID, name, &expiresAt, nil, 0, 0, nil)
	require.NoError(t, err)
	return res
}
