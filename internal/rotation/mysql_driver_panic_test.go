package rotation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// panicConn stands in for a connection whose underlying driver panics.
type panicConn struct{ closed *bool }

func (panicConn) Exec(context.Context, string, ...any) error { panic("driver failure") }
func (p panicConn) Close() error                             { *p.closed = true; return nil }

// A panic from the database driver during Rotate is contained at the executor
// boundary: Rotate returns an error, the connection is still closed, and the
// panic text is not part of the returned error.
func TestMySQLExecutor_Rotate_ContainsDriverPanic(t *testing.T) {
	t.Parallel()
	closed := false
	e := NewMySQLExecutor("my", "user:pw@tcp(db:3306)/", []string{"app_"})
	e.newConn = func(context.Context, string) (mysqlConn, error) { return panicConn{closed: &closed}, nil }

	var err error
	require.NotPanics(t, func() { err = e.Rotate(context.Background(), "app_svc", "new-value") })
	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrDriverPanic)
	assert.NotContains(t, err.Error(), "driver failure")
	assert.True(t, closed, "the connection must still be closed after a contained panic")
}
