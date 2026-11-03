package dynamic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/netutil"
)

// panickingResolver makes a panic surface from inside the driver's connect path
// (the resolver is called from the dial function the driver invokes), on the
// same goroutine as the engine call.
func panickingResolver(context.Context, string) ([]net.IPAddr, error) { panic("driver failure") }

// A panic raised while connecting to the target is contained at the engine
// boundary and comes back as an error. Not parallel: it swaps dialResolve.
func TestMySQLEngine_Issue_ContainsDriverPanic(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = panickingResolver

	var err error
	require.NotPanics(t, func() {
		_, _, err = (&MySQLEngine{}).Issue(context.Background(), "admin:pass@tcp(panic.mysql.example:3306)/app", "", time.Minute)
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrDriverPanic)
	assert.NotContains(t, err.Error(), "driver failure")
}

func TestMySQLEngine_Revoke_ContainsDriverPanic(t *testing.T) {
	origResolve := dialResolve
	defer func() { dialResolve = origResolve }()
	dialResolve = panickingResolver

	var err error
	require.NotPanics(t, func() {
		err = (&MySQLEngine{}).Revoke(context.Background(), "admin:pass@tcp(panic.mysql.example:3306)/app", "kx_dyn_abc123")
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrDriverPanic)
}
