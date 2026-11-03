package core

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

// TestIsAuthorizeTransient pins the classification of an authorization-lookup error:
// storage outages are transient, everything else (including a text that merely says
// "connection refused") stays a fail-closed denial. INV-MW-authorize-lookup-error-is-503.
func TestIsAuthorizeTransient(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	transient := map[string]error{
		"deadline":            context.DeadlineExceeded,
		"canceled":            context.Canceled,
		"wrapped deadline":    fmt.Errorf("resolve: %w", context.DeadlineExceeded),
		"auth storage":        ErrAuthStorageUnavailable,
		"role resolution":     ErrRoleResolutionUnavailable,
		"bad conn":            driver.ErrBadConn,
		"conn done":           sql.ErrConnDone,
		"unexpected eof":      io.ErrUnexpectedEOF,
		"econnrefused":        syscall.ECONNREFUSED,
		"econnreset":          fmt.Errorf("query: %w", syscall.ECONNRESET),
		"net op error":        &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")},
		"pg connection class": &pgconn.PgError{Code: "08006"},
		"pg admin shutdown":   &pgconn.PgError{Code: "57P01"},
		"pg out of resources": &pgconn.PgError{Code: "53300"},
	}
	for name, err := range transient {
		assert.True(t, IsAuthorizeTransient(context.Background(), err), name)
	}

	denials := map[string]error{
		"nil":                nil,
		"no principal perm":  errNoPrincipalPermission,
		"plain":              errors.New("boom"),
		"text lookalike":     errors.New("dial tcp: connection refused"),
		"pg unique":          &pgconn.PgError{Code: "23505"},
		"pg syntax":          &pgconn.PgError{Code: "42601"},
		"pg short code":      &pgconn.PgError{Code: "0"},
		"verdict not found":  fmt.Errorf("secret %d not found", 1),
		"wrapped plain deny": fmt.Errorf("authorize: %w", errNoPrincipalPermission),
	}
	for name, err := range denials {
		assert.False(t, IsAuthorizeTransient(context.Background(), err), name)
	}

	// A request whose own context is done is transient for any non-nil error, the one
	// reliable signal when the driver hides the cause.
	assert.True(t, IsAuthorizeTransient(canceled, errors.New("boom")))
	assert.False(t, IsAuthorizeTransient(canceled, nil))
}
