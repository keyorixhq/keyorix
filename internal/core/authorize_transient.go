package core

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsAuthorizeTransient reports whether an error returned by an authorization
// lookup (Authorize, AuthorizePrincipal, AuthorizeSecret*, HoldsPermissionInAnyScope)
// is a storage outage rather than a decision: the request context was canceled or
// ran out of time, a credential/role lookup was already classified transient
// (IsAuthTransient), or the database connection itself failed (refused, reset,
// closed, timed out, server shutting down).
//
// It is the authorization twin of the credential-lookup classification
// (ErrAuthStorageUnavailable): a transport answers such an error 503 / Unavailable
// so the client retries, instead of 403 / PermissionDenied ("you are not allowed"),
// which no client retries. The request is refused either way; nothing here grants
// access.
//
// Classification is structural (sentinels, errors.As on driver and net error
// types), never by message text. Anything it does not recognise is NOT transient and
// stays a fail-closed denial: a programming error such as errNoPrincipalPermission,
// or a verdict-shaped error, must never be reported as an outage.
func IsAuthorizeTransient(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	if IsAuthTransient(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) {
		return true
	}
	if _, ok := errors.AsType[net.Error](err); ok {
		return true
	}
	if _, ok := errors.AsType[*pgconn.ConnectError](err); ok {
		return true
	}
	if pgconn.Timeout(err) {
		return true
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && len(pgErr.Code) >= 2 {
		// SQLSTATE class 08 (connection exception), 53 (insufficient resources),
		// 57 (operator intervention: admin shutdown, crash shutdown, cannot connect now).
		switch pgErr.Code[:2] {
		case "08", "53", "57":
			return true
		}
	}
	return false
}
