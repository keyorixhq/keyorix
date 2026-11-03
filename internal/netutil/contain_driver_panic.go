package netutil

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"strconv"
)

// ErrDriverPanic is the sentinel wrapped by the error ContainDriverPanic
// returns in place of a panic from a third-party database driver. The error
// text names only the operation, never the panic value: that goes to the log.
var ErrDriverPanic = errors.New("third-party database driver failed unexpectedly")

// ContainDriverPanic contains panics from third-party database drivers at the
// boundary where Keyorix calls into one. Defer it as the first statement of a
// function with a named error result:
//
//	func (e *Engine) Issue(...) (_ T, err error) {
//	    defer netutil.ContainDriverPanic("engine issue", &err)
//
// A panic becomes a returned error (wrapping ErrDriverPanic), so a caller that
// loops over several targets or leases counts one failure and carries on
// instead of abandoning the rest. The panic value and stack are logged with
// the SECURITY: prefix, as one quoted line for the value so text that came
// from a remote peer cannot forge a log line.
//
// Context cancellation is never swallowed: if the panic value is itself a
// context cancellation or deadline error, the returned error wraps that error
// so errors.Is(err, context.Canceled) still holds. A function that returns
// normally, with or without an error, is not touched.
func ContainDriverPanic(op string, err *error) {
	r := recover()
	if r == nil {
		return
	}
	log.Printf("SECURITY: panic from a third-party database driver contained during %s: %s\n%s",
		op, strconv.Quote(fmt.Sprint(r)), debug.Stack())
	if err == nil {
		return
	}
	if re, ok := r.(error); ok && (errors.Is(re, context.Canceled) || errors.Is(re, context.DeadlineExceeded)) {
		*err = fmt.Errorf("%s: %w", op, re)
		return
	}
	*err = fmt.Errorf("%s: %w", op, ErrDriverPanic)
}
