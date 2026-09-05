package common

// ExitCodeError lets a command signal a specific process exit code, rather
// than the generic "1" internal/cli/main.go's Execute() gives every returned
// error today. Introduced for `status`/`ping` (#4, 2026-09-05): those commands
// distinguish "the configured target is unreachable/unhealthy" (1) from "no
// usable configuration exists at all" (2) -- a distinction a bare error can't
// carry, since Execute() only sees the error's text, not why it occurred.
//
// A command that returns a plain error (not wrapped in this type) still gets
// exit code 1, unchanged from today -- this is additive, not a behavior
// change for any command that doesn't opt in.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string { return e.Err.Error() }
func (e *ExitCodeError) Unwrap() error { return e.Err }

// ExitUnhealthy wraps err to signal exit code 1: a configured target was
// reached (or a check was attempted) but reported unhealthy, or could not be
// reached at all.
func ExitUnhealthy(err error) error {
	return &ExitCodeError{Code: 1, Err: err}
}

// ExitUsageError wraps err to signal exit code 2: no usable configuration
// exists, or the command was invoked in a way that makes checking health
// impossible (e.g. `ping` with no remote storage configured).
func ExitUsageError(err error) error {
	return &ExitCodeError{Code: 2, Err: err}
}
