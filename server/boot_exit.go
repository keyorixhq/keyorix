package main

// boot_exit.go -- exit statuses for a boot that fails (EDGE-STARTUP-NOV-1).
//
// A service manager can only act on a failure it can tell apart. Under the
// shipped systemd unit (deploy/edge/keyorix-server.service) every exit used to
// become a restart five seconds later, whether or not waiting could help.
// Three classes, by what the operator or the supervisor should do:
//
//	exitOperatorFix    78  refused configuration or missing/unusable key
//	                       material: restarting cannot help; stop and tell
//	                       the operator. (sysexits EX_CONFIG)
//	exitDependencyDown 75  a dependency that may come back (cloud KMS,
//	                       remote database): retry, but not every five
//	                       seconds. (sysexits EX_TEMPFAIL)
//	1                      everything else, as before: a crash, a port that
//	                       is in use, a lost lock.
//
// deploy/edge/keyorix-server.service names these numbers in
// RestartPreventExitStatus= (78); 75 is retried at RestartSec=.
// deploy/edge/edge_exit_codes_test.go parses the unit and fails when the
// numbers there and the constants here differ. Both exit statuses are
// documented in docs/edge-deployment.md §7a.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
)

const (
	exitOperatorFix    = 78
	exitDependencyDown = 75
)

// bootError carries the exit status a failed boot step wants. It wraps the
// original error, so errors.Is/As and the logged text are unchanged.
type bootError struct {
	code int
	err  error
}

func (e *bootError) Error() string { return e.err.Error() }
func (e *bootError) Unwrap() error { return e.err }

// operatorFix marks err as something only an operator can fix.
func operatorFix(err error) error {
	if err == nil {
		return nil
	}
	return &bootError{code: exitOperatorFix, err: err}
}

// isDependencyUnreachable reports whether err is a network-level failure
// (refused, unreachable, DNS, timed out) rather than an answer from the
// dependency: a KMS or database that replied "no" is a configuration problem,
// one that did not reply may come back.
func isDependencyUnreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// operatorFixUnlessUnreachable is operatorFix for a step that may also fail
// because something it talks to is down: that stays unmarked so bootExitCode
// reports it as a dependency.
func operatorFixUnlessUnreachable(err error) error {
	if isDependencyUnreachable(err) {
		return err
	}
	return operatorFix(err)
}

// bootExitCode is the exit status for a boot failure err. An explicit mark
// wins; otherwise a database authentication failure needs an operator and an
// unreachable dependency may recover. Anything else stays 1.
func bootExitCode(err error) int {
	if be, ok := errors.AsType[*bootError](err); ok {
		return be.code
	}
	if _, ok := errors.AsType[*config.PostgresAuthError](err); ok {
		return exitOperatorFix
	}
	if isDependencyUnreachable(err) {
		return exitDependencyDown
	}
	return 1
}

// bootHint is the one line printed last on stderr for each class. It never
// repeats the error, so it cannot carry a secret or a path the log lines above
// do not already carry.
func bootHint(code int) string {
	switch code {
	case exitOperatorFix:
		return "keyorix-server: exit 78 (operator action required): the configuration or key material was refused; " +
			"read the error above, fix it, then start the service again. Restarting without a fix will fail the same way."
	case exitDependencyDown:
		return "keyorix-server: exit 75 (dependency unavailable): the KMS or database could not be reached; " +
			"the server did not start. Check the network and the service it names above; start it again once it is back."
	}
	return ""
}

// bootFatal logs err the way log.Fatalf did, adds the operator hint for its
// class and exits with that class's status.
func bootFatal(err error) {
	code := bootExitCode(err)
	log.Print(err)
	// Straight to stderr, not through log: with server.log.format "json" the
	// logger would wrap the hint in a JSON object, and the hint must stay one
	// plain last line a person reads in `journalctl`.
	if hint := bootHint(code); hint != "" {
		fmt.Fprintln(os.Stderr, hint)
	}
	os.Exit(code)
}
