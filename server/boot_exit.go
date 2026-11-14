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
//	exitDependencyDown 75  a dependency that may come back (cloud KMS or
//	                       remote database unreachable, or a KMS answering
//	                       5xx/throttled): retry, but not every five
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
	"net/http"
	"net/url"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
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

// operatorFixWith is operatorFix for err prefixed by a message, "<prefix>: <err>"
// (the prefix may start with a capital: these lines predate the exit statuses
// and operators grep for them).
func operatorFixWith(prefix string, err error) error {
	return operatorFix(fmt.Errorf("%s: %w", prefix, err))
}

// isDependencyUnreachable reports whether err means the dependency may come
// back: either it did not answer (isNetworkFailure) or it answered that it
// cannot serve right now (isServiceUnavailable). A KMS or database that
// replied "no" is a configuration problem; one that did not reply, or replied
// "not now", may come back.
func isDependencyUnreachable(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return isNetworkFailure(err) || isServiceUnavailable(err) || isTokenRequestUnanswered(err)
}

// isNetworkFailure reports whether err is a network-level failure (refused,
// unreachable, DNS, timed out). A *url.Error is a net.Error whatever its
// cause, so for one it is the cause that decides: a TLS certificate the host
// does not trust, wrapped in a *url.Error, is not a network failure.
func isNetworkFailure(err error) bool {
	var ne net.Error
	if !errors.As(err, &ne) {
		return false
	}
	if ue, ok := ne.(*url.Error); ok {
		return ue.Timeout() || isNetworkFailure(ue.Err)
	}
	return true
}

// The error shapes isServiceUnavailable reads, by method so this file needs
// no SDK-internal types: httpStatusError is the AWS SDK's response error,
// apiCodeError its API error (smithy.APIError), grpcStatusError a gRPC status
// (the GCP KMS client).
type (
	httpStatusError interface {
		error
		HTTPStatusCode() int
	}
	apiCodeError interface {
		error
		ErrorCode() string
	}
	grpcStatusError interface {
		error
		GRPCStatus() *status.Status
	}
)

// isServiceUnavailable reports whether err is an answer from a cloud KMS that
// says "not now" rather than "no": a server-side failure (HTTP 5xx, gRPC
// UNAVAILABLE/INTERNAL/DEADLINE_EXCEEDED) or throttling (HTTP 429, AWS's
// throttle error codes, gRPC RESOURCE_EXHAUSTED). The SDKs retry exactly
// these; a refusal (access denied, key not found or disabled, bad
// ciphertext: HTTP 4xx, gRPC PERMISSION_DENIED/NOT_FOUND/...) is not one.
//
// Recognised shapes, one per provider SDK this server links: the AWS SDK's
// response error (HTTPStatusCode()) and API error (ErrorCode()), Azure's
// *azcore.ResponseError, and a gRPC status (GCP, GRPCStatus()).
func isServiceUnavailable(err error) bool {
	if he, ok := errors.AsType[httpStatusError](err); ok && transientHTTP(he.HTTPStatusCode()) {
		return true
	}
	if ae, ok := errors.AsType[apiCodeError](err); ok {
		if _, throttled := retry.DefaultThrottleErrorCodes[ae.ErrorCode()]; throttled {
			return true
		}
	}
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok && transientHTTP(re.StatusCode) {
		return true
	}
	if _, ok := errors.AsType[grpcStatusError](err); ok {
		switch status.Code(err) {
		case codes.Unavailable, codes.Internal, codes.DeadlineExceeded, codes.ResourceExhausted:
			return true
		}
	}
	return false
}

// isTokenRequestUnanswered reports whether err is an Azure token request
// (azure-kms authenticates to Entra ID before it calls the vault) that got no
// answer or a "not now" answer. azidentity's *AuthenticationFailedError keeps
// the cause of a request that failed (a refused dial, a DNS failure, a
// timeout) only as message text, with no Unwrap, so isNetworkFailure cannot
// see it; its RawResponse is nil exactly when Entra ID did not answer. An
// answer of 5xx or 429 may come back too. Any other answer (400 invalid_client,
// 401: a wrong secret or application) is a refusal. No credential configured
// at all is azidentity's credentialUnavailableError, a different type, and
// stays a refusal.
//
// What this does not tell apart: a nil RawResponse also covers a local failure
// inside azidentity before the request (a client assertion that could not be
// read). That is retried rather than stopped, the direction that fails soft.
func isTokenRequestUnanswered(err error) bool {
	afe, ok := errors.AsType[*azidentity.AuthenticationFailedError](err)
	if !ok {
		return false
	}
	if afe.RawResponse == nil {
		return true
	}
	return transientHTTP(afe.RawResponse.StatusCode)
}

// transientHTTP reports whether an HTTP answer says "not now": 5xx or 429.
func transientHTTP(code int) bool {
	return code >= http.StatusInternalServerError || code == http.StatusTooManyRequests
}

// operatorFixUnlessUnreachable is operatorFix for a step that may also fail
// because something it talks to is down or overloaded: that stays unmarked so
// bootExitCode reports it as a dependency.
func operatorFixUnlessUnreachable(err error) error {
	if isDependencyUnreachable(err) {
		return err
	}
	return operatorFix(err)
}

// poolerStepError classifies an error from
// appstorage.RefuseUndeclaredTransactionPooler. Only the pooler refusal itself
// is an operator fix. That step is also the first one that connects to
// Postgres, so every other error from it (a database that is down, starting up
// or out of connections) stays unmarked and bootExitCode retries it.
func poolerStepError(err error) error {
	if _, ok := errors.AsType[*appstorage.UndeclaredTransactionPoolerError](err); ok {
		return operatorFix(err)
	}
	return err
}

// bootExitCode is the exit status for a boot failure err. An explicit mark
// wins; otherwise a database authentication failure needs an operator and an
// unreachable dependency may recover. Anything else stays 1.
//
// Only a login the database answered with an authentication SQLSTATE is 78. A
// connection closed during start-up (PostgresAuthError.ClosedDuringStartup) is
// a guess: a proxy or pooler in front of a backend that is down, or a Postgres
// that is restarting, closes it the same way, so it falls through and is
// retried.
func bootExitCode(err error) int {
	if be, ok := errors.AsType[*bootError](err); ok {
		return be.code
	}
	if pae, ok := errors.AsType[*config.PostgresAuthError](err); ok && !pae.ClosedDuringStartup {
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
