package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/config"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
)

func TestBootExitCode_Classes(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unclassified stays 1", errors.New("port already in use"), 1},
		{"marked operator fix", operatorFix(errors.New("bad config")), exitOperatorFix},
		{"mark survives wrapping", fmt.Errorf("failed to initialize core service: %w", operatorFix(errors.New("x"))), exitOperatorFix},
		{"database login refused", fmt.Errorf("storage: %w", &config.PostgresAuthError{}), exitOperatorFix},
		// REVIEW-4213 F3: a connection closed during start-up is also what a
		// proxy in front of a down backend, or a restarting Postgres, does.
		{"connection closed during start-up is not 78", fmt.Errorf("storage: %w", &config.PostgresAuthError{ClosedDuringStartup: true}), 1},
		{"network refusal", fmt.Errorf("KMS: %w", refused), exitDependencyDown},
		{"deadline", fmt.Errorf("KMS: %w", context.DeadlineExceeded), exitDependencyDown},
		{"operator fix unless unreachable: plain", operatorFixUnlessUnreachable(errors.New("wrong passphrase")), exitOperatorFix},
		{"operator fix unless unreachable: network", operatorFixUnlessUnreachable(fmt.Errorf("kms: %w", refused)), exitDependencyDown},
		{"nil mark stays nil", operatorFix(nil), 0},
		// REVIEW-4213 LOW: a *url.Error is a net.Error whatever its cause; a TLS
		// trust failure inside one is a refusal, not a network failure.
		{"tls trust failure in url.Error", operatorFixUnlessUnreachable(fmt.Errorf("kms: %w", &url.Error{Op: "Post", URL: "https://kms", Err: x509.UnknownAuthorityError{}})), exitOperatorFix},
		{"refusal in url.Error", fmt.Errorf("kms: %w", &url.Error{Op: "Post", URL: "https://kms", Err: refused}), exitDependencyDown},
	}
	for _, tc := range cases {
		if tc.err == nil {
			if tc.want != 0 {
				t.Errorf("%s: got nil error", tc.name)
			}
			continue
		}
		if got := bootExitCode(tc.err); got != tc.want {
			t.Errorf("%s: bootExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// REVIEW-4213 F1: the pooler tripwire is the first boot step that connects to
// Postgres; only its pooler refusal is an operator fix.
func TestBootExitCode_PoolerStep(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"undeclared pooler", &appstorage.UndeclaredTransactionPoolerError{PID: 7}, exitOperatorFix},
		{"database down", fmt.Errorf("failed to connect to postgres: %w", refused), exitDependencyDown},
		{"database starting up", fmt.Errorf("failed to connect to postgres: %w", &pgconn.PgError{Code: "57P03"}), 1},
		{"too many connections", fmt.Errorf("failed to connect to postgres: %w", &pgconn.PgError{Code: "53300"}), 1},
		{"login refused", fmt.Errorf("storage: %w", &config.PostgresAuthError{}), exitOperatorFix},
	}
	for _, tc := range cases {
		if got := bootExitCode(poolerStepError(tc.err)); got != tc.want {
			t.Errorf("%s: bootExitCode(poolerStepError) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// kmsStartupError wraps err the way a failed KEK fetch at boot does.
func kmsStartupError(provider string, err error) error {
	return operatorFixUnlessUnreachable(fmt.Errorf("KEK from key provider %q failed: %w", provider, err))
}

// REVIEW-4213 F2: a KMS that answered "not now" (5xx, throttled) may come
// back; one that answered "no" (4xx refusal) needs an operator. The AWS and
// Azure answers are in boot_exit_aws_test.go and boot_exit_azure_test.go (they
// need their SDK, which the noaws/noazure builds do not link).
func TestBootExitCode_KMSAnswers(t *testing.T) {
	kms := func(err error) error { return kmsStartupError("gcp-kms", err) }
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"gcp unavailable", kms(status.Error(codes.Unavailable, "x")), exitDependencyDown},
		{"gcp internal", kms(status.Error(codes.Internal, "x")), exitDependencyDown},
		{"gcp resource exhausted", kms(status.Error(codes.ResourceExhausted, "x")), exitDependencyDown},
		{"gcp permission denied", kms(status.Error(codes.PermissionDenied, "x")), exitOperatorFix},
		{"gcp not found", kms(status.Error(codes.NotFound, "x")), exitOperatorFix},
		{"gcp failed precondition", kms(status.Error(codes.FailedPrecondition, "x")), exitOperatorFix},
	}
	for _, tc := range cases {
		if tc.err == nil {
			if tc.want != 0 {
				t.Errorf("%s: got nil error", tc.name)
			}
			continue
		}
		if got := bootExitCode(tc.err); got != tc.want {
			t.Errorf("%s: bootExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestBootExitCode_MessageUnchanged(t *testing.T) {
	inner := errors.New("open ./pass: no such file or directory")
	if got := operatorFix(inner).Error(); got != inner.Error() {
		t.Errorf("operatorFix changed the logged text: %q", got)
	}
}

func TestBootHint_OneLineNoSecretsOnlyForClassified(t *testing.T) {
	for _, code := range []int{exitOperatorFix, exitDependencyDown} {
		h := bootHint(code)
		if h == "" || strings.Contains(h, "\n") {
			t.Errorf("hint for %d must be one non-empty line, got %q", code, h)
		}
		if !strings.HasPrefix(h, fmt.Sprintf("keyorix-server: exit %d ", code)) {
			t.Errorf("hint for %d must start with the status: %q", code, h)
		}
	}
	if h := bootHint(1); h != "" {
		t.Errorf("exit 1 must stay as before, got hint %q", h)
	}
}
