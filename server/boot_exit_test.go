package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
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
		{"network refusal", fmt.Errorf("KMS: %w", refused), exitDependencyDown},
		{"deadline", fmt.Errorf("KMS: %w", context.DeadlineExceeded), exitDependencyDown},
		{"operator fix unless unreachable: plain", operatorFixUnlessUnreachable(errors.New("wrong passphrase")), exitOperatorFix},
		{"operator fix unless unreachable: network", operatorFixUnlessUnreachable(fmt.Errorf("kms: %w", refused)), exitDependencyDown},
		{"nil mark stays nil", operatorFix(nil), 0},
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
