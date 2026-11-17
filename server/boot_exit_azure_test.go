//go:build !noazure

package main

import (
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// REVIEW-4213 F2, Azure answers: "not now" (5xx, throttled) may come back;
// "no" (4xx refusal) needs an operator.
func TestBootExitCode_KMSAnswers_Azure(t *testing.T) {
	kms := func(err error) error { return kmsStartupError("azure-kms", err) }
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"azure 503", kms(&azcore.ResponseError{StatusCode: http.StatusServiceUnavailable}), exitDependencyDown},
		{"azure 429", kms(&azcore.ResponseError{StatusCode: http.StatusTooManyRequests}), exitDependencyDown},
		{"azure 403", kms(&azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden"}), exitOperatorFix},
	}
	for _, tc := range cases {
		if got := bootExitCode(tc.err); got != tc.want {
			t.Errorf("%s: bootExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}
