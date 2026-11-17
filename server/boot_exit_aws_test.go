//go:build !noaws

package main

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
)

// awsResponseError mimics the AWS SDK's response error (awshttp.ResponseError
// over smithyhttp.ResponseError) and API error (smithy.GenericAPIError) by
// method, the way isServiceUnavailable reads them.
type awsResponseError struct {
	status int
	code   string
}

func (e *awsResponseError) Error() string       { return fmt.Sprintf("StatusCode: %d, %s", e.status, e.code) }
func (e *awsResponseError) HTTPStatusCode() int { return e.status }
func (e *awsResponseError) ErrorCode() string   { return e.code }

// REVIEW-4213 F2, AWS answers: "not now" (5xx, throttled) may come back; "no"
// (4xx refusal) needs an operator.
func TestBootExitCode_KMSAnswers_AWS(t *testing.T) {
	kms := func(err error) error { return kmsStartupError("aws-kms", err) }
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"aws 500 internal", kms(&retry.MaxAttemptsError{Attempt: 3, Err: &awsResponseError{500, "KMSInternalException"}}), exitDependencyDown},
		{"aws 503 dependency timeout", kms(&awsResponseError{503, "DependencyTimeoutException"}), exitDependencyDown},
		{"aws 400 throttling", kms(&awsResponseError{400, "ThrottlingException"}), exitDependencyDown},
		{"aws 429", kms(&awsResponseError{429, "TooManyRequests"}), exitDependencyDown},
		{"aws 400 access denied", kms(&awsResponseError{400, "AccessDeniedException"}), exitOperatorFix},
		{"aws 400 not found", kms(&awsResponseError{400, "NotFoundException"}), exitOperatorFix},
		{"aws 400 invalid ciphertext", kms(&awsResponseError{400, "InvalidCiphertextException"}), exitOperatorFix},
		{"aws 400 disabled key", kms(&awsResponseError{400, "DisabledException"}), exitOperatorFix},
	}
	for _, tc := range cases {
		if got := bootExitCode(tc.err); got != tc.want {
			t.Errorf("%s: bootExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}
