//go:build !noaws

package main

// boot_exit_aws.go -- the AWS half of the boot-exit classification
// (EDGE-STARTUP-NOV-1). It lives in its own file so that an air-gapped build
// (-tags noaws) does not link the AWS SDK just to classify an error;
// boot_exit_aws_stub.go is the counterpart that never matches.

import "github.com/aws/aws-sdk-go-v2/aws/retry"

// isAWSThrottleCode reports whether code is one of the error codes the AWS SDK
// itself retries as throttling.
func isAWSThrottleCode(code string) bool {
	_, throttled := retry.DefaultThrottleErrorCodes[code]
	return throttled
}
