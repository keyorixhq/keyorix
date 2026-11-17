//go:build noaws

package main

// boot_exit_aws_stub.go -- the noaws counterpart of boot_exit_aws.go: no AWS
// SDK is linked, so no error code is an AWS throttle code.

func isAWSThrottleCode(string) bool { return false }
