//go:build !noaws

package main

// buildHasAWS reports whether this test binary links the AWS cloud SDK
// integrations (ADR-109 step 6). See requireCloudBuild.
const buildHasAWS = true
