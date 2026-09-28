//go:build !noazure

package main

// buildHasAzure reports whether this test binary links the Azure cloud SDK
// integrations (ADR-109 step 6). See requireCloudBuild.
const buildHasAzure = true
