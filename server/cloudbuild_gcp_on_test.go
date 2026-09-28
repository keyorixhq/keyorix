//go:build !nogcp

package main

// buildHasGCP reports whether this test binary links the GCP cloud SDK
// integrations (ADR-109 step 6). See requireCloudBuild.
const buildHasGCP = true
