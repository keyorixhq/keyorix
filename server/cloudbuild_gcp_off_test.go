//go:build nogcp

package main

// buildHasGCP: this test binary was built with -tags nogcp. See requireCloudBuild.
const buildHasGCP = false
