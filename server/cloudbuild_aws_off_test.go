//go:build noaws

package main

// buildHasAWS: this test binary was built with -tags noaws. See requireCloudBuild.
const buildHasAWS = false
