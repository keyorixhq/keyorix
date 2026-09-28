//go:build noazure

package main

// buildHasAzure: this test binary was built with -tags noazure. See requireCloudBuild.
const buildHasAzure = false
