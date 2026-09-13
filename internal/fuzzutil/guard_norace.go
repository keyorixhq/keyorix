//go:build !race

package fuzzutil

// Without the race detector the native GuardTimeout applies unchanged (3s).
const guardTimeoutScale = 1
