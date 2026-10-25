// Package coretests holds the black-box tests of internal/core: tests that use only
// core's exported API (and the shared doubles in internal/core/storage/storagetest).
//
// It is test-only (ADR-121 decision 2): only _test.go files plus this file, nothing
// imports it, and no production file may import it. It is ONE package on purpose:
// every extra test package that imports core links another test binary on every
// change to core. A test whose file needs an unexported core symbol, or that is a
// fuzz target, reads testdata, needs PostgreSQL, registers an init() registry
// entry, scans source, or is named by a ledger row, stays in internal/core.
package coretests
