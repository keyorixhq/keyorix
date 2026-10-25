// Package storagetest is the shared storage test kit for internal/core's tests
// (ADR-121 decision 2, CORE-TESTKIT-1): the HookStore/StoreHooks/Hooked double, the
// testify MockStorage and the authz stubs that wire it.
//
// It is a non-test package so that both internal/core's in-package tests and its
// external (core_test) and, later, coretests packages can import it. It must be imported
// only from _test.go files (rule R3, internal/core/guards/test_only_packages_guard_test.go)
// and must never import internal/core (rule R1): core's in-package tests import this
// package, so the reverse edge would be an import cycle.
package storagetest
