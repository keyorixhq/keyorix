package core

// storagetest_aliases_test.go — CORE-TESTKIT-1 (ADR-121 decision 2).
//
// hookStore, MockStorage and the authz stubs moved to internal/core/storage/storagetest
// so that other test packages can share them. These aliases keep every in-package test
// file that uses the old lower-case names compiling without an edit. Do not add logic here.

import "github.com/keyorixhq/keyorix/internal/core/storage/storagetest"

type (
	hookStore   = storagetest.HookStore
	storeHooks  = storagetest.StoreHooks
	MockStorage = storagetest.MockStorage
)

var (
	hooked = storagetest.Hooked

	stubAuthorizedPrincipal       = storagetest.StubAuthorizedPrincipal
	stubUnauthorizedPrincipal     = storagetest.StubUnauthorizedPrincipal
	stubAuthorizedSecretPrincipal = storagetest.StubAuthorizedSecretPrincipal
)
