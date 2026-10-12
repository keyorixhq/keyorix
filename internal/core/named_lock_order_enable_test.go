package core

import "github.com/keyorixhq/keyorix/internal/storage/store"

// C-GUARD-3 guard 3: every WithNamedLock acquisition this package's whole test
// suite makes through a real LocalStorage panics if it violates
// storage.NamedLockOrder. Tests built on MockStorage (mock_storage_test.go)
// bypass LocalStorage.WithNamedLock and are not checked.
func init() { store.EnableNamedLockOrderCheckForTesting() }
