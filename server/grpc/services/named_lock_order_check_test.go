package services

import "github.com/keyorixhq/keyorix/internal/core/storage"

// Every WithNamedLock acquisition this package's tests drive through a real
// LocalStorage is checked against storage.NamedLockOrder; an out-of-order
// acquisition panics at the acquiring call site (C-GUARD-3 item 3).
func init() { storage.EnableNamedLockOrderCheck() }
