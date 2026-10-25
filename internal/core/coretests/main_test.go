package coretests

// main_test.go — the process-wide test setup internal/core's own test binary has
// (sharing_test.go TestMain, named_lock_order_enable_test.go init), repeated here
// because these tests now run in a separate test binary and would lose it.

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// C-GUARD-3 guard 3 (same as internal/core): every WithNamedLock acquisition a test
// makes through a real LocalStorage panics if it violates storage.NamedLockOrder.
func init() { store.EnableNamedLockOrderCheckForTesting() }

func TestMain(m *testing.M) {
	if err := i18n.InitializeForTesting(); err != nil {
		panic("failed to initialize i18n for tests: " + err.Error())
	}
	// Production bcrypt cost is 12; see bcrypt_cost.go.
	core.SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
