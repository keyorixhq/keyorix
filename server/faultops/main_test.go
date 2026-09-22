package faultops

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestMain lowers the bcrypt work factor for this package's tests — see
// server/http/main_test.go's identical rationale. It matters MORE here: the
// STEP 1 profiling pass (profile_iteration_test.go) found bootstrap+login
// alone costs ~394ms of every ~400ms newFaultWorld spends, almost entirely
// bcrypt.GenerateFromPassword/CompareHashAndPassword at the production cost
// (12) — and FuzzStorageFaultOperations builds at least TWO fresh worlds
// (reference + faulted) per single fuzz iteration.
func TestMain(m *testing.M) {
	core.SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
