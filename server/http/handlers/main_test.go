package handlers

import (
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// Lower the bcrypt cost from 12 to MinCost (4) for all tests in this
	// package. The handler tests exercise CreateUser and ChangePassword
	// extensively; at cost 12 the suite reliably exceeds the 600s CI timeout.
	core.SetBcryptCostForTesting(bcrypt.MinCost)

	code := m.Run()

	// Runs after every test has completed, so it sees the full set of
	// operations AssertOpenAPIResponse recorded as exercised -- see
	// ADR-074, "Coverage assertion: enforced must mean exercised", and
	// CheckAllEnforcedExercised's doc comment for how this stays correct
	// under CI's handlers-1..4 sharding.
	if err := contracttest.CheckAllEnforcedExercised(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}

	os.Exit(code)
}
