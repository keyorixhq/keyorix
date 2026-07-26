package handlers

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	// Lower the bcrypt cost from 12 to MinCost (4) for all tests in this
	// package. The handler tests exercise CreateUser and ChangePassword
	// extensively; at cost 12 the suite reliably exceeds the 600s CI timeout.
	core.SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
