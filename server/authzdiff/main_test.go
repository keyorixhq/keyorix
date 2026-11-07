package authzdiff

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestMain lowers the bcrypt work factor (core's documented test hook). The
// template seeds ~20 users and logs most of them in; at the production cost
// hashing alone was ~4.8 s of the default run. No authorization decision
// depends on the hash cost.
func TestMain(m *testing.M) {
	core.SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
