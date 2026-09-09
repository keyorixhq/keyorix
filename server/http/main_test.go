package http

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestMain exists solely to lower the bcrypt work factor for this package's
// tests. internal/core/bcrypt_cost.go asks for it directly: "Production
// default is 12. Tests should call SetBcryptCostForTesting(bcrypt.MinCost) in
// TestMain to avoid slowing down the test suite." server/http/handlers/
// main_test.go already did; this package had no TestMain at all.
//
// It matters more here than anywhere else. Cost 12 is 2^8 = 256x the work of
// MinCost, and server/http carries 182 Password: fields across its tests
// (against 55 in handlers) plus 137 auth call sites -- and every FAILED-login
// test also pays a full hash, because auth.go hashes dummyBcryptHash as a
// timing equaliser on the user-not-found path so /auth/login cannot be used
// as a username-existence oracle.
//
// The mechanism is race-safe by construction: bcryptCost is an atomic.Int32
// specifically because SetBcryptCostForTesting is exported and nothing
// enforces its "call before any test runs" contract (#G63). Calling it here,
// before m.Run(), is the contract being honoured rather than relied upon.
func TestMain(m *testing.M) {
	core.SetBcryptCostForTesting(bcrypt.MinCost)
	os.Exit(m.Run())
}
