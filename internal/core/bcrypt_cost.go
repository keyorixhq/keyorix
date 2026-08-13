package core

import (
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor for all password hashing. Production default is
// 12. Tests should call SetBcryptCostForTesting(bcrypt.MinCost) in TestMain to
// avoid slowing down the test suite.
//
// #G63: bcryptCost and dummyBcryptHash are both atomic (not a plain int/[]byte)
// — SetBcryptCostForTesting is exported and nothing enforces its documented
// "call before any test runs" contract, so a call racing a concurrent
// account.go/scim.go/users.go/auth.go password-hashing read is a real,
// unsynchronized data race (caught by `go test -race`), not just a
// theoretical one.
var bcryptCost atomic.Int32

// dummyBcryptHash is a fixed bcrypt hash used to equalize the timing of the
// user-not-found login path with the wrong-password path (auth.go), so
// /auth/login can't be used as a username-existence oracle.
var dummyBcryptHash atomic.Pointer[[]byte]

func init() {
	bcryptCost.Store(12)
	hash, _ := bcrypt.GenerateFromPassword([]byte("keyorix-login-timing-equalizer"), 12) // NOSONAR -- not a credential; timing-equalization sentinel
	dummyBcryptHash.Store(&hash)
}

// SetBcryptCostForTesting sets the bcrypt work factor and regenerates the
// timing-equalization dummy hash. Call this in TestMain before any test runs;
// do not call in production code.
func SetBcryptCostForTesting(cost int) {
	bcryptCost.Store(int32(cost)) // #nosec G115 -- test-only; bcrypt's own valid range is 4-31, far below int32's range
	// Regenerate so the dummy hash matches the test cost; otherwise the
	// timing-equalization constant is computed at cost 12 even in tests.
	hash, _ := bcrypt.GenerateFromPassword([]byte("keyorix-login-timing-equalizer"), cost) // NOSONAR
	dummyBcryptHash.Store(&hash)
}
