package core

import "golang.org/x/crypto/bcrypt"

// bcryptCost is the work factor for all password hashing. Production default is
// 12. Tests should call SetBcryptCostForTesting(bcrypt.MinCost) in TestMain to
// avoid slowing down the test suite.
var bcryptCost = 12

// SetBcryptCostForTesting sets the bcrypt work factor and regenerates the
// timing-equalization dummy hash. Call this in TestMain before any test runs;
// do not call in production code.
func SetBcryptCostForTesting(cost int) {
	bcryptCost = cost
	// Regenerate so the dummy hash matches the test cost; otherwise the
	// timing-equalization constant is computed at cost 12 even in tests.
	dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("keyorix-login-timing-equalizer"), cost) // NOSONAR
}
