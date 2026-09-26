package encryption

import "github.com/keyorixhq/keyorix/internal/crypto"

// testFastKEKIterations is a throwaway PBKDF2 round count for tests that construct
// many KeyManagers/passphrase providers across a fuzz corpus and only care about the
// derivation's correctness (does rewrap/recovery round-trip?), not the real KDF's
// cost. Never crypto.PBKDF2Iterations, and never reachable outside a _test.go file —
// see crypto.NewPasswordKeyProviderWithIterations's doc comment and
// TestNewPasswordKeyProviderWithIterations_NoProductionCallers, which fails the build
// if any non-test file ever calls that constructor.
const testFastKEKIterations = 64

// fastPasswordProvider builds a crypto.KeyProvider with testFastKEKIterations instead
// of the real 600,000-round production KDF — byte-for-byte the same
// PasswordKeyProvider shape (salt handling, KEK derivation, wrap/unwrap format), just
// cheap enough to call dozens of times per fuzz seed without dominating the package's
// test time. Only safe where every provider touching the same wrapped material in a
// given test (seed, rewrap target, recovery attempts) uses this same helper — mixing
// a fast provider with a crypto.NewPasswordKeyProvider (real-iteration) provider over
// the same salt/passphrase pair produces a genuinely different KEK and an unwrap
// failure that looks like — but is not — a real bug.
func fastPasswordProvider(passphrase, baseDir, saltPath string) crypto.KeyProvider {
	return crypto.NewPasswordKeyProviderWithIterations(passphrase, baseDir, saltPath, testFastKEKIterations)
}
