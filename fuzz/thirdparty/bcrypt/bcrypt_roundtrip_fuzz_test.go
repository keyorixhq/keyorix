// Reachability-first fuzz harness for golang.org/x/crypto/bcrypt, the password
// hasher Keyorix uses on every login and password change.
//
// Live callers (traced from reachgen, 9 untrusted sites):
//   - internal/core/auth.go:76      bcrypt.CompareHashAndPassword(user.PasswordHash, password)
//   - internal/core/account.go:123  bcrypt.CompareHashAndPassword(user.PasswordHash, password)
//   - internal/core/users.go:131    bcrypt.GenerateFromPassword(req.Password, cost)
//   - ...and the dummy-hash constant-time paths (auth.go:54/73, account.go:120).
//
// The hash bytes come from storage (a DB row) and the password from the login
// request; both are untrusted in the relevant threat models.
//
// Oracles (sound):
//  1. Round-trip + fail-closed: for any password p (<=72 bytes, bcrypt's own
//     limit), h = GenerateFromPassword(p, MinCost) must verify p (err==nil)
//     and must REJECT a different password (err!=nil). A hasher that accepts
//     the wrong password, or rejects the right one, is broken.
//  2. Hostile-hash robustness: CompareHashAndPassword on arbitrary bytes must
//     not panic and must return (it may legitimately return nil IF the bytes
//     happen to be a valid hash of p — so we assert no-panic/returns, not a
//     verdict). Inputs whose DECLARED cost is large are skipped BEFORE the
//     compare: bcrypt will actually run 2^cost rounds, so a cost=31 hash is a
//     genuine CPU bomb — we bound the fuzzer instead of hanging it, and record
//     the cost-bomb as a documented property (see report), not a library bug.
//
// What these oracles do NOT verify:
//   - NOT the cryptographic strength or constant-time property of bcrypt.
//   - NOT any timing side-channel (the dummy-hash equal-time path is untested).
//   - NOT cost>MinCost round-trips (deliberately bounded to keep the fuzzer
//     fast; the cost field's DoS behaviour is documented, not fuzzed into a
//     hang).
//   - NOT that the stored-hash column is well-formed in production (that is a
//     storage invariant, not a bcrypt property).
package bcrypthostile

import (
	"bytes"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"golang.org/x/crypto/bcrypt"
)

func FuzzBcryptRoundTripHostileHash(f *testing.F) {
	f.Add([]byte("correct horse battery staple"), []byte("$2a$04$abcdefghijklmnopqrstuu"))
	f.Add([]byte(""), []byte("not-a-hash"))
	f.Add([]byte("p"), []byte("$2a$31$this.declares.cost.31.cpu.bomb.xxxxxxxxxxxxxxxxxxxxxx"))

	// PK2: resguard resource oracle (see resguard_bcrypt_test.go). Records cost
	// every input; the FATAL meter is alloc (a tripwire). cpu_ns/wall_ns are
	// advisory; the cost-bomb stays guarded by the cost-skip below.
	rgBudget, rgErr := resguard.LoadBudget(rgBudgetPath)
	rgHaveBudget := rgErr == nil
	rgProbe := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, password, hostileHash []byte) {
		n := len(password) + len(hostileHash)
		c := rgProbe.Measure(n, func() { rgRun(password, hostileHash) })
		resguard.FeedCoverage(c)
		if rgHaveBudget {
			rgBudget.Check(t.Fatalf, c)
		}

		// bcrypt refuses passwords > 72 bytes; keep within its domain for the
		// round-trip oracle (longer inputs just get an error on Generate).
		if len(password) > 72 {
			password = password[:72]
		}

		// --- Oracle 1: round-trip + fail-closed ---
		h, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
		if err != nil {
			t.Fatalf("GenerateFromPassword(MinCost) failed for %q: %v", password, err)
		}
		if err := roundTripVerify(h, password); err != nil {
			t.Fatalf("round-trip: correct password %q did NOT verify: %v", password, err)
		}
		// A different password must be rejected (fail-closed). Flip the first
		// byte (or append) to guarantee a distinct password.
		wrong := wrongPassword(password)
		if !bytes.Equal(wrong, password) {
			if err := bcrypt.CompareHashAndPassword(h, wrong); err == nil {
				t.Fatalf("fail-closed: wrong password %q was ACCEPTED for hash of %q", wrong, password)
			}
		}

		// --- Oracle 2: hostile hash must not panic / must return, bounded ---
		// Guard against the cost-bomb: only compare hashes whose declared cost
		// is sane, else bcrypt would spin 2^cost rounds.
		if cost, cerr := bcrypt.Cost(hostileHash); cerr == nil && cost <= bcrypt.DefaultCost {
			// Return value intentionally ignored: a garbage hash normally
			// errors, but could legitimately match; we only assert no panic.
			_ = bcrypt.CompareHashAndPassword(hostileHash, password)
		}
	})
}

// roundTripVerify is factored out so the red-proof can plant a defect here in a
// scratch copy (e.g. `return bcrypt.CompareHashAndPassword(h[:len(h)-1], pw)`,
// corrupting the hash) and watch the "correct password did NOT verify"
// assertion fire while the unmodified path stays green.
func roundTripVerify(h, pw []byte) error {
	return bcrypt.CompareHashAndPassword(h, pw)
}

func wrongPassword(pw []byte) []byte {
	w := make([]byte, len(pw))
	copy(w, pw)
	if len(w) == 0 {
		return []byte("x")
	}
	w[0] ^= 0x01
	return w
}
