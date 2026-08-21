// g80_helpers_test.go — shared test helpers for the g80 coverage-uplift round
// (internal/encryption statement coverage 89.1% baseline).
//
// withFailingRand / withLimitedThenFailingRand swap crypto/rand.Reader for the
// duration of a callback, following the same pattern already established in
// internal/crypto/coverage_test.go ("crypto/rand.Reader is a package-level var,
// so swapping it for the duration of a test ... is a legitimate way to reach an
// otherwise-untriggerable error path"). This package has no t.Parallel anywhere
// (verified: every test in this package runs sequentially), so the swap is safe.
package encryption

import (
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// g80FailingReader is an io.Reader that always fails.
type g80FailingReader struct{}

func (g80FailingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("g80: injected rand failure")
}

// withFailingRand swaps crypto/rand.Reader for the duration of fn so that any
// io.ReadFull(rand.Reader, ...)/rand.Read call made by fn fails deterministically,
// then restores the original reader — even if fn panics.
func withFailingRand(t *testing.T, fn func()) {
	t.Helper()
	old := rand.Reader
	rand.Reader = g80FailingReader{}
	defer func() { rand.Reader = old }()
	fn()
}

// g80LimitedThenFailingReader lets the first n bytes read successfully (from the
// real crypto/rand reader) and fails every read after that. Used to let an EARLIER
// rand.Read call in the same code path (e.g. a salt/newSalt generation) succeed
// while forcing a LATER one (e.g. a nonce generation inside a nested call) to fail
// — reaching an inner error branch without also tripping an outer one.
type g80LimitedThenFailingReader struct {
	real      io.Reader
	remaining int
}

func (r *g80LimitedThenFailingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, errors.New("g80: injected rand failure after budget exhausted")
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.real.Read(p)
	r.remaining -= n
	return n, err
}

// withRandFailingAfter swaps crypto/rand.Reader so the first n bytes read succeed
// normally and every byte after that fails, then restores the original reader.
func withRandFailingAfter(t *testing.T, n int, fn func()) {
	t.Helper()
	old := rand.Reader
	rand.Reader = &g80LimitedThenFailingReader{real: old, remaining: n}
	defer func() { rand.Reader = old }()
	fn()
}
