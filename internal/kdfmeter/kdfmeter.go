// Package kdfmeter is the production-side seam for counting password-hash /
// key-derivation (KDF) invocations. Production code that hashes or verifies a
// credential calls GenerateFromPassword / CompareHashAndPassword here instead of
// golang.org/x/crypto/bcrypt directly, so a test harness (the KDFMeter in
// internal/fuzzutil/resguard) can count exactly how many bcrypt invocations a
// single logical operation performs.
//
// # Why this seam exists
//
// Account-enumeration timing side-channels on auth endpoints turn on whether the
// expensive KDF (bcrypt, ~milliseconds) runs the SAME number of times for an
// account that exists and one that does not. Keyorix already equalises this with
// a dummy-hash comparison on the not-found / locked paths (internal/core/auth.go,
// internal/core/account.go), but nothing MACHINE-CHECKED that the equalisation is
// actually balanced — a wall-clock test is flaky, and the resguard DBMeter counts
// DB round-trips, which is a different signal (a path can be DB-balanced yet
// KDF-unbalanced, which is exactly the enumeration bug). This seam makes the KDF
// invocation count a first-class, deterministic meter so an oracle can assert
// known-account and unknown-account cost parity exactly.
//
// # Zero cost when off
//
// With no observer installed (the production default) the only added work per call
// is a single atomic pointer load and a nil check; the bcrypt call itself is
// byte-for-byte identical to calling the library directly. No allocation, no lock.
//
// # Test-only enablement
//
// Installing an observer is test-only. SetObserver is exported only so the
// resguard KDFMeter can install its counter. That package is a normal (non-_test.go)
// file set kept test-only by TestResguardImportedOnlyFromTests, and is the one path
// TestKDFMeterSetObserver_NoProductionCallers excludes: that test fails the build if
// any other non-_test.go file references SetObserver. The observer must itself be
// cheap and non-blocking (resguard's is two atomic adds) because it runs inline on
// every credential op.
//
// # Only path to bcrypt
//
// TestBcryptImportedOnlyThroughKDFMeter fails if any production file outside a short,
// reasoned allowlist imports golang.org/x/crypto/bcrypt directly, since a direct call
// is invisible to the meter.
package kdfmeter

import (
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

// Op classifies a single KDF invocation for the observer. The two kinds are kept
// distinct because an enumeration oracle cares about them separately: a
// not-found login path must still spend one OpCompare (the dummy-hash equaliser),
// never an OpGenerate.
type Op uint8

const (
	// OpGenerate is a fresh password hash (bcrypt.GenerateFromPassword).
	OpGenerate Op = iota
	// OpCompare is a password verification (bcrypt.CompareHashAndPassword),
	// including the timing-equaliser dummy comparisons.
	OpCompare
)

// String renders an Op for logs/labels.
func (o Op) String() string {
	switch o {
	case OpGenerate:
		return "generate"
	case OpCompare:
		return "compare"
	default:
		return "unknown"
	}
}

// observer holds the installed invocation observer, or nil (the production
// default). atomic.Pointer so SetObserver races a concurrent credential op
// safely — the worst case is an in-flight call observing the previous observer,
// which is harmless for a counter.
var observer atomic.Pointer[func(Op)]

// notify fires the installed observer, if any. Inlinable; the hot path when no
// observer is installed is one atomic load and a nil branch.
func notify(op Op) {
	if o := observer.Load(); o != nil {
		(*o)(op)
	}
}

// GenerateFromPassword wraps bcrypt.GenerateFromPassword, recording one
// OpGenerate invocation before delegating. Behaviour and return values are
// identical to the wrapped function.
func GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	notify(OpGenerate)
	return bcrypt.GenerateFromPassword(password, cost)
}

// CompareHashAndPassword wraps bcrypt.CompareHashAndPassword, recording one
// OpCompare invocation before delegating. Behaviour and return values are
// identical to the wrapped function.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	notify(OpCompare)
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// SetObserver installs fn as the KDF invocation observer and returns the
// previously-installed observer (nil if none). Pass nil to uninstall. TEST-ONLY:
// see the package doc and TestKDFMeterSetObserver_NoProductionCallers. Safe to
// call concurrently with credential operations.
func SetObserver(fn func(Op)) func(Op) {
	var prev func(Op)
	if p := observer.Load(); p != nil {
		prev = *p
	}
	if fn == nil {
		observer.Store(nil)
	} else {
		observer.Store(&fn)
	}
	return prev
}
