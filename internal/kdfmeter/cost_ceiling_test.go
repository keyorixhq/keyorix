package kdfmeter_test

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/kdfmeter"
)

// withCost rewrites the cost field of a bcrypt hash ("$2a$NN$...") without
// recomputing it. bcrypt.Cost reads only that header, so the result looks like a
// hash generated at the requested cost; it cannot verify, which is fine for a
// test whose point is that the KDF is never started.
func withCost(t *testing.T, hash []byte, cost int) []byte {
	t.Helper()
	out := append([]byte(nil), hash...)
	out[4] = byte('0' + cost/10)
	out[5] = byte('0' + cost%10)
	if got, err := bcrypt.Cost(out); err != nil || got != cost {
		t.Fatalf("withCost(%d): bcrypt.Cost = %d, %v", cost, got, err)
	}
	return out
}

// TestCompareHashAndPassword_RefusesCostAboveCeiling is the red/green proof for
// INV-KDFMETER-compare-cost-ceiling. Without the ceiling the call below starts
// 2^31 bcrypt rounds (minutes of CPU), so the result is read with a deadline: red
// is "did not return", not a hang of the whole test binary.
func TestCompareHashAndPassword_RefusesCostAboveCeiling(t *testing.T) {
	base, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, cost := range []int{kdfmeter.MaxCompareCost + 1, bcrypt.MaxCost} {
		hash := withCost(t, base, cost)
		done := make(chan error, 1)
		go func() { done <- kdfmeter.CompareHashAndPassword(hash, []byte("pw")) }()
		select {
		case err := <-done:
			if !errors.Is(err, kdfmeter.ErrHashCostTooHigh) {
				t.Fatalf("cost %d: err = %v, want ErrHashCostTooHigh", cost, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("cost %d: CompareHashAndPassword still running after 5s; the cost ceiling did not stop the KDF", cost)
		}
	}
}

// TestCompareHashAndPassword_CeilingKeepsOneCountPerCall guards the other
// invariant the early return could break: a refused hash is still one OpCompare.
func TestCompareHashAndPassword_CeilingKeepsOneCountPerCall(t *testing.T) {
	base, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var cmp int
	prev := kdfmeter.SetObserver(func(op kdfmeter.Op) {
		if op == kdfmeter.OpCompare {
			cmp++
		}
	})
	t.Cleanup(func() { kdfmeter.SetObserver(prev) })

	hash := withCost(t, base, bcrypt.MaxCost)
	done := make(chan struct{})
	go func() {
		_ = kdfmeter.CompareHashAndPassword(hash, []byte("pw"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CompareHashAndPassword still running after 5s; the cost ceiling did not stop the KDF")
	}
	if cmp != 1 {
		t.Fatalf("OpCompare count for a refused hash = %d, want 1", cmp)
	}
}

// TestCompareHashAndPassword_NormalHashesUnaffected is the green half: hashes at
// and below the default cost still verify and still fail on a wrong password, and
// a malformed hash keeps bcrypt's own error rather than ErrHashCostTooHigh.
func TestCompareHashAndPassword_NormalHashesUnaffected(t *testing.T) {
	hash, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("pw")); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	if err := kdfmeter.CompareHashAndPassword(hash, []byte("nope")); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("wrong password: err = %v, want ErrMismatchedHashAndPassword", err)
	}
	err = kdfmeter.CompareHashAndPassword([]byte("not-a-bcrypt-hash"), []byte("pw"))
	if err == nil || errors.Is(err, kdfmeter.ErrHashCostTooHigh) {
		t.Fatalf("malformed hash: err = %v, want a bcrypt error", err)
	}
}
