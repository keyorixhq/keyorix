package core

import (
	"testing"
	"time"
)

func TestJitterNBounds(t *testing.T) {
	for _, n := range []int64{-5, 0} {
		if got := jitterN(n); got != 0 {
			t.Fatalf("jitterN(%d) = %d, want 0", n, got)
		}
	}
	for range 200 {
		if got := jitterN(1); got != 0 {
			t.Fatalf("jitterN(1) = %d, want 0", got)
		}
		if got := jitterN(1000); got < 0 || got >= 1000 {
			t.Fatalf("jitterN(1000) = %d, outside [0,1000)", got)
		}
	}
}

func TestBackoffDelayJitterRange(t *testing.T) {
	a := &lastUsedCoalescer{}
	for n := range 6 {
		d := a.backoffDelay(n)
		if d < 0 || d > time.Hour {
			t.Fatalf("backoffDelay(%d) = %v, implausible", n, d)
		}
	}
}
