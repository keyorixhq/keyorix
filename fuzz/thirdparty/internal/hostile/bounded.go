package hostile

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// WaitBounded is the bounded-time oracle of the hostile-server harnesses. It delegates to
// fuzzutil.WaitBounded, which separates a hung driver call from a frozen fuzz process (see
// internal/fuzzutil/stall.go) before reporting a violation.
func WaitBounded(tb testing.TB, done <-chan struct{}, limit time.Duration, msg string) {
	tb.Helper()
	fuzzutil.WaitBounded(tb, done, limit, msg)
}
