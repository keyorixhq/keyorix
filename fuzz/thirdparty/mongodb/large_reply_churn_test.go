package mongofuzz

import (
	"bytes"
	"testing"
)

// TestKFZ2026130ReconnectChurnLargeReplyWithinBudget is the KFZ-2026-130 churn
// with a larger reply body behind the same invalid section kind. The driver's
// cost per connection grows with the reply it reads, so a fixed per-dial budget
// fails here (review of #4413: pad 8192 and up were 3/3 red at d94be65). The
// bytes-read term of the budget must cover it, up to the maxWireLen clamp.
func TestKFZ2026130ReconnectChurnLargeReplyWithinBudget(t *testing.T) {
	for _, pad := range []int{0, 8192, 16384, 32768, 65000} {
		body := append([]byte("20000"), bytes.Repeat([]byte{'0'}, pad)...)
		for range 3 {
			runInteraction(t, 0, 0, 44, 0, body)
		}
	}
}
