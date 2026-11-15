package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// SUSPEND-TAILS-NOV-1 item 2: the core error text of a refused clear-synced-copies
// suspend says that suspending without clearing cuts access now, so a caller that
// prints err.Error() (not the transports' fixed message) is not left with "retry" alone.
func TestSuspendAuditRefusalErrors_SayPlainSuspendCutsAccessNow(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"single secret":   ErrSuspendAuditUnavailable,
		"project-wide":    ErrBulkSuspendAuditUnavailable,
		"partial refusal": &BulkSuspendPartialError{Suspended: 1, Failed: 2, AuditRefused: true},
	} {
		assert.Contains(t, err.Error(), SuspendWithoutClearingHint, name)
	}
}
