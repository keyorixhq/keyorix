package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core"
)

// TestIsSafeSSOError_ReconcileRefusals (#2903 finding 1): a login refused over
// a failed group/role reconcile must reach the browser as the refusal's own
// text, so the affected user -- typically an administrator the IdP just
// changed -- has something diagnosable to report, rather than the generic
// "SSO login failed". The texts are referenced from core, not copied, so the
// allowlist cannot drift from what CompleteSAML/CompleteSSO actually return.
//
// RED before the fix: none of the three was on the allowlist.
func TestIsSafeSSOError_ReconcileRefusals(t *testing.T) {
	for _, msg := range []string{
		core.SSOMsgGroupReconcileRefused,
		core.SSOMsgRoleReconcileRefused,
		core.SSOMsgLastAdminRemovalRefused,
	} {
		assert.True(t, isSafeSSOError(msg), "expected %q to be safe", msg)
	}
}
