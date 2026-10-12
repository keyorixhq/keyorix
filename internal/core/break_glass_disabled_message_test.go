package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/require"
)

// #2943: break-glass is disabled by default (deliberate). The refusal used to be
// the bare "permission denied", indistinguishable from a real role problem. It
// must stay a refusal (fail closed) but say the feature is off and which key
// enables it. The "permission denied" prefix is what the HTTP handler maps to 403.
func TestActivateBreakGlass_DisabledSaysSoAndHowToEnable(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateBreakGlass(t, h)
	// No SetBreakGlassPolicy: the default policy is disabled.

	act, err := h.CoreService.ActivateBreakGlass(context.Background(), 1, 1, "database is down, paging oncall", "1h")
	require.Error(t, err, "disabled break-glass must still refuse")
	require.Nil(t, act)
	msg := err.Error()
	require.Contains(t, msg, "permission denied", "the HTTP layer maps this prefix to 403")
	require.Contains(t, msg, "not enabled")
	require.Contains(t, msg, "break_glass.enabled")
}
