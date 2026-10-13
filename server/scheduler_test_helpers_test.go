package main

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// startSchedulersForTest is how a test starts the background schedulers: it calls
// startSchedulers under a context of its own and registers a cleanup that cancels
// it and waits until every scheduler goroutine has exited.
//
// A test that called startSchedulers directly and returned (even after
// cancelling) left any in-flight tick running into the NEXT test: a leaked
// break_glass_review_reminder tick logged into
// TestWarnIfRecoveryKeyMissing_KeyConfiguredSilent's captured log buffer
// (merge_group run 38057485762, "race detected during execution of test"), and
// leaked 1ms-interval ticks hit "i18n not initialized" after a later test reset
// i18n. TestNoTestCallsStartSchedulersDirectly keeps every caller on this helper.
func startSchedulersForTest(t *testing.T, ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore) { //nolint:revive // t first, like every other test helper here
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	wait := startSchedulers(ctx, cfg, coreService)
	t.Cleanup(func() {
		cancel()
		wait()
	})
}
