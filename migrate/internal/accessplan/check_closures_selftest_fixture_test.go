package accessplan

import "testing"

// This file exists ONLY to give scripts/check-closures.sh --self-test a real,
// stable test in the migrate module (its own go.mod) to point a calibration row at,
// so it can prove a ./migrate/... row is run inside migrate/ and accepted when the
// test passes. It is not, and should never become, a real closure's proving test: it
// asserts nothing about product behaviour. Never delete or rename it without
// updating the matching case in check-closures.sh's --self-test block.

// TestCheckClosuresSelfTestFixture_MigrateModulePasses always passes.
func TestCheckClosuresSelfTestFixture_MigrateModulePasses(t *testing.T) {
	t.Parallel()
}
