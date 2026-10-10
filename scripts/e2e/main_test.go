//go:build e2e

package e2e

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestMain removes the binaries harness.BuildBinaries compiled (#3039).
func TestMain(m *testing.M) { os.Exit(harness.RunMain(m)) }
