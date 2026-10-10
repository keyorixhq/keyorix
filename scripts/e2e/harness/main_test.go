//go:build e2e

package harness

import (
	"os"
	"testing"
)

// TestMain removes the binaries BuildBinaries compiled (#3039).
func TestMain(m *testing.M) { os.Exit(RunMain(m)) }
