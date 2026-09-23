// Command keyorix-next is the thin, REST-only Keyorix CLI (ADR-108). It links no server
// code and no cloud SDK -- internal/depguard's test proves that mechanically. It keeps the
// name keyorix-next until Phase 5 of the split program, when it takes over the `keyorix`
// name from the old, still-shipping CLI (internal/cli in the main module).
package main

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
