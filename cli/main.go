// Command keyorix is the thin, REST-only Keyorix CLI (ADR-108). It links no server
// code and no cloud SDK -- internal/depguard's test proves that mechanically. It took over
// the `keyorix` name from the old CLI (formerly internal/cli in the main module, since
// removed) at the end of the split program; it was called keyorix-next before that.
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
