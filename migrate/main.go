// Command keyorix-migrate imports secrets from an existing secret store (HashiCorp Vault
// first; AWS/Azure/GCP secret managers follow, docs/design-keyorix-migrate.md Step 3) into
// Keyorix over its public REST API. See docs/design-keyorix-migrate.md for the full design.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/keyorixhq/keyorix/migrate/cmd"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. A command error is printed here, once;
// the cobra root command is silenced so it does not print the same error first.
func run(args []string, stdout, stderr io.Writer) int {
	if err := cmd.Execute(args, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "Error:", err)
		return 1
	}
	return 0
}
