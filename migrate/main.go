// Command keyorix-migrate imports secrets from an existing secret store (HashiCorp Vault
// first; AWS/Azure/GCP secret managers follow, docs/design-keyorix-migrate.md Step 3) into
// Keyorix over its public REST API. See docs/design-keyorix-migrate.md for the full design.
package main

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/migrate/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
