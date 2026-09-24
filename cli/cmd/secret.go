// secret.go ports `keyorix secret` (docs/cli-split-inventory.md §2.1, PR 4):
// core CRUD + metadata for secrets, REST only. Same flags, output, and exit
// codes as the old CLI's internal/cli/secret package's remote-mode branch
// (ADR-108 Decision A removes local mode entirely). Most of this package's
// commands were already remote-only in the old CLI (no embedded fallback to
// strip) -- this is a straightforward retarget onto the generated apiclient.
//
// This is the highest-scrutiny command group in the whole split: secret
// VALUES must never appear in a log line, an argv-visible flag echo, or an
// error message. See secret_test.go's
// TestNoSecretCommandLeaksTheCanaryValue for the standing regression guard.
package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// SecretCmd is the root command for secret operations, exported (matching
// the old CLI's internal/cli/secret.SecretCmd) so sibling files in this
// package can attach their subcommands to it directly.
var SecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  "Create, read, update, delete, and manage secrets and their metadata.",
}

func init() {
	rootCmd.AddCommand(SecretCmd)
}

// secretAPIClient resolves the stored credentials and builds a client, the
// shared pre-flight every secret subcommand needs.
func secretAPIClient() (*apiclient.ClientWithResponses, error) {
	store, err := resolveCredStore()
	if err != nil {
		return nil, fmt.Errorf("resolve credential store: %w", err)
	}
	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		return nil, err
	}
	return newAPIClient(serverURL, token)
}

// warnInsecureFlag mirrors the old CLI's internal/cli/common.WarnInsecureFlag:
// warns to stderr when a secret-bearing flag was passed on the command line
// (visible to other local users via ps/proc, and saved in shell history).
func warnInsecureFlag(cmd *cobra.Command, flagName, advice string) {
	if cmd.Flags().Changed(flagName) {
		fmt.Fprintf(os.Stderr, "Warning: passing --%s on the command line is insecure (visible to other local users via ps/proc, and saved in shell history); %s\n", flagName, advice)
	}
}

// parseSecretArg parses a positional secret/edge/version ID argument,
// matching the old CLI's internal/cli/secret.parseSecretArg exactly (0 is
// never a valid ID).
func parseSecretArg(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	return n, nil
}

func derefSecretInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func derefSecretBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}
