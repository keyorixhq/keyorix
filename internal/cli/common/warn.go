package common

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// WarnInsecureFlag prints a loud stderr warning when the named flag was explicitly
// set on the command line. Command-line arguments are visible to any other local user
// via `ps`/`/proc/<pid>/cmdline` and are typically saved in shell history, so a secret
// value, password, API key, or token should never be passed this way if there is a
// safer alternative (an interactive prompt, --from-file, or an environment variable).
// It is a no-op when the flag was left at its default (nothing insecure happened).
func WarnInsecureFlag(cmd *cobra.Command, flagName, advice string) {
	if cmd.Flags().Changed(flagName) {
		fmt.Fprintf(os.Stderr, "⚠️  Passing --%s on the command line is insecure (visible to other local users via ps/proc, and saved in shell history); %s\n", flagName, advice)
	}
}
