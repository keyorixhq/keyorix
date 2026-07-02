package common

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// APIKeyEnvVar is the NAME of the environment variable an API key should be read
// from instead of a command-line flag, so the key itself never appears in
// `ps`/`/proc` output or shell history. This is an identifier, not a credential
// value.
const APIKeyEnvVar = "KEYORIX_API_KEY" // #nosec G101 -- env var name, not a secret value

// ResolveAPIKey resolves an API key in order of preference:
//  1. the (insecure, warned) --api-key flag, if set;
//  2. the KEYORIX_API_KEY environment variable;
//  3. when prompt is true and neither of the above is set, an interactive no-echo
//     prompt.
//
// A literal --api-key value is visible via `ps`/`/proc` and gets saved in shell
// history, so its use is flagged with a warning on stderr — the same pattern
// `keyorix connect`'s resolveAPIKey already applies. Set prompt to false for a
// command where the API key is optional (e.g. `config set-remote`, which is fine
// proceeding with an empty key); set it to true where a key is required (e.g.
// `auth login`).
func ResolveAPIKey(cmd *cobra.Command, prompt bool) (string, error) {
	if k, _ := cmd.Flags().GetString("api-key"); k != "" {
		fmt.Fprintln(os.Stderr, "⚠️  Passing --api-key on the command line is insecure (visible via ps/proc and saved in shell history); prefer the KEYORIX_API_KEY environment variable.")
		return k, nil
	}
	if k := os.Getenv(APIKeyEnvVar); k != "" {
		return k, nil
	}
	if !prompt {
		return "", nil
	}
	fmt.Fprint(os.Stderr, "Enter API key: ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read API key: %w", err)
	}
	return string(b), nil
}
