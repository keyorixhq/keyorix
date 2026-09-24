// secret.go — keyorix secret: root command and shared helpers for PR 5's command
// group (docs/cli-split-inventory.md §7): bulk/rotation/export/import/scan/hygiene.
// REST-only, no local/embedded mode (ADR-108 Decision A).
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/securefiles"
)

var SecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets: bulk operations, rotation, export/import, and hygiene reports",
}

func init() {
	rootCmd.AddCommand(SecretCmd)
}

// secretAPIClient resolves the stored credentials and builds a client, the shared
// pre-flight every secret subcommand needs.
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

// parseSecretArg parses a positional secret-ID argument, rejecting anything non-numeric
// rather than silently truncating or wrapping.
func parseSecretArg(s string) (int, error) {
	id, err := strconv.Atoi(s)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid secret ID %q: must be a positive integer", s)
	}
	return id, nil
}

// warnInsecureFlag warns on stderr that flagName's value is visible in shell history
// and process listings, naming the FLAG only — it must never print the flag's value.
func warnInsecureFlag(cmd *cobra.Command, flagName, advice string) {
	if cmd.Flags().Changed(flagName) {
		_, _ = fmt.Fprintf(cmdErrWriter(cmd), "WARNING: --%s is insecure (visible in shell history and process listings); %s\n", flagName, advice)
	}
}

// cmdErrWriter returns the command's configured stderr writer, or the process's own
// os.Stderr if none was set (tests override this via cmd.SetErr).
func cmdErrWriter(cmd *cobra.Command) interface{ Write([]byte) (int, error) } {
	return cmd.ErrOrStderr()
}

// secureCreateOutputFile opens path for a fresh output file (render --output, export
// --output, scan --report). Delegates to securefiles.SecureCreateFileHandle, which
// combines O_EXCL (refuses to write through OR overwrite a pre-existing path,
// including a symlink an attacker with write access to a shared directory planted at
// the target ahead of time) with a per-path-component O_NOFOLLOW walk. path may be an
// arbitrary operator-supplied absolute or relative path, so it's split into
// (baseDir, relPath) the way securefiles expects.
func secureCreateOutputFile(path string) (*os.File, error) {
	return securefiles.SecureCreateFileHandle(filepath.Dir(path), filepath.Base(path), 0o600)
}

// decodeJSONBody unmarshals a raw generated-client response body into v. Used for the
// operations this module's own openapi.yaml filter kept without a response schema
// (listSecrets, createSecret, getSecret — PR 4's job, a sibling independent PR), whose
// generated methods return only a raw []byte body rather than a typed JSON200 field.
func decodeJSONBody(body []byte, v interface{}) error {
	return json.Unmarshal(body, v)
}
