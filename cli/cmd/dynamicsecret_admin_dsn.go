package cmd

// `keyorix dynamic-secret set-admin-dsn` and `refused-dsn` (DYNAMIC-ADMIN-DSN-1, #4193): replace a
// stored admin DSN in place, and list the configs whose stored DSN names a driver option the
// server has refused since #3952 (a private-CA sslrootcert or tlsCAFile) so they can be fixed.
//
// The DSN is a credential. It is read from KEYORIX_DYNAMIC_ADMIN_DSN, from a hidden prompt on a
// terminal, or from piped stdin, and never from argv (the hidden --admin-dsn flag exists only so
// it can be refused with a message that says what to do instead). Nothing here prints it, and
// an error that came back from the server or the transport is scrubbed of it before it is shown.

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

const dynAdminDSNFlag = "admin-dsn"

var (
	dynRefusedProjectID int
	dynRefusedFormat    string
)

var dynSetAdminDSNCmd = &cobra.Command{
	Use:   "set-admin-dsn <config-id>",
	Short: "Replace a dynamic-secret config's admin DSN (from the environment or stdin)",
	Long: `Replace the admin DSN stored for a dynamic-secret config, in place. Use it to remove an
option the server has refused since #3952 (a private-CA sslrootcert or tlsCAFile) from a
config that can no longer issue, without deleting and recreating the config.

The new DSN is read from the ` + dynAdminDSNEnv + ` environment variable, or from
stdin (a hidden prompt on a terminal, or whatever is piped in). It is never accepted as a
flag, so it cannot land in shell history or a process listing; the server encrypts it at
rest and never returns it.

While the config has an active or revoke_failed lease, the new DSN must name the same
host(s) as the old one (the server answers 409 otherwise): those leases are revoked through it.

List the configs that need this with: keyorix dynamic-secret refused-dsn --project-id <id>`,
	Args: cobra.ExactArgs(1),
	RunE: runDynSetAdminDSN,
}

var dynRefusedDSNCmd = &cobra.Command{
	Use:   "refused-dsn",
	Short: "List a project's configs whose admin DSN names a refused option",
	Long: `List the configs in a project whose stored admin DSN names a driver option the server
has refused since #3952 (a server file such as sslrootcert or tlsCAFile, or ambient
credentials). They can no longer issue. Fix each with:
  keyorix dynamic-secret set-admin-dsn <config-id>

Needs secrets.read on the project and dynamic-secret admin authority there, because the
report is derived from the decrypted DSNs. It prints config and option names only, never a
DSN or an option value.`,
	Args: cobra.NoArgs,
	RunE: runDynRefusedDSN,
}

func init() {
	// Hidden and always refused (see refusedSecretFlags): it exists so the refusal can name the
	// safe way in instead of cobra's bare "unknown flag".
	dynSetAdminDSNCmd.Flags().String(dynAdminDSNFlag, "", "")
	_ = dynSetAdminDSNCmd.Flags().MarkHidden(dynAdminDSNFlag)

	dynRefusedDSNCmd.Flags().IntVar(&dynRefusedProjectID, "project-id", 0, "Project ID (required)")
	_ = dynRefusedDSNCmd.MarkFlagRequired("project-id")
	addOutputFlag(dynRefusedDSNCmd, &dynRefusedFormat)

	dynamicSecretCmd.AddCommand(dynSetAdminDSNCmd, dynRefusedDSNCmd)
}

// dynAdminDSNStdin is where set-admin-dsn reads a piped DSN (a variable so tests can feed it).
var dynAdminDSNStdin io.Reader = sharedStdin{}

// readDynamicAdminDSNForUpdate resolves the new DSN from the environment, a hidden prompt on a
// terminal, or piped stdin, in that order. Both stdin forms say what they are waiting for.
func readDynamicAdminDSNForUpdate() (string, error) {
	if v := strings.TrimSpace(os.Getenv(dynAdminDSNEnv)); v != "" {
		return v, nil
	}
	if _, shared := dynAdminDSNStdin.(sharedStdin); shared && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "New admin DSN (input hidden): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("failed to read the admin DSN (set %s or pipe it on stdin for non-interactive use): %w", dynAdminDSNEnv, err)
		}
		dsn := strings.TrimSpace(string(b))
		if dsn == "" {
			return "", usageErrorf("the admin DSN is empty: nothing was changed")
		}
		return dsn, nil
	}
	data, err := io.ReadAll(io.LimitReader(dynAdminDSNStdin, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("cannot read the admin DSN from stdin: %w", err)
	}
	if len(data) > maxSecretFileSize {
		return "", usageErrorf("the admin DSN on stdin is too large (limit %d bytes): nothing was changed", maxSecretFileSize)
	}
	dsn := strings.TrimSpace(string(data))
	if dsn == "" {
		return "", usageErrorf("no admin DSN: set %s, or pipe the DSN on stdin, e.g. printf %%s \"$DSN\" | keyorix dynamic-secret set-admin-dsn <config-id>. Nothing was changed", dynAdminDSNEnv)
	}
	return dsn, nil
}

func runDynSetAdminDSN(cmd *cobra.Command, args []string) error {
	// Defence in depth for the secret-flag policy: KEYORIX_ALLOW_INSECURE_SECRET_FLAGS turns that
	// wrapper into a warning for commands that used to accept the flag, and this one never did.
	if cmd.Flags().Changed(dynAdminDSNFlag) {
		return usageErrorf("--%s is never accepted by this command: a DSN on the command line is visible through ps and stays in shell "+
			"history. Set %s or pipe the DSN on stdin instead", dynAdminDSNFlag, dynAdminDSNEnv)
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id <= 0 {
		return usageErrorf("invalid config id: %s", args[0])
	}
	dsn, err := readDynamicAdminDSNForUpdate()
	if err != nil {
		return err
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return redactDSN(err, dsn)
	}
	body := apiclient.UpdateDynamicSecretConfigAdminDSNJSONRequestBody{AdminDsn: &dsn}
	resp, err := client.UpdateDynamicSecretConfigAdminDSNWithResponse(context.Background(), id, body)
	if err != nil {
		return redactDSN(err, dsn)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return redactDSN(httpStatusError("replace admin DSN failed", resp.StatusCode(), resp.Body), dsn)
	}
	cfg := resp.JSON200.Data
	fmt.Printf("Replaced the admin DSN of dynamic-secret config #%d (%s, %s).\n", id, derefStr(cfg.Name), derefStr((*string)(cfg.BackendType)))
	fmt.Printf("Check it with: keyorix dynamic-secret issue %d\n", id)
	return nil
}

func runDynRefusedDSN(_ *cobra.Command, _ []string) error {
	if err := checkOutputFormat(dynRefusedFormat); err != nil {
		return err
	}
	if dynRefusedProjectID <= 0 {
		return usageErrorf("--project-id is required")
	}
	client, err := dynamicSecretAPIClient()
	if err != nil {
		return err
	}
	resp, err := client.ListDynamicSecretConfigsWithRefusedAdminDSNWithResponse(context.Background(),
		&apiclient.ListDynamicSecretConfigsWithRefusedAdminDSNParams{ProjectId: dynRefusedProjectID})
	if err != nil {
		return err
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return httpStatusError("list refused admin DSNs failed", resp.StatusCode(), resp.Body)
	}
	data := resp.JSON200.Data
	// Skipped configs are never silent, and stdout stays clean for -o json|yaml.
	if n := derefInt(data.Unreadable); n > 0 {
		fmt.Fprintf(os.Stderr, "%d config(s) in project %d have an admin DSN that could not be decrypted and were not checked.\n", n, dynRefusedProjectID)
	}
	var configs []struct {
		BackendType    *string   `json:"backend_type,omitempty"`
		EnvironmentId  *int      `json:"environment_id,omitempty"`
		Id             *int      `json:"id,omitempty"`
		LiveLeases     *int      `json:"live_leases,omitempty"`
		Name           *string   `json:"name,omitempty"`
		ProjectId      *int      `json:"project_id,omitempty"`
		RefusedOptions *[]string `json:"refused_options,omitempty"`
	}
	if data.Configs != nil {
		configs = *data.Configs
	}
	return emitList(dynRefusedFormat, configs, func() error {
		if len(configs) == 0 {
			fmt.Printf("No config in project %d has a refused admin DSN option.\n", dynRefusedProjectID)
			return nil
		}
		fmt.Printf("%-5s %-24s %-10s %-7s %s\n", "ID", "NAME", "BACKEND", "LEASES", "REFUSED OPTIONS")
		for _, c := range configs {
			var opts []string
			if c.RefusedOptions != nil {
				opts = *c.RefusedOptions
			}
			fmt.Printf("%-5d %-24s %-10s %-7d %s\n", derefInt(c.Id), derefStr(c.Name), derefStr(c.BackendType),
				derefInt(c.LiveLeases), strings.Join(opts, ", "))
		}
		fmt.Printf("\nFix each with: keyorix dynamic-secret set-admin-dsn <config-id>\n")
		return nil
	})
}

// redactDSN returns err with the DSN, and the password inside it, replaced by [redacted] in its
// text. The server does not echo the DSN; this keeps that true if a proxy, a future handler or a
// transport error ever does. A nil err stays nil. The original error stays reachable through
// Unwrap, so the exit code and the transport-error classification do not change.
func redactDSN(err error, dsn string) error {
	if err == nil || dsn == "" {
		return err
	}
	msg := err.Error()
	red := msg
	for _, secret := range dsnSecrets(dsn) {
		red = strings.ReplaceAll(red, secret, "[redacted]")
	}
	if red == msg {
		return err
	}
	return &redactedError{err: err, msg: red}
}

// redactedError is err with a scrubbed message.
type redactedError struct {
	err error
	msg string
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// dsnSecrets lists the strings to scrub, longest first: the whole DSN, then the password of a
// URL-shaped one in both its raw and escaped forms.
func dsnSecrets(dsn string) []string {
	out := []string{dsn}
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			out = append(out, pw, url.QueryEscape(pw), url.PathEscape(pw))
		}
	}
	return out
}
