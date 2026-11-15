// systeminit.go ports the network-bootstrap half of the old CLI's `system init
// --server` (docs/cli-split-inventory.md §2.7 gap, PR 10 leftover): bootstraps a
// running Keyorix server -- creates the admin user, default RBAC roles, and default
// workspace (project + 3 environments) via POST /system/init. Unlike every other
// command in this module, it does not resolve stored credentials first: this IS
// how the first credentials come to exist, and the endpoint itself is
// unauthenticated (gated on the bootstrap token instead of a session/PAT token).
//
// The old CLI's `system init` was dual-mode: local (create config/keys/DB on this
// host) or --server (network bootstrap). Only the network half belongs in this
// network-only CLI -- the local half has no server interaction at all and belongs in
// `keyorix-server admin init` (see system.go's header comment, corrected alongside
// this file to stop implying `system init` doesn't belong here at all).
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/oapi-codegen/runtime/types"
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

// defaultSystemInitAdminEmail is the --admin-email default. It must pass the
// server's email rule (name@domain.tld); ".local" is reserved, so it can never be
// someone else's mailbox.
const defaultSystemInitAdminEmail = "admin@keyorix.local"

var (
	systemInitServer         string
	systemInitAdminUsername  string
	systemInitAdminPassword  string
	systemInitAdminEmail     string
	systemInitBootstrapToken string
)

var systemInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Bootstrap a running Keyorix server (admin user + default workspace)",
	Long: `Bootstrap a running Keyorix server: creates the admin user, default RBAC
roles, and default workspace (project + 3 environments) via POST /system/init.
Safe to run more than once -- idempotent.

This is the network-bootstrap half only. Local host setup (config file, encryption
keys, database) is "keyorix-server admin init", a separate host-filesystem tool this
network-only CLI does not run.

The admin password is read from KEYORIX_ADMIN_PASSWORD, or prompted for (hidden)
when that is unset. The bootstrap token is read from KEYORIX_BOOTSTRAP_TOKEN. Do
not pass either on the command line: arguments are visible via ps/proc and saved
in shell history.

Examples:
  keyorix system init --server http://localhost:8080
  keyorix system init --server https://vault.example.com \
      --admin-username admin --admin-email admin@example.com`,
	SilenceUsage: true,
	RunE:         runSystemInit,
}

func init() {
	systemInitCmd.Flags().StringVar(&systemInitServer, "server", "", "Server base URL to bootstrap (required)")
	systemInitCmd.Flags().StringVar(&systemInitAdminUsername, "admin-username", "admin", "Admin username to create")
	// No default: a defaulted "admin" password would silently bootstrap a live server
	// with a well-known credential pair, and this command's only feedback is the
	// trailing success banner, printed AFTER the account already exists -- see G76.
	systemInitCmd.Flags().StringVar(&systemInitAdminPassword, "admin-password", "",
		"Admin password (required; INSECURE on the command line -- prefer KEYORIX_ADMIN_PASSWORD, or omit to be prompted)")
	// A default that passes the server's email rule: the old "admin@localhost" has no
	// dot-domain and was refused, so a bare `system init` always failed (#4216). Kept as
	// a default (not a required flag) so every quick-start that omits the flag works.
	systemInitCmd.Flags().StringVar(&systemInitAdminEmail, "admin-email", defaultSystemInitAdminEmail,
		"Admin email address (default "+defaultSystemInitAdminEmail+" is a placeholder with no mailbox; "+
			"pass your own to receive password-reset mail)")
	systemInitCmd.Flags().StringVar(&systemInitBootstrapToken, "bootstrap-token", "",
		"Bootstrap token authorizing first-admin creation (or KEYORIX_BOOTSTRAP_TOKEN; printed in the server log on first boot; INSECURE on the command line)")
	_ = systemInitCmd.MarkFlagRequired("server") // #nosec G104

	systemCmd.AddCommand(systemInitCmd)
}

func runSystemInit(cmd *cobra.Command, _ []string) error {
	server := strings.TrimRight(systemInitServer, "/")
	warnIfInsecureEndpoint(server)

	password, err := resolveSystemInitAdminPassword(cmd)
	if err != nil {
		return err
	}
	token, err := resolveSystemInitBootstrapToken(cmd)
	if err != nil {
		return err
	}

	client, err := newAPIClient(server, "")
	if err != nil {
		return fmt.Errorf("build client for %s: %w", server, err)
	}

	body := apiclient.SystemInitJSONRequestBody{
		Username:    systemInitAdminUsername,
		Email:       types.Email(systemInitAdminEmail),
		Password:    password,
		DisplayName: strPtr("Administrator"),
	}
	if token != "" {
		body.BootstrapToken = strPtr(token)
	}

	ctx := context.Background()
	resp, err := client.SystemInitWithResponse(ctx, body)
	if err != nil {
		return fmt.Errorf("contact %s: %w", server, err)
	}
	if resp.StatusCode() != 200 {
		return systemInitError(resp.StatusCode(), resp.Body)
	}
	if resp.JSON200 == nil || resp.JSON200.Data == nil {
		return fmt.Errorf("unexpected response from %s: HTTP %d", server, resp.StatusCode())
	}
	d := resp.JSON200.Data

	if d.AlreadyInitialized != nil && *d.AlreadyInitialized {
		fmt.Fprintf(os.Stderr, "Server at %s is already initialised.\n", server)
		fmt.Fprintf(os.Stderr, "Use \"keyorix login\" to authenticate.\n")
		return nil
	}

	envList := "development, staging, production"
	if d.Environments != nil && len(*d.Environments) > 0 {
		envList = strings.Join(*d.Environments, ", ")
	}
	project := ""
	if d.Project != nil {
		project = *d.Project
	}
	username := systemInitAdminUsername
	if d.User != nil && d.User.Username != nil && *d.User.Username != "" {
		username = *d.User.Username
	}

	fmt.Printf("Keyorix initialised successfully\n\n")
	fmt.Printf("Your workspace is ready:\n")
	fmt.Printf("  +-- Project: %s\n", project)
	fmt.Printf("  +-- Environments: %s\n", envList)
	fmt.Printf("  +-- Admin user: %s (change password after first login)\n", username)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  keyorix login --server %s --username %s\n", server, username)
	fmt.Printf("  keyorix mfa enroll      (required by default: secrets stay locked until the admin has a second factor)\n")
	fmt.Printf("  keyorix mfa activate\n")
	fmt.Printf("  keyorix secret create --name my-first-secret --interactive\n")
	return nil
}

// resolveSystemInitAdminPassword resolves the admin password in order of
// preference: the (insecure, warned) --admin-password flag, then
// KEYORIX_ADMIN_PASSWORD, then an interactive no-echo prompt (login.go's
// promptPassword). Mirrors resolveAdminPassword from the old CLI's
// internal/cli/system/init.go.
func resolveSystemInitAdminPassword(cmd *cobra.Command) (string, error) {
	if systemInitAdminPassword != "" {
		warnInsecureFlag(cmd, "admin-password", "prefer the KEYORIX_ADMIN_PASSWORD environment variable, or omit it to be prompted.")
		return systemInitAdminPassword, nil
	}
	// KEYORIX_ADMIN_PASSWORD_FILE is accepted too; both set, an unreadable file or
	// a file with loose permissions is an error, never a silent prompt/fallback.
	p, found, err := lookupSecretEnv("KEYORIX_ADMIN_PASSWORD")
	if err != nil {
		return "", err
	}
	if found {
		return p, nil
	}
	p, err = promptPassword("Enter admin password for the new account: ")
	if err != nil {
		return "", fmt.Errorf("read admin password: %w", err)
	}
	if p == "" {
		return "", fmt.Errorf("admin password is required to bootstrap a server (--admin-password, KEYORIX_ADMIN_PASSWORD, or enter one at the prompt)")
	}
	return p, nil
}

// bootstrapTokenHint is the next step for a refused bootstrap token. The generic 403
// hint ("ask a project admin ...") does not fit: nobody is signed in yet.
const bootstrapTokenHint = " Next step: check that KEYORIX_BOOTSTRAP_TOKEN / KEYORIX_BOOTSTRAP_TOKEN_FILE " +
	"matches the token the server was started with."

// systemInitError turns a non-200 answer of POST /system/init into the command's error.
// The server answers a refused bootstrap token with a plain 403 whose error code is the
// generic "Error" (shared with its other validation refusals), so the refusal is told
// apart by its message; any other answer keeps the standard status handling.
func systemInitError(status int, body []byte) error {
	if field, ok := systemInitValidationField(status, body); ok {
		var eb apiErrorBody
		_ = json.Unmarshal(body, &eb)
		return withExitCode(statusExitCode(http.StatusBadRequest), fmt.Errorf("bootstrap server failed: %s (HTTP %d)%s",
			cliout.SanitizeForTerminal(eb.Message), status, systemInitValidationHint(field)))
	}
	var eb apiErrorBody
	if status == http.StatusForbidden && json.Unmarshal(body, &eb) == nil &&
		strings.Contains(eb.Message, "invalid bootstrap token") &&
		!strings.Contains(eb.Message, "disabled") {
		return withExitCode(statusExitCode(status), fmt.Errorf("bootstrap server failed: %s (HTTP %d)%s",
			cliout.SanitizeForTerminal(eb.Message), status, bootstrapTokenHint))
	}
	return apiError("bootstrap server", status, body)
}

// errCodeValidation is the "error" code of the server's 400 for admin details it
// rejects (server/http/handlers/auth.go InitSystem); details.field names the input.
const errCodeValidation = "ValidationError"

// systemInitValidationField reports whether the answer is a refusal of the admin
// details sent (not of the bootstrap token) and which input it names ("" when the
// server did not say). A server that predates the typed code answers the same
// refusal 403 with the generic "Error" code and core's wrapped text ("failed to create
// admin user: Validation error: ..."), so the text is matched anywhere, not as a
// prefix; it is recognised too so the operator is not sent to "request access".
// Neither token refusal ("invalid bootstrap token", "system initialisation over the
// API is disabled: ...") contains "Validation error", so neither is re-labelled.
func systemInitValidationField(status int, body []byte) (field string, ok bool) {
	var eb struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Details struct {
			Field string `json:"field"`
		} `json:"details"`
	}
	if json.Unmarshal(body, &eb) != nil {
		return "", false
	}
	switch {
	case status == http.StatusBadRequest && eb.Error == errCodeValidation:
		return eb.Details.Field, true
	case status == http.StatusForbidden && eb.Error == "Error" && strings.Contains(eb.Message, "Validation error"):
		lower := strings.ToLower(eb.Message)
		for _, f := range []string{"email", "username"} {
			if strings.Contains(lower, f) {
				return f, true
			}
		}
		return "", true
	}
	return "", false
}

// systemInitValidationHint names the flag that fixes the rejected input.
func systemInitValidationHint(field string) string {
	switch field {
	case "email":
		return " Next step: pass a valid address with --admin-email (name@domain.tld)."
	case "username":
		return " Next step: pass a different name with --admin-username."
	case "display_name":
		return " Next step: the display name is fixed by this command; report this to the server operator."
	case "password":
		return " Next step: set KEYORIX_ADMIN_PASSWORD (or enter one at the prompt) and run again."
	}
	return " Next step: check --admin-username, --admin-email and the admin password, then run again."
}

// resolveSystemInitBootstrapToken resolves the bootstrap token: the (insecure,
// warned) --bootstrap-token flag, else KEYORIX_BOOTSTRAP_TOKEN. Never logged,
// echoed, or included in any error message -- it is as sensitive as the admin
// password this same request carries.
func resolveSystemInitBootstrapToken(cmd *cobra.Command) (string, error) {
	if systemInitBootstrapToken != "" {
		warnInsecureFlag(cmd, "bootstrap-token", "prefer the KEYORIX_BOOTSTRAP_TOKEN environment variable.")
		return systemInitBootstrapToken, nil
	}
	// KEYORIX_BOOTSTRAP_TOKEN_FILE is accepted too (both set, unreadable or too
	// open is an error).
	v, _, err := lookupSecretEnv("KEYORIX_BOOTSTRAP_TOKEN")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// warnIfInsecureEndpoint warns before this command's admin credentials and
// bootstrap token are sent to a non-HTTPS, non-loopback endpoint, where they
// would leave the machine in cleartext, MITM-capturable. Mirrors the old CLI's
// internal/cli/common.WarnIfInsecureEndpoint/endpointIsSecure.
func warnIfInsecureEndpoint(endpoint string) {
	if endpoint == "" || endpointIsSecure(endpoint) {
		return
	}
	fmt.Fprintf(os.Stderr, "WARNING: server %q is not HTTPS -- the admin password and bootstrap token are sent in cleartext and MITM-capturable.\n", endpoint)
}

func endpointIsSecure(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func strPtr(s string) *string { return &s }
