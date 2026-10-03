package cmd

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"github.com/keyorixhq/keyorix/cli/internal/migrate"
)

var (
	loginServerURL string
	loginUsername  string
	loginPassword  string
	loginMFACode   string
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to a Keyorix server and store the resulting token",
	Long: `login exchanges a username and password for a session token via POST /auth/login,
verifies it against GET /api/v1/auth/profile, and stores it (with the server URL) at the
one credential-file location this CLI uses (see "keyorix-next status --help").`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginServerURL, "server", "", "Server base URL (or set KEYORIX_SERVER)")
	loginCmd.Flags().StringVar(&loginUsername, "username", "", "Username")
	loginCmd.Flags().StringVar(&loginPassword, "password", "", "Password (omit to be prompted)")
	loginCmd.Flags().StringVar(&loginMFACode, "mfa-code", "", "TOTP or recovery code, for an MFA-enabled account (INSECURE on the command line -- omit to be prompted)")
}

func runLogin(cmd *cobra.Command, args []string) error {
	serverURL, err := resolveLoginServerURL()
	if err != nil {
		return err
	}

	username := loginUsername
	if username == "" {
		u, err := promptLine("Username: ")
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
		username = u
	}

	password, err := resolveLoginPassword(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client, err := newAPIClient(serverURL, "")
	if err != nil {
		return fmt.Errorf("build client for %s: %w", serverURL, err)
	}

	loginResp, err := client.AuthLoginWithResponse(ctx, apiclient.AuthLoginJSONRequestBody{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if loginResp.StatusCode() != http.StatusOK || loginResp.JSON200 == nil || loginResp.JSON200.Data == nil {
		return fmt.Errorf("login failed: HTTP %d", loginResp.StatusCode())
	}

	data := loginResp.JSON200.Data
	var token string
	if data.MfaRequired != nil && *data.MfaRequired {
		if data.MfaChallenge == nil {
			return fmt.Errorf("login failed: server reported mfa_required with no challenge")
		}
		token, err = completeMFALogin(ctx, client, serverURL, *data.MfaChallenge)
		if err != nil {
			return err
		}
	} else {
		if data.Token == nil {
			return fmt.Errorf("login failed: server did not return a session token")
		}
		token = *data.Token
	}

	// Verify the token before persisting anything -- a bad/mistyped server URL that
	// happens to accept the login POST but isn't really Keyorix should be caught here,
	// not discovered on the next command.
	verifyClient, err := newAPIClient(serverURL, token)
	if err != nil {
		return fmt.Errorf("build verification client: %w", err)
	}
	profileResp, err := verifyClient.GetAuthProfileWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("verify token against %s: %w", serverURL, err)
	}
	if profileResp.StatusCode() != http.StatusOK {
		return fmt.Errorf("login succeeded but token verification failed: HTTP %d", profileResp.StatusCode())
	}

	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}
	if err := store.Save(credstore.Credentials{ServerURL: serverURL, Token: token}); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}

	if skewResult, err := checkVersionSkew(ctx, verifyClient); err == nil && skewResult.Warning != "" {
		fmt.Fprintln(os.Stderr, "Warning:", skewResult.Warning)
	}

	fmt.Printf("Logged in to %s as %s.\n", serverURL, username)
	return nil
}

// resolveLoginServerURL resolves the target server URL (flag > KEYORIX_SERVER > old-CLI
// migration prompt) and warns to stderr if it is not HTTPS/loopback before this command's
// username and password are sent to it. CLI-LOGIN-001: prior to this fix, login was the
// one credential-transmitting command in this module that never called
// warnIfInsecureEndpoint -- systeminit.go's `system init --server` does (see its own
// warnIfInsecureEndpoint doc comment), and the old CLI called the equivalent
// common.WarnIfInsecureEndpoint from every credential-persisting/transmitting call site,
// explicitly including "auth login" (#G74) -- this closes the gap this rewrite silently
// reopened for the single most commonly used auth command.
func resolveLoginServerURL() (string, error) {
	serverURL := loginServerURL
	if serverURL == "" {
		serverURL = os.Getenv("KEYORIX_SERVER")
	}
	if serverURL == "" {
		serverURL = offerOldServerURLMigration()
	}
	if serverURL == "" {
		return "", fmt.Errorf("no server given: pass --server or set KEYORIX_SERVER")
	}
	warnIfInsecureEndpoint(serverURL)
	return serverURL, nil
}

// resolveLoginPassword resolves the password: the (insecure, warned) --password flag, or
// else an interactive no-echo prompt. CLI-LOGIN-001: --password previously carried no
// warnInsecureFlag call, unlike every sibling command with a password-bearing flag
// (systeminit.go's --admin-password, user.go's --password).
func resolveLoginPassword(cmd *cobra.Command) (string, error) {
	if loginPassword != "" {
		warnInsecureFlag(cmd, "password", "omit it to be prompted instead.")
		return loginPassword, nil
	}
	p, err := promptPassword("Password: ")
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return p, nil
}

// completeMFALogin finishes a two-step login for an MFA-enabled account: resolves a
// code (the --mfa-code flag, warned as insecure same as --password, or an interactive
// prompt naming the challenge as TOTP-or-recovery) and calls POST /auth/mfa/verify.
// ADR-112 item 1 flipped security.require_mfa on by default, so this is now the
// common path for a fresh install's bootstrap admin, not an edge case.
func completeMFALogin(ctx context.Context, client *apiclient.ClientWithResponses, serverURL, challenge string) (string, error) {
	code := loginMFACode
	if code != "" {
		fmt.Fprintln(os.Stderr, "Warning: --mfa-code is visible in your shell history and to other processes on this machine (ps/proc) -- prefer the interactive prompt.")
	} else {
		c, err := promptLine("MFA required. Enter TOTP or recovery code: ")
		if err != nil {
			return "", fmt.Errorf("read MFA code: %w", err)
		}
		code = c
	}
	if code == "" {
		return "", fmt.Errorf("MFA code is required")
	}

	verifyResp, err := client.MfaVerifyWithResponse(ctx, apiclient.MfaVerifyJSONRequestBody{
		MfaChallenge: challenge,
		Code:         code,
	})
	if err != nil {
		return "", fmt.Errorf("contact %s: %w", serverURL, err)
	}
	if verifyResp.StatusCode() != http.StatusOK || verifyResp.JSON200 == nil || verifyResp.JSON200.Data == nil || verifyResp.JSON200.Data.Token == nil {
		return "", fmt.Errorf("MFA verification failed: HTTP %d", verifyResp.StatusCode())
	}
	return *verifyResp.JSON200.Data.Token, nil
}

// offerOldServerURLMigration looks for a server URL left behind by the old,
// pre-ADR-108 CLI and, if one is found, asks the operator whether to reuse it --
// it never imports a credential, only a URL (see internal/migrate's doc comment).
// Returns "" if none is found or the operator declines, in which case runLogin
// falls through to its existing "no server given" error exactly as before.
func offerOldServerURLMigration() string {
	c, ok := migrate.DetectOldServerURL()
	if !ok {
		return ""
	}
	answer, err := promptLine(fmt.Sprintf("Found a server URL from an older keyorix CLI config (%s): %s\nUse it? [Y/n]: ", c.Source, c.ServerURL))
	if err != nil {
		return ""
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" || answer == "y" || answer == "yes" {
		return c.ServerURL
	}
	return ""
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return promptLine("")
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
