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
}

func runLogin(cmd *cobra.Command, args []string) error {
	serverURL := loginServerURL
	if serverURL == "" {
		serverURL = os.Getenv("KEYORIX_SERVER")
	}
	if serverURL == "" {
		serverURL = offerOldServerURLMigration()
	}
	if serverURL == "" {
		return fmt.Errorf("no server given: pass --server or set KEYORIX_SERVER")
	}

	username := loginUsername
	if username == "" {
		u, err := promptLine("Username: ")
		if err != nil {
			return fmt.Errorf("read username: %w", err)
		}
		username = u
	}

	password := loginPassword
	if password == "" {
		p, err := promptPassword("Password: ")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = p
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
	if loginResp.StatusCode() != http.StatusOK || loginResp.JSON200 == nil || loginResp.JSON200.Data == nil || loginResp.JSON200.Data.Token == nil {
		return fmt.Errorf("login failed: HTTP %d", loginResp.StatusCode())
	}
	token := *loginResp.JSON200.Data.Token

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
