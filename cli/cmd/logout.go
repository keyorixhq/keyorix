package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke the stored session and forget it locally (keeps server URL and ca_file)",
	Long: `Sign out: the server revokes the stored session token first, then the token is
removed from the local credentials file, even when the server cannot be reached or already
rejects the token, so no stale credential stays on disk.

Your settings stay: the server URL and the ca_file setting (keyorix config set ca_file) are
kept, so the next "keyorix login" works against a server with a private or self-signed
certificate without repeating them. To forget them too, run "keyorix config unset ca_file"
or delete the credentials file.`,
	RunE: runLogout,
}

func runLogout(cmd *cobra.Command, args []string) error {
	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}

	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		// Nothing stored, nothing to revoke or forget -- but not an error: logging out
		// of a session that doesn't exist locally is a no-op, not a failure.
		fmt.Println("Not logged in.")
		return nil
	}

	var revokeErr error
	if token != "" {
		client, cerr := newAPIClient(serverURL, token)
		if cerr != nil {
			revokeErr = fmt.Errorf("build client: %w", cerr)
		} else if _, cerr := client.AuthLogoutWithResponse(context.Background()); cerr != nil {
			revokeErr = fmt.Errorf("contact %s: %w", serverURL, cerr)
		}
	}

	if err := store.ForgetSession(); err != nil {
		return fmt.Errorf("forget local session: %w", err)
	}

	if revokeErr != nil {
		fmt.Fprintln(os.Stderr, "Warning: could not revoke the session server-side:", revokeErr)
		fmt.Fprintln(os.Stderr, "The local session was forgotten anyway; the server-side token may still be valid until it expires or is revoked separately.")
		return nil
	}

	fmt.Println("Logged out.")
	return nil
}
