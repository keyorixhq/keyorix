package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Revoke the stored session and forget it locally",
	Long: `Sign out: the server revokes the stored session token first, then the local
credentials file is deleted, even when the server cannot be reached or already rejects
the token, so no stale credential stays on disk.

The credentials file also holds the server URL and the ca_file setting
(keyorix config set ca_file), so both are forgotten too: against a server with a private
or self-signed certificate, run "keyorix config set ca_file <path>" again (or pass
--ca-file) before the next "keyorix login".`,
	RunE: runLogout,
}

func runLogout(cmd *cobra.Command, args []string) error {
	store, err := resolveCredStore()
	if err != nil {
		return fmt.Errorf("resolve credential store: %w", err)
	}

	serverURL, token, err := resolveServerAndToken(store)
	if err != nil {
		// Nothing stored, nothing to revoke or delete -- but not an error: logging out
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

	if err := store.Clear(); err != nil {
		return fmt.Errorf("delete local credentials: %w", err)
	}

	if revokeErr != nil {
		fmt.Fprintln(os.Stderr, "Warning: could not revoke the session server-side:", revokeErr)
		fmt.Fprintln(os.Stderr, "The local credentials were deleted anyway; the server-side token may still be valid until it expires or is revoked separately.")
		return nil
	}

	fmt.Println("Logged out.")
	return nil
}
