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
	Long: `logout is the remote-only successor to the old CLI's "auth logout"
(docs/cli-split-inventory.md §2.3, §4): the old command only cleared local config and
never told the server (§8 Finding S12). This one calls POST /auth/logout to invalidate
the token server-side first, then deletes the local credentials file regardless of
whether that call succeeded -- a server that is unreachable or already rejects the
token must not leave a stale credential sitting on disk.`,
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
