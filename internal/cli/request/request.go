// Package request provides the `keyorix request` CLI commands for project
// access requests (ADR-024): access (create), list, withdraw, and review
// (approve/reject). Requesting and withdrawing are self-service; review is
// admin-driven. These mirror the HTTP surface under /projects/{id}/access-requests.
package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

// RequestCmd is the root command for access-request operations.
var RequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Manage project access requests",
	Long:  "Request access to a project, list, withdraw, and review (approve/reject) requests (ADR-024).",
}

func init() {
	RequestCmd.AddCommand(accessCmd)
	RequestCmd.AddCommand(listCmd)
	RequestCmd.AddCommand(withdrawCmd)
	RequestCmd.AddCommand(reviewCmd)
}

// resolveUserID resolves an email address to a user ID via the core service.
func resolveUserID(ctx context.Context, service *core.KeyorixCore, email string) (uint, error) {
	u, err := service.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, fmt.Errorf("no user found for %q: %w", email, err)
	}
	return u.ID, nil
}

// userLabel renders a user ID as "username (#id)", falling back to "#id" if the
// lookup fails.
func userLabel(ctx context.Context, service *core.KeyorixCore, id uint) string {
	u, err := service.GetUser(ctx, id)
	if err != nil || u == nil {
		return fmt.Sprintf("#%d", id)
	}
	return fmt.Sprintf("%s (#%d)", u.Username, id)
}
