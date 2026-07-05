// Package request provides the `keyorix request` CLI commands for project
// access requests (ADR-024): access (create), list, withdraw, and review
// (approve/reject). Requesting and withdrawing are self-service; review is
// admin-driven. These mirror the HTTP surface under /projects/{id}/access-requests.
//
// secret-access is the narrower sibling: a request for approval to read one
// specific secret's value (the classification gate — see
// internal/core/classification_gate.go), rather than a role at a project.
// list/withdraw/review all work on it unchanged (it's the same AccessRequest
// row, just with SecretID set); review's approve path detects that and routes
// to ApproveSecretAccessRequest instead of granting a role.
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
	RequestCmd.AddCommand(secretAccessCmd)
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
