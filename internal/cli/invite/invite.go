// Package invite provides the `keyorix invite` CLI commands for project
// invitations (ADR-024): send, list, and revoke. These operate on the local
// core service directly, mirroring the admin-gated HTTP surface
// (POST/GET/DELETE /projects/{id}/invitations).
package invite

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

// InviteCmd is the root command for invitation operations.
var InviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage project invitations",
	Long:  "Send, list, and revoke project invitations (ADR-024).",
}

func init() {
	InviteCmd.AddCommand(sendCmd)
	InviteCmd.AddCommand(listCmd)
	InviteCmd.AddCommand(revokeCmd)
}

// resolveUserID resolves an email address to a user ID via the core service.
func resolveUserID(ctx context.Context, service *core.KeyorixCore, email string) (uint, error) {
	u, err := service.GetUserByEmail(ctx, email)
	if err != nil {
		return 0, fmt.Errorf("no user found for %q: %w", email, err)
	}
	return u.ID, nil
}

// fmtTime renders an optional timestamp for table output.
func fmtTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}
