// role_expiry.go — CLI command: keyorix system role-expiry-check
//
// Triggers the role-expiry notification scan on the connected server
// (POST /api/v1/admin/jobs/role-expiry-check). Requires system.write.
package system

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// roleExpiryCheckResult mirrors the {warnings, criticals} response body.
type roleExpiryCheckResult struct {
	Warnings  int `json:"warnings"`
	Criticals int `json:"criticals"`
}

var roleExpiryCheckCmd = &cobra.Command{
	Use:   "role-expiry-check",
	Short: "Trigger a role-expiry notification scan on the connected server",
	Long: `Send immediate role-expiry notifications for time-bound role grants
approaching their deadline (POST /api/v1/admin/jobs/role-expiry-check).

Warning notifications are sent for grants expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var result roleExpiryCheckResult
		if err := c.Post(context.Background(), "/api/v1/admin/jobs/role-expiry-check", nil, &result); err != nil {
			return err
		}
		fmt.Printf("Role-expiry check complete: %d warning(s), %d critical(s)\n", result.Warnings, result.Criticals)
		return nil
	},
}
