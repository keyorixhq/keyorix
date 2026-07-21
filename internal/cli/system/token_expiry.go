// token_expiry.go — CLI command: keyorix system token-expiry-check
//
// Triggers the PAT and machine-credential expiry notification scan on the
// connected server (POST /api/v1/admin/jobs/token-expiry-check). Requires system.write.
package system

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// tokenExpiryCheckResult mirrors the {pat_warnings, pat_criticals, machine_warnings,
// machine_criticals} response body.
type tokenExpiryCheckResult struct {
	PATWarnings      int `json:"pat_warnings"`
	PATCriticals     int `json:"pat_criticals"`
	MachineWarnings  int `json:"machine_warnings"`
	MachineCriticals int `json:"machine_criticals"`
}

var tokenExpiryCheckCmd = &cobra.Command{
	Use:   "token-expiry-check",
	Short: "Trigger a PAT and machine-credential expiry notification scan on the connected server",
	Long: `Send immediate expiry notifications for PersonalAccessTokens and
MachineIdentityCredentials approaching their deadline
(POST /api/v1/admin/jobs/token-expiry-check).

Warning notifications are sent for tokens expiring within 7 days; critical
notifications for those expiring within 1 day. Requires system.write.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var result tokenExpiryCheckResult
		if err := c.Post(context.Background(), "/api/v1/admin/jobs/token-expiry-check", nil, &result); err != nil {
			return err
		}
		fmt.Printf("Token expiry check complete: %d PAT warning(s), %d PAT critical(s), %d machine warning(s), %d machine critical(s)\n",
			result.PATWarnings, result.PATCriticals, result.MachineWarnings, result.MachineCriticals)
		return nil
	},
}
