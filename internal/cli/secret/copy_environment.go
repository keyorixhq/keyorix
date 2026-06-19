package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	copyEnvProject uint
	copyEnvFrom    uint
	copyEnvTo      uint
)

var copyEnvironmentCmd = &cobra.Command{
	Use:   "copy-environment",
	Short: "Copy every secret from one environment into another (same project)",
	Long: `Bulk-promote a whole environment — copy every secret from one environment into
another of the same project (e.g. seed production from staging) in a single call.
Name clashes in the target are skipped, never overwritten. Requires secrets.write in
the target environment.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if copyEnvProject == 0 || copyEnvFrom == 0 || copyEnvTo == 0 {
			return fmt.Errorf("--project, --from-environment and --to-environment are required")
		}
		if copyEnvFrom == copyEnvTo {
			return fmt.Errorf("--from-environment and --to-environment must differ")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		copied, skipped, err := copyEnvironmentSecrets(context.Background(), c, copyEnvProject, copyEnvFrom, copyEnvTo)
		if err != nil {
			return err
		}
		fmt.Printf("✅ Promoted environment %d → %d: %d copied, %d skipped (name clashes).\n", copyEnvFrom, copyEnvTo, copied, skipped)
		return nil
	},
}

// copyEnvironmentSecrets POSTs the bulk copy and returns the copied/skipped counts
// (split out for tests).
func copyEnvironmentSecrets(ctx context.Context, c *common.RemoteClient, projectID, fromEnv, toEnv uint) (copied, skipped int, err error) {
	body := map[string]interface{}{"target_environment_id": toEnv}
	var out struct {
		Copied  int `json:"copied"`
		Skipped int `json:"skipped"`
	}
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) +
		"/environments/" + strconv.Itoa(int(fromEnv)) + "/copy-secrets"
	if err := c.Post(ctx, path, body, &out); err != nil {
		return 0, 0, err
	}
	return out.Copied, out.Skipped, nil
}

func init() {
	copyEnvironmentCmd.Flags().UintVar(&copyEnvProject, "project", 0, "Project ID (required)")
	copyEnvironmentCmd.Flags().UintVar(&copyEnvFrom, "from-environment", 0, "Source environment ID (required)")
	copyEnvironmentCmd.Flags().UintVar(&copyEnvTo, "to-environment", 0, "Target environment ID, same project (required)")
	SecretCmd.AddCommand(copyEnvironmentCmd)
}
