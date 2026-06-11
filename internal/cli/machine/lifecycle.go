package machine

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var lifecycleProjectName string

var suspendCmd = &cobra.Command{
	Use:   "suspend <name|id>",
	Short: "Suspend a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  lifecycleRunE("suspend", core.MachineSuspended),
}

var reactivateCmd = &cobra.Command{
	Use:   "reactivate <name|id>",
	Short: "Reactivate a suspended machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  lifecycleRunE("activate", core.MachineActive),
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <name|id>",
	Short: "Revoke a machine identity (terminal)",
	Args:  cobra.ExactArgs(1),
	RunE:  lifecycleRunE("revoke", core.MachineRevoked),
}

func init() {
	for _, c := range []*cobra.Command{suspendCmd, reactivateCmd, revokeCmd} {
		c.Flags().StringVar(&lifecycleProjectName, "project", "", "Project name (defaults to the active project)")
	}
}

// lifecycleRunE returns a RunE that transitions the referenced machine identity
// to targetState. action is the API verb (activate/suspend/revoke).
func lifecycleRunE(action, targetState string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		_, projectID, err := resolveProjectContext(lifecycleProjectName)
		if err != nil {
			return err
		}
		m, err := findMachineByRef(ctx, projectID, args[0])
		if err != nil {
			return err
		}

		if rc, ok := common.NewRemoteClient(); ok {
			path := fmt.Sprintf("/api/v1/projects/%d/machine-identities/%d", projectID, m.ID)
			if err := rc.Put(ctx, path, map[string]interface{}{"action": action}, nil); err != nil {
				return fmt.Errorf("failed to %s machine identity: %w", action, err)
			}
			fmt.Printf("Machine identity %q → %s\n", m.Name, targetState)
			return nil
		}

		svc, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		if _, err := svc.TransitionMachineIdentity(ctx, m.ProjectID, m.ID, targetState, 0); err != nil {
			return fmt.Errorf("failed to %s machine identity: %w", action, err)
		}
		fmt.Printf("Machine identity %q → %s\n", m.Name, targetState)
		return nil
	}
}
