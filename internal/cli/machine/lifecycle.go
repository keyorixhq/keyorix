package machine

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

var revokeForce bool

var revokeCmd = &cobra.Command{
	Use:   "revoke <name|id>",
	Short: "Revoke a machine identity (terminal)",
	Args:  cobra.ExactArgs(1),
	RunE:  runRevoke,
}

func init() {
	for _, c := range []*cobra.Command{suspendCmd, reactivateCmd, revokeCmd} {
		c.Flags().StringVar(&lifecycleProjectName, "project", "", "Project name (defaults to the active project)")
	}
	revokeCmd.Flags().BoolVar(&revokeForce, "force", false, "Skip the confirmation prompt")
}

// lifecycleRunE returns a RunE that transitions the referenced machine identity
// to targetState. action is the API verb (activate/suspend).
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
		return transitionMachine(ctx, projectID, m, action, targetState)
	}
}

// runRevoke resolves the referenced machine identity and, unless --force is
// set, requires the operator to type its name back before revoking it — revoke
// is a one-way, irreversible credential-kill action (see canTransitionMachine:
// MachineRevoked has no outgoing transitions), matching the typed-name
// confirmation convention used by `secret delete`.
func runRevoke(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(lifecycleProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}
	return revokeMachine(cmd, ctx, projectID, m)
}

func revokeMachine(cmd *cobra.Command, ctx context.Context, projectID uint, m *models.MachineIdentity) error {
	if !revokeForce {
		fmt.Printf("Revoking %q is permanent — the machine identity cannot be reactivated afterward.\nType the machine identity name to confirm: ", m.Name)
		reader := bufio.NewReader(cmd.InOrStdin())
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(input) != m.Name {
			fmt.Println("Name mismatch — revoke aborted.")
			return nil
		}
	}
	return transitionMachine(ctx, projectID, m, "revoke", core.MachineRevoked)
}

// transitionMachine performs the actual state transition (remote or local).
func transitionMachine(ctx context.Context, projectID uint, m *models.MachineIdentity, action, targetState string) error {
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
	// #G67: operator-asserted actor (KEYORIX_CLI_ACTOR), not a hardcoded placeholder.
	if _, err := svc.TransitionMachineIdentity(ctx, m.ProjectID, m.ID, targetState, common.ResolveActorID()); err != nil {
		return fmt.Errorf("failed to %s machine identity: %w", action, err)
	}
	fmt.Printf("Machine identity %q → %s\n", m.Name, targetState)
	return nil
}
