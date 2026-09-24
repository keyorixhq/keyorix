package cmd

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var machineLifecycleProjectName string

var machineSuspendCmd = &cobra.Command{
	Use:   "suspend <name|id>",
	Short: "Suspend a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  machineLifecycleRunE(apiclient.Suspend, "suspended"),
}

var machineReactivateCmd = &cobra.Command{
	Use:   "reactivate <name|id>",
	Short: "Reactivate a suspended machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  machineLifecycleRunE(apiclient.Activate, "active"),
}

var machineRevokeForce bool

var machineRevokeCmd = &cobra.Command{
	Use:   "revoke <name|id>",
	Short: "Revoke a machine identity (terminal)",
	Args:  cobra.ExactArgs(1),
	RunE:  runMachineRevoke,
}

func init() {
	for _, c := range []*cobra.Command{machineSuspendCmd, machineReactivateCmd, machineRevokeCmd} {
		c.Flags().StringVar(&machineLifecycleProjectName, "project", "", "Project name")
	}
	machineRevokeCmd.Flags().BoolVar(&machineRevokeForce, "force", false, "Skip the confirmation prompt")
	machineCmd.AddCommand(machineSuspendCmd, machineReactivateCmd, machineRevokeCmd)
}

// machineLifecycleRunE returns a RunE that transitions the referenced machine
// identity via action, reporting it as having reached targetStateLabel.
func machineLifecycleRunE(action apiclient.TransitionMachineIdentityJSONBodyAction, targetStateLabel string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client, err := machineAPIClient()
		if err != nil {
			return err
		}
		_, projectID, err := resolveMachineProjectID(client, machineLifecycleProjectName)
		if err != nil {
			return err
		}
		m, err := findMachineByRef(client, projectID, args[0])
		if err != nil {
			return err
		}
		return transitionMachine(client, projectID, m, action, targetStateLabel)
	}
}

// runMachineRevoke resolves the referenced machine identity and, unless --force is
// set, requires the operator to type its name back before revoking it -- revoke is a
// one-way, irreversible credential-kill action, matching the typed-name confirmation
// convention used by `secret delete` (ported unchanged from the old CLI).
func runMachineRevoke(cmd *cobra.Command, args []string) error {
	client, err := machineAPIClient()
	if err != nil {
		return err
	}
	_, projectID, err := resolveMachineProjectID(client, machineLifecycleProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(client, projectID, args[0])
	if err != nil {
		return err
	}

	if !machineRevokeForce {
		fmt.Printf("Revoking %q is permanent — the machine identity cannot be reactivated afterward.\nType the machine identity name to confirm: ", derefStr(m.Name))
		reader := bufio.NewReader(cmd.InOrStdin())
		input, _ := reader.ReadString('\n')
		if strings.TrimSpace(input) != derefStr(m.Name) {
			fmt.Println("Name mismatch — revoke aborted.")
			return nil
		}
	}
	return transitionMachine(client, projectID, m, apiclient.Revoke, "revoked")
}

func transitionMachine(client *apiclient.ClientWithResponses, projectID int, m apiclient.MachineIdentity, action apiclient.TransitionMachineIdentityJSONBodyAction, targetStateLabel string) error {
	resp, err := client.TransitionMachineIdentityWithResponse(context.Background(), projectID, derefInt(m.Id), apiclient.TransitionMachineIdentityJSONRequestBody{Action: action})
	if err != nil {
		return fmt.Errorf("failed to %s machine identity: %w", action, err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return fmt.Errorf("failed to %s machine identity: HTTP %d", action, resp.StatusCode())
	}
	fmt.Printf("Machine identity %q → %s\n", derefStr(m.Name), targetStateLabel)
	return nil
}
