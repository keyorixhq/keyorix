package machine

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var listProjectName string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List machine identities in a project",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listProjectName, "project", "", "Project name (defaults to the active project)")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	projectName, projectID, err := resolveProjectContext(listProjectName)
	if err != nil {
		return err
	}
	identities, err := fetchMachineIdentities(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list machine identities: %w", err)
	}
	printMachineTable(identities, projectName)
	return nil
}

func printMachineTable(identities []*models.MachineIdentity, projectName string) {
	if len(identities) == 0 {
		fmt.Printf("No machine identities found for project %q.\n", projectName)
		return
	}
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "ID", "NAME", "TYPE", "STATE", "DESCRIPTION")
	fmt.Printf("%-5s %-24s %-12s %-10s %s\n", "-----", "------------------------", "------------", "----------", "-----------")
	for _, m := range identities {
		desc := m.Description
		if len(desc) > 40 {
			desc = desc[:37] + "..."
		}
		fmt.Printf("%-5d %-24s %-12s %-10s %s\n", m.ID, m.Name, m.IdentityType, m.State, desc)
	}
}
