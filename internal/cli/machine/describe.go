package machine

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var describeProjectName string

var describeCmd = &cobra.Command{
	Use:   "describe <name|id>",
	Short: "Show details of a machine identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runDescribe,
}

func init() {
	describeCmd.Flags().StringVar(&describeProjectName, "project", "", "Project name (defaults to the active project)")
}

func runDescribe(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(describeProjectName)
	if err != nil {
		return err
	}
	m, err := findMachineByRef(ctx, projectID, args[0])
	if err != nil {
		return err
	}
	fmt.Printf("ID:          %d\n", m.ID)
	fmt.Printf("Name:        %s\n", m.Name)
	fmt.Printf("Type:        %s\n", m.IdentityType)
	fmt.Printf("State:       %s\n", m.State)
	fmt.Printf("Project ID:  %d\n", m.ProjectID)
	if m.Description != "" {
		fmt.Printf("Description: %s\n", m.Description)
	}
	if m.LastSeenAt != nil {
		fmt.Printf("Last seen:   %s\n", m.LastSeenAt.Format("2006-01-02 15:04:05 MST"))
	}
	if m.RevokedAt != nil {
		fmt.Printf("Revoked at:  %s\n", m.RevokedAt.Format("2006-01-02 15:04:05 MST"))
	}
	return nil
}
