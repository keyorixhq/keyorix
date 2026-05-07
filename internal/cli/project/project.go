// project.go — CLI commands for managing Keyorix projects.
//
// Commands: project list, project create, project use, project current,
//
//	project describe, project env list/create/delete
package project

import (
	"github.com/spf13/cobra"
)

// ProjectCmd is the root command for project management.
var ProjectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
	Long:  "Commands for listing, creating, and inspecting Keyorix projects.",
}

func init() {
	ProjectCmd.AddCommand(listCmd)
	ProjectCmd.AddCommand(createCmd)
	ProjectCmd.AddCommand(useCmd)
	ProjectCmd.AddCommand(currentCmd)
	ProjectCmd.AddCommand(describeCmd)

	// env subcommand tree: project env list/create/delete
	envCmd.AddCommand(envListCmd)
	envCmd.AddCommand(envCreateCmd)
	envCmd.AddCommand(envDeleteCmd)
	ProjectCmd.AddCommand(envCmd)

	// Keep legacy 'environments' alias for backwards compat.
	ProjectCmd.AddCommand(environmentsCmd)
}
