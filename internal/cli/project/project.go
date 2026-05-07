// project.go — CLI commands for managing Keyorix projects.
//
// Commands: project list, project create, project environments
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
	ProjectCmd.AddCommand(environmentsCmd)
}
