// current.go — keyorix project current
// Prints the active project from cli.yaml or KEYORIX_PROJECT env var (ADR-016).
package project

import (
	"fmt"
	"os"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/spf13/cobra"
)

var currentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the currently active project",
	RunE:  runCurrent,
}

func runCurrent(cmd *cobra.Command, args []string) error {
	if v := os.Getenv("KEYORIX_PROJECT"); v != "" {
		fmt.Printf("%s (from KEYORIX_PROJECT)\n", v)
		return nil
	}
	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil || cfg.ActiveProject == "" {
		fmt.Println("No active project set.")
		fmt.Println("Run 'keyorix project use <name>' or set KEYORIX_PROJECT to configure one.")
		return nil
	}
	fmt.Printf("%s\n", cfg.ActiveProject)
	return nil
}
