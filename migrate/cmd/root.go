// Package cmd implements keyorix-migrate's CLI surface (cobra), mirroring cli/cmd's shape —
// see docs/design-keyorix-migrate.md.
package cmd

import (
	"io"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keyorix-migrate",
	Short: "Import secrets from an existing secret store into Keyorix",
	Long: `keyorix-migrate imports secrets from an existing secret store (HashiCorp Vault
first; AWS/Azure/GCP follow) into Keyorix over its public REST API.

Every run defaults to a dry run: it prints a mapping plan (source -> Keyorix
project/environment/secret name, and whether each item would be created,
updated, skipped, or flagged as a conflict) without writing anything. Pass
--apply to execute the plan.

See docs/design-keyorix-migrate.md for the full design.`,
	SilenceUsage: true,
	// main prints the returned error once ("Error: ..."); without this cobra printed it a second
	// time first. Applies to every subcommand: cobra checks the root's flag as well as the command's.
	SilenceErrors: true,
}

// Execute runs the root command with the given arguments, writing command output to stdout and
// stderr. It returns the command's error without printing it: the caller prints it exactly once.
func Execute(args []string, stdout, stderr io.Writer) error {
	rootCmd.SetArgs(args)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)
	return rootCmd.Execute()
}
