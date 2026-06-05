// migrate.go — one-off operator migration helpers.
//
// These commands run against the local database (direct core service, no remote
// API), mirroring the user account-lifecycle CLI: they have no session, so the
// acting admin is supplied by email via --by for audit attribution. Today the
// group hosts `migrate user-to-machine` (ADR-023).
package migrate

import (
	"github.com/spf13/cobra"
)

// MigrateCmd is the root command for operator migrations.
var MigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Operator migration helpers",
	Long:  "One-off migrations an operator runs against the local database, such as converting service-account-shaped users into machine identities.",
}

func init() {
	MigrateCmd.AddCommand(userToMachineCmd)
}
