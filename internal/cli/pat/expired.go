// expired.go — `keyorix pat list-expired` and `keyorix pat cleanup-expired`.
//
// list-expired lists the caller's own expired (non-revoked) personal access
// tokens so they can see what needs cleaning up. cleanup-expired bulk-revokes
// all of them in a single server call.
package pat

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func init() {
	PATCmd.AddCommand(listExpiredCmd, cleanupExpiredCmd)
}

var listExpiredCmd = &cobra.Command{
	Use:   "list-expired",
	Short: "List your expired (non-revoked) personal access tokens",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var tokens []patView
		if err := c.Get(context.Background(), "/api/v1/auth/tokens/expired", &tokens); err != nil {
			return err
		}
		if len(tokens) == 0 {
			fmt.Println("You have no expired personal access tokens.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tPREFIX\tCREATED\tEXPIRED\tSCOPE") //nolint:errcheck
		for _, t := range tokens {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck
				t.ID, t.Name, t.TokenPrefix+"…",
				patDate(&t.CreatedAt), patDate(t.ExpiresAt),
				describeScope(t))
		}
		_ = w.Flush() // #nosec G104
		return nil
	},
}

var cleanupExpiredCmd = &cobra.Command{
	Use:   "cleanup-expired",
	Short: "Bulk-revoke all your expired personal access tokens",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), "/api/v1/auth/tokens/expired"); err != nil {
			return err
		}
		fmt.Println("All expired tokens have been revoked.")
		return nil
	},
}
