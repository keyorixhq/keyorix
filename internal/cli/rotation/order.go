// order.go — the `keyorix rotation order` CLI (ADR-052): print a safe rotation
// sequence for a project's secret dependency graph, where each secret is listed
// before anything that depends on it. Talks to GET /api/v1/projects/{id}/rotation-order
// (scoped by the caller's secrets.read permission server-side).
package rotation

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

type rotationStep struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
}

type rotationOrderView struct {
	ProjectID uint           `json:"project_id"`
	Order     []rotationStep `json:"order"`
}

var orderCmd = &cobra.Command{
	Use:   "order <project-id>",
	Short: "Print a safe rotation sequence for a project's dependency graph",
	Long: `Print the order in which a project's secrets should be rotated so that each secret
is rotated before anything that depends on it (a topological sort of the dependency
graph, ADR-052). Only secrets that appear in the graph are listed.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		projectID, err := strconv.ParseUint(strings.TrimSpace(args[0]), 10, 32)
		if err != nil || projectID == 0 {
			return fmt.Errorf("invalid project id %q", args[0])
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		view, err := fetchRotationOrder(context.Background(), c, uint(projectID))
		if err != nil {
			return err
		}
		if len(view.Order) == 0 {
			fmt.Println("No secret dependencies in this project — secrets can rotate in any order.")
			return nil
		}
		fmt.Printf("Rotation order for project %d (rotate top to bottom):\n", view.ProjectID)
		for i, s := range view.Order {
			fmt.Printf("  %2d. %-6d %s\n", i+1, s.SecretID, s.SecretName)
		}
		return nil
	},
}

// fetchRotationOrder is split out for httptest-backed tests.
func fetchRotationOrder(ctx context.Context, c *common.RemoteClient, projectID uint) (*rotationOrderView, error) {
	var v rotationOrderView
	if err := c.Get(ctx, fmt.Sprintf("/api/v1/projects/%d/rotation-order", projectID), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func init() {
	RotationCmd.AddCommand(orderCmd)
}
