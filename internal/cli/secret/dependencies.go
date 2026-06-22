// dependencies.go — the `keyorix secret deps` CLI (ADR-052): inspect and manage a
// secret's dependency graph from the terminal, and see the blast radius of rotating
// it. All commands talk to the server's REST API under /api/v1/secrets/{id}/...,
// scoped by the caller's secrets.read / secrets.write permission server-side.
package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

type depEdgeView struct {
	ID         uint   `json:"id"`
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Note       string `json:"note"`
}

type depsView struct {
	SecretID   uint          `json:"secret_id"`
	DependsOn  []depEdgeView `json:"depends_on"`
	Dependents []depEdgeView `json:"dependents"`
}

type impactedView struct {
	SecretID   uint   `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Depth      int    `json:"depth"`
}

type impactView struct {
	SecretID   uint           `json:"secret_id"`
	SecretName string         `json:"secret_name"`
	Affected   []impactedView `json:"affected"`
}

var depNote string

var depsCmd = &cobra.Command{
	Use:     "deps",
	Aliases: []string{"dependencies"},
	Short:   "Inspect and manage a secret's dependency graph",
	Long: `Manage the secret dependency graph (ADR-052): declare that one secret depends on
another, list a secret's dependencies and dependents, and see the blast radius of
rotating it. Dependencies drive rotation impact analysis and ordering.`,
}

var depsListCmd = &cobra.Command{
	Use:          "list <secret-id>",
	Short:        "Show what a secret depends on and what depends on it",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := depsClient()
		if err != nil {
			return err
		}
		v, err := fetchDependencies(context.Background(), c, id)
		if err != nil {
			return err
		}
		printDependencies(v)
		return nil
	},
}

var depsAddCmd = &cobra.Command{
	Use:          "add <secret-id> <depends-on-id>",
	Short:        "Declare that <secret-id> depends on <depends-on-id>",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		dependsOn, err := parseSecretArg(args[1])
		if err != nil {
			return err
		}
		c, err := depsClient()
		if err != nil {
			return err
		}
		body := map[string]interface{}{"depends_on_id": dependsOn, "note": depNote}
		var out depEdgeView
		if err := c.Post(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/dependencies", id), body, &out); err != nil {
			return err
		}
		fmt.Printf("Added: secret %d now depends on secret %d (edge %d).\n", id, dependsOn, out.ID)
		return nil
	},
}

var depsRemoveCmd = &cobra.Command{
	Use:          "rm <secret-id> <edge-id>",
	Aliases:      []string{"remove", "delete"},
	Short:        "Remove a dependency edge (edge id from `deps list`)",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		edgeID, err := parseSecretArg(args[1])
		if err != nil {
			return err
		}
		c, err := depsClient()
		if err != nil {
			return err
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/dependencies/%d", id, edgeID)); err != nil {
			return err
		}
		fmt.Printf("Removed dependency edge %d from secret %d.\n", edgeID, id)
		return nil
	},
}

var depsImpactCmd = &cobra.Command{
	Use:          "impact <secret-id>",
	Short:        "Show the blast radius of rotating a secret (transitive dependents)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := parseSecretArg(args[0])
		if err != nil {
			return err
		}
		c, err := depsClient()
		if err != nil {
			return err
		}
		v, err := fetchImpact(context.Background(), c, id)
		if err != nil {
			return err
		}
		printImpact(v)
		return nil
	},
}

// fetchDependencies / fetchImpact are split out so the rendering can be tested against
// an httptest-backed client.
func fetchDependencies(ctx context.Context, c *common.RemoteClient, id uint) (*depsView, error) {
	var v depsView
	if err := c.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d/dependencies", id), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func fetchImpact(ctx context.Context, c *common.RemoteClient, id uint) (*impactView, error) {
	var v impactView
	if err := c.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d/impact", id), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func printDependencies(v *depsView) {
	fmt.Printf("Depends on (%d):\n", len(v.DependsOn))
	if len(v.DependsOn) == 0 {
		fmt.Println("  (none — this secret stands alone)")
	}
	for _, e := range v.DependsOn {
		fmt.Printf("  edge %-5d → secret %-5d %s%s\n", e.ID, e.SecretID, e.SecretName, noteSuffix(e.Note))
	}
	fmt.Printf("Used by (%d):\n", len(v.Dependents))
	if len(v.Dependents) == 0 {
		fmt.Println("  (none)")
	}
	for _, e := range v.Dependents {
		fmt.Printf("  edge %-5d ← secret %-5d %s%s\n", e.ID, e.SecretID, e.SecretName, noteSuffix(e.Note))
	}
}

func printImpact(v *impactView) {
	if len(v.Affected) == 0 {
		fmt.Printf("Rotating %s (secret %d) affects no other secrets.\n", v.SecretName, v.SecretID)
		return
	}
	fmt.Printf("Rotating %s (secret %d) affects %d secret(s):\n", v.SecretName, v.SecretID, len(v.Affected))
	for _, a := range v.Affected {
		fmt.Printf("  %-5d %-26s (%d hop%s)\n", a.SecretID, a.SecretName, a.Depth, plural(a.Depth))
	}
}

func noteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return "  — " + note
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func parseSecretArg(s string) (uint, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid secret id %q", s)
	}
	return uint(n), nil
}

func depsClient() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

func init() {
	depsAddCmd.Flags().StringVar(&depNote, "note", "", "Optional note describing the dependency")
	depsCmd.AddCommand(depsListCmd, depsAddCmd, depsRemoveCmd, depsImpactCmd)
	SecretCmd.AddCommand(depsCmd)
}
