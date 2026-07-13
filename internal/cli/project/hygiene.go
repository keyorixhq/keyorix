package project

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// hygieneSummary mirrors the GET /projects/{id}/hygiene response (counts only).
type hygieneSummary struct {
	OrphanedSecrets        int `json:"orphaned_secrets"`
	UnusedSecrets          int `json:"unused_secrets"`
	ExpiringSecrets        int `json:"expiring_secrets"`
	StaleMachineIdentities int `json:"stale_machine_identities"`
	RotationOverdue        int `json:"rotation_overdue"`
}

var hygieneCmd = &cobra.Command{
	Use:   "hygiene <project-id>",
	Short: "Show a project's security-hygiene posture (counts)",
	Long: `Summarize a project's outstanding cleanup signals in one call: secrets whose owner
departed, secrets unused for a long window, secrets expiring/expired, and stale machine
identities. Requires secrets.read at the project scope.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		id, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid project ID: %s", args[0])
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		h, err := fetchHygiene(context.Background(), c, uint(id))
		if err != nil {
			return err
		}
		fmt.Printf("Hygiene for project %d:\n", id)
		fmt.Printf("  orphaned secrets         %d\n", h.OrphanedSecrets)
		fmt.Printf("  unused secrets           %d\n", h.UnusedSecrets)
		fmt.Printf("  expiring/expired secrets %d\n", h.ExpiringSecrets)
		fmt.Printf("  stale machine identities %d\n", h.StaleMachineIdentities)
		fmt.Printf("  rotation overdue         %d\n", h.RotationOverdue)
		return nil
	},
}

// fetchHygiene GETs the project hygiene summary (split out for httptest tests).
func fetchHygiene(ctx context.Context, c *common.RemoteClient, projectID uint) (*hygieneSummary, error) {
	var out hygieneSummary
	if err := c.Get(ctx, "/api/v1/projects/"+strconv.FormatUint(uint64(projectID), 10)+"/hygiene", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func init() {
	ProjectCmd.AddCommand(hygieneCmd)
}
