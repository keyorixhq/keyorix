package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// bulkRotateResultDTO mirrors the core.BulkRotateResult JSON shape the API returns.
type bulkRotateResultDTO struct {
	Triggered []uint             `json:"triggered"`
	Failed    []bulkRotateErrDTO `json:"failed"`
	Total     int                `json:"total"`
}

// bulkRotateErrDTO mirrors core.BulkRotateError.
type bulkRotateErrDTO struct {
	SecretID uint   `json:"secret_id"`
	Name     string `json:"name"`
	Error    string `json:"error"`
}

var (
	bulkRotateProject        uint
	bulkRotateEnv            uint
	bulkRotateClassification string
	bulkRotateNames          string
	bulkRotateConfirm        bool
)

var bulkRotateCmd = &cobra.Command{
	Use:   "bulk-rotate",
	Short: "Trigger rotation for multiple secrets at once",
	Long: `Trigger rotation for all matching secrets in a project — the CLI surface for
incident response ("rotate everything tagged confidential in project X").

Secrets without auto-rotate configured are skipped (reported in the failure list,
not treated as errors) so the operation is always best-effort.

Without --names the command rotates every matching secret in the project; use
--env and/or --classification to narrow the scope.

--confirm is required (or pass --names to rotate a named subset): this is a bulk
destructive operation and an accidental wide rotation cannot be undone.

  keyorix secret bulk-rotate --project 7 --classification confidential --confirm
  keyorix secret bulk-rotate --project 7 --env 3 --confirm
  keyorix secret bulk-rotate --project 7 --names db-password,api-key --confirm`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if bulkRotateProject == 0 {
			return fmt.Errorf("--project is required")
		}
		if !bulkRotateConfirm {
			return fmt.Errorf("--confirm is required to proceed with bulk rotation (this is a destructive bulk operation)")
		}

		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}

		// Resolve --names to a list of secret IDs if provided.
		var secretIDs []uint
		if bulkRotateNames != "" {
			ids, err := resolveSecretNamesToIDs(context.Background(), c, bulkRotateProject, bulkRotateEnv, splitNames(bulkRotateNames))
			if err != nil {
				return fmt.Errorf("resolve secret names: %w", err)
			}
			secretIDs = ids
		}

		result, err := postBulkRotate(context.Background(), c, bulkRotateProject, secretIDs, bulkRotateEnv, bulkRotateClassification)
		if err != nil {
			return err
		}

		fmt.Printf("Bulk rotation triggered: %d scheduled, %d failed\n", len(result.Triggered), len(result.Failed))
		if len(result.Failed) > 0 {
			fmt.Println("\nFailed:")
			for _, f := range result.Failed {
				label := f.Name
				if label == "" {
					label = fmt.Sprintf("id:%d", f.SecretID)
				}
				fmt.Printf("  %-30s %s\n", label+":", f.Error)
			}
		}
		return nil
	},
}

// splitNames splits a comma-separated name list, trimming whitespace.
func splitNames(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// resolveSecretNamesToIDs resolves a list of secret names to IDs by listing secrets
// in the given project (and optionally environment). Names not found are skipped
// with a warning.
func resolveSecretNamesToIDs(ctx context.Context, c *common.RemoteClient, projectID, envID uint, names []string) ([]uint, error) {
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d", projectID)
	if envID != 0 {
		path += fmt.Sprintf("&environment_id=%d", envID)
	}

	var resp struct {
		Secrets []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"secrets"`
	}
	if err := c.Get(ctx, path, &resp); err != nil {
		return nil, err
	}

	nameToID := make(map[string]uint, len(resp.Secrets))
	for _, s := range resp.Secrets {
		nameToID[s.Name] = s.ID
	}

	ids := make([]uint, 0, len(names))
	for _, n := range names {
		id, ok := nameToID[n]
		if !ok {
			fmt.Printf("warning: secret %q not found — skipping\n", n)
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// postBulkRotate POSTs the bulk-rotate request (split out for httptest tests).
func postBulkRotate(ctx context.Context, c *common.RemoteClient, projectID uint, secretIDs []uint, envID uint, classification string) (bulkRotateResultDTO, error) {
	path := fmt.Sprintf("/api/v1/projects/%d/secrets/bulk-rotate", projectID)
	body := map[string]interface{}{
		"secret_ids":     secretIDs,
		"environment_id": envID,
		"classification": classification,
	}
	var result bulkRotateResultDTO
	if err := c.Post(ctx, path, body, &result); err != nil {
		return bulkRotateResultDTO{}, err
	}
	return result, nil
}

func init() {
	bulkRotateCmd.Flags().UintVar(&bulkRotateProject, "project", 0, "Project ID (required)")
	bulkRotateCmd.Flags().UintVar(&bulkRotateEnv, "env", 0, "Environment ID (optional filter)")
	bulkRotateCmd.Flags().StringVar(&bulkRotateClassification, "classification", "", "Classification label filter (e.g. confidential)")
	bulkRotateCmd.Flags().StringVar(&bulkRotateNames, "names", "", "Comma-separated secret names to rotate (omit to rotate all matching)")
	bulkRotateCmd.Flags().BoolVar(&bulkRotateConfirm, "confirm", false, "Required: confirm you want to trigger bulk rotation")
	SecretCmd.AddCommand(bulkRotateCmd)
}
