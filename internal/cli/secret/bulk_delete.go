// bulk_delete.go — CLI command for deleting multiple secrets in a single call.
// Follows the bulk-rename pattern; destructive so --confirm is required.
package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	bulkDeleteProject uint
	bulkDeleteIDs     []uint
	bulkDeleteNames   []string
	bulkDeleteConfirm bool
)

// bulkDeleteResult mirrors the BulkDeleteResult from core / the HTTP response envelope.
type bulkDeleteResult struct {
	Deleted []uint             `json:"deleted"`
	Failed  []bulkDeleteError  `json:"failed"`
	Total   int                `json:"total"`
}

type bulkDeleteError struct {
	SecretID uint   `json:"secret_id"`
	Name     string `json:"name"`
	Error    string `json:"error"`
}

var bulkDeleteCmd = &cobra.Command{
	Use:   "bulk-delete",
	Short: "Delete multiple secrets in one operation",
	Long: `Delete one or more secrets in a project in a single call.

Pass secret IDs directly with --ids, or resolve by name with --names (requires
--project for name resolution). --confirm is mandatory for the deletion to
proceed; without it the command prints what would be deleted and exits.

  keyorix secret bulk-delete --ids 1,2,3 --confirm
  keyorix secret bulk-delete --names s1,s2,s3 --project 7 --confirm`,
	SilenceUsage: true,
	RunE:         runBulkDelete,
}

func init() {
	bulkDeleteCmd.Flags().UintVar(&bulkDeleteProject, "project", 0, "Project ID (required for --names and for cross-project guard)")
	bulkDeleteCmd.Flags().UintSliceVar(&bulkDeleteIDs, "ids", nil, "Comma-separated secret IDs to delete")
	bulkDeleteCmd.Flags().StringSliceVar(&bulkDeleteNames, "names", nil, "Comma-separated secret names to delete (requires --project)")
	bulkDeleteCmd.Flags().BoolVar(&bulkDeleteConfirm, "confirm", false, "Required to actually delete (omit to preview)")
	SecretCmd.AddCommand(bulkDeleteCmd)
}

func runBulkDelete(_ *cobra.Command, _ []string) error {
	if len(bulkDeleteIDs) == 0 && len(bulkDeleteNames) == 0 {
		return fmt.Errorf("at least one of --ids or --names is required")
	}

	rc, ok := common.NewRemoteClient()
	if !ok {
		return runBulkDeleteEmbedded(context.Background())
	}
	return runBulkDeleteRemote(context.Background(), rc)
}

// ── Remote mode ───────────────────────────────────────────────────────────────

func runBulkDeleteRemote(ctx context.Context, rc *common.RemoteClient) error {
	if bulkDeleteProject == 0 && len(bulkDeleteNames) > 0 {
		return fmt.Errorf("--project is required when using --names")
	}

	ids := make([]uint, 0, len(bulkDeleteIDs)+len(bulkDeleteNames))
	ids = append(ids, bulkDeleteIDs...)

	// Resolve names → IDs via the project's secret list.
	if len(bulkDeleteNames) > 0 {
		resolved, err := resolveNamesToIDs(ctx, rc, bulkDeleteProject, bulkDeleteNames)
		if err != nil {
			return err
		}
		ids = append(ids, resolved...)
	}

	if !bulkDeleteConfirm {
		fmt.Printf("Would delete %d secret(s): %s\n", len(ids), joinUints(ids))
		fmt.Println("Pass --confirm to actually delete.")
		return nil
	}

	result, err := postBulkDelete(ctx, rc, bulkDeleteProject, ids)
	if err != nil {
		return err
	}
	printBulkDeleteResult(result)
	return nil
}

// postBulkDelete POSTs the bulk-delete request and returns the result.
// Extracted for httptest-level unit tests.
func postBulkDelete(ctx context.Context, rc *common.RemoteClient, projectID uint, ids []uint) (bulkDeleteResult, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/bulk-delete"
	body := map[string]interface{}{"secret_ids": ids}
	var result bulkDeleteResult
	if err := rc.Post(ctx, path, body, &result); err != nil {
		return bulkDeleteResult{}, err
	}
	return result, nil
}

// resolveNamesToIDs fetches the project's secret list and resolves each name to
// its ID. Unknown names produce an error.
func resolveNamesToIDs(ctx context.Context, rc *common.RemoteClient, projectID uint, names []string) ([]uint, error) {
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d&page_size=500", projectID)
	var resp models.SecretListResponse
	if err := rc.Get(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("failed to list secrets for name resolution: %w", err)
	}

	nameToID := make(map[string]uint, len(resp.Secrets))
	for _, s := range resp.Secrets {
		if s.SecretNode != nil {
			nameToID[s.SecretNode.Name] = s.SecretNode.ID
		}
	}

	ids := make([]uint, 0, len(names))
	var missing []string
	for _, name := range names {
		id, ok := nameToID[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		ids = append(ids, id)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("secret(s) not found in project %d: %s", projectID, strings.Join(missing, ", "))
	}
	return ids, nil
}

// ── Embedded mode ─────────────────────────────────────────────────────────────

func runBulkDeleteEmbedded(ctx context.Context) error {
	if bulkDeleteProject == 0 {
		return fmt.Errorf("--project is required in embedded mode")
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return err
	}

	ids := make([]uint, 0, len(bulkDeleteIDs)+len(bulkDeleteNames))
	ids = append(ids, bulkDeleteIDs...)

	if len(bulkDeleteNames) > 0 {
		resolved, err := resolveNamesToIDsEmbedded(ctx, svc, bulkDeleteProject, bulkDeleteNames)
		if err != nil {
			return err
		}
		ids = append(ids, resolved...)
	}

	if !bulkDeleteConfirm {
		fmt.Printf("Would delete %d secret(s): %s\n", len(ids), joinUints(ids))
		fmt.Println("Pass --confirm to actually delete.")
		return nil
	}

	req := core.BulkDeleteRequest{SecretIDs: ids}
	result, err := svc.BulkDeleteSecrets(ctx, req, bulkDeleteProject, "cli", 0, "", "")
	if err != nil {
		return fmt.Errorf("bulk delete failed: %w", err)
	}

	// Map core result to display type.
	dr := bulkDeleteResult{
		Deleted: result.Deleted,
		Total:   result.Total,
	}
	for _, f := range result.Failed {
		dr.Failed = append(dr.Failed, bulkDeleteError{
			SecretID: f.SecretID,
			Name:     f.Name,
			Error:    f.Error,
		})
	}
	printBulkDeleteResult(dr)
	return nil
}

func resolveNamesToIDsEmbedded(ctx context.Context, svc *core.KeyorixCore, projectID uint, names []string) ([]uint, error) {
	filter := &coreStorage.SecretFilter{ProjectID: &projectID, PageSize: 500}
	secrets, _, err := svc.ListSecrets(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets for name resolution: %w", err)
	}

	nameToID := make(map[string]uint, len(secrets))
	for _, s := range secrets {
		nameToID[s.Name] = s.ID
	}

	ids := make([]uint, 0, len(names))
	var missing []string
	for _, name := range names {
		id, ok := nameToID[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		ids = append(ids, id)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("secret(s) not found in project %d: %s", projectID, strings.Join(missing, ", "))
	}
	return ids, nil
}

// ── Output ────────────────────────────────────────────────────────────────────

func printBulkDeleteResult(r bulkDeleteResult) {
	fmt.Printf("Deleted %d secrets.\n", len(r.Deleted))
	if len(r.Failed) > 0 {
		fmt.Println("\nFailed:")
		for _, f := range r.Failed {
			label := f.Name
			if label == "" {
				label = fmt.Sprintf("id=%d", f.SecretID)
			}
			fmt.Printf("  %s: %s\n", label, f.Error)
		}
	}
}

func joinUints(ids []uint) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(int(id))
	}
	return strings.Join(parts, ", ")
}
