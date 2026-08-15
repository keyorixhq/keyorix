// folder.go — CLI subcommand: keyorix secret folder create/list/delete
package secret

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

// folderCmd is the root subcommand: keyorix secret folder
var folderCmd = &cobra.Command{
	Use:   "folder",
	Short: "Manage secret folders",
	Long:  "Commands for creating, listing, and deleting secret folder nodes.",
}

// ── Create ────────────────────────────────────────────────────────────────────

var (
	folderCreateName    string
	folderCreateProject uint
	folderCreateEnvID   uint
	folderCreateParent  uint // 0 = root
)

var folderCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a folder",
	RunE:  runFolderCreate,
}

func init() {
	folderCreateCmd.Flags().StringVar(&folderCreateName, "name", "", "Folder name (required)")
	folderCreateCmd.Flags().UintVar(&folderCreateProject, "project", 1, "Project ID")
	folderCreateCmd.Flags().UintVar(&folderCreateEnvID, "environment", 1, "Environment ID")
	folderCreateCmd.Flags().UintVar(&folderCreateParent, "parent", 0, "Parent folder ID (0 = root)")

	folderCmd.AddCommand(folderCreateCmd)
}

func runFolderCreate(cmd *cobra.Command, args []string) error {
	if folderCreateName == "" {
		return fmt.Errorf("folder name is required (use --name)")
	}

	ctx := context.Background()

	body := map[string]interface{}{
		"name":           folderCreateName,
		"project_id":     folderCreateProject,
		"environment_id": folderCreateEnvID,
	}
	if folderCreateParent != 0 {
		body["parent_id"] = folderCreateParent
	}

	if rc, ok := common.NewRemoteClient(); ok {
		var folder models.SecretNode
		if err := rc.Post(ctx, "/api/v1/folders", body, &folder); err != nil {
			return fmt.Errorf("failed to create folder: %w", err)
		}
		printFolder(&folder)
		return nil
	}

	// Embedded mode.
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	var parentID *uint
	if folderCreateParent != 0 {
		pid := folderCreateParent
		parentID = &pid
	}
	folder, err := service.CreateFolder(ctx, 0, folderCreateName, folderCreateProject, folderCreateEnvID, parentID)
	if err != nil {
		return fmt.Errorf("failed to create folder: %w", err)
	}
	printFolder(folder)
	return nil
}

func printFolder(f *models.SecretNode) {
	fmt.Printf("Folder created successfully!\n")
	fmt.Printf("ID:          %d\n", f.ID)
	fmt.Printf("Name:        %s\n", f.Name)
	fmt.Printf("Project:     %d\n", f.ProjectID)
	fmt.Printf("Environment: %d\n", f.EnvironmentID)
	if f.ParentID != nil {
		fmt.Printf("Parent ID:   %d\n", *f.ParentID)
	}
	fmt.Printf("Created:     %s\n", f.CreatedAt.Format(time.RFC3339))
}

// ── List ─────────────────────────────────────────────────────────────────────

var (
	folderListProject uint
	folderListParent  uint // 0 = all
)

var folderListCmd = &cobra.Command{
	Use:   "list",
	Short: "List folders",
	RunE:  runFolderList,
}

func init() {
	folderListCmd.Flags().UintVar(&folderListProject, "project", 0, "Filter by project ID")
	folderListCmd.Flags().UintVar(&folderListParent, "parent", 0, "Filter by parent folder ID (0 = no filter)")

	folderCmd.AddCommand(folderListCmd)
}

func runFolderList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		path := "/api/v1/folders?page_size=100"
		if folderListProject != 0 {
			path += fmt.Sprintf("&project_id=%d", folderListProject)
		}
		if folderListParent != 0 {
			path += fmt.Sprintf("&parent_id=%d", folderListParent)
		}

		var folders []*models.SecretNode
		if err := rc.Get(ctx, path, &folders); err != nil {
			return fmt.Errorf("failed to list folders: %w", err)
		}
		printFolderList(folders)
		return nil
	}

	// Embedded mode.
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	var parentID *uint
	if folderListParent != 0 {
		pid := folderListParent
		parentID = &pid
	}
	folders, _, err := service.ListFolders(ctx, folderListProject, parentID, 1, 100)
	if err != nil {
		return fmt.Errorf("failed to list folders: %w", err)
	}
	printFolderList(folders)
	return nil
}

func printFolderList(folders []*models.SecretNode) {
	if len(folders) == 0 {
		fmt.Println("No folders found.")
		return
	}
	fmt.Printf("%-6s  %-30s  %-10s  %-12s  %-10s\n", "ID", "Name", "Project", "Environment", "Parent")
	fmt.Printf("%-6s  %-30s  %-10s  %-12s  %-10s\n", "------", "------------------------------", "----------", "------------", "----------")
	for _, f := range folders {
		parentStr := "-"
		if f.ParentID != nil {
			parentStr = fmt.Sprintf("%d", *f.ParentID)
		}
		fmt.Printf("%-6d  %-30s  %-10d  %-12d  %-10s\n", f.ID, f.Name, f.ProjectID, f.EnvironmentID, parentStr)
	}
}

// ── Delete ────────────────────────────────────────────────────────────────────

var (
	folderDeleteID    uint
	folderDeleteForce bool
)

var folderDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a folder",
	Long: `Delete a secret folder node permanently.

Examples:
  keyorix secret folder delete --id 123
  keyorix secret folder delete --id 123 --force  # Skip confirmation`,
	RunE: runFolderDelete,
}

func init() {
	folderDeleteCmd.Flags().UintVar(&folderDeleteID, "id", 0, "Folder ID to delete (required)")
	folderDeleteCmd.Flags().BoolVar(&folderDeleteForce, "force", false, "Skip confirmation prompt")

	folderCmd.AddCommand(folderDeleteCmd)
}

// confirmFolderDeletion prompts on stdin and reports whether the operator typed "y"/"yes"
// (case-insensitive). Anything else — including a blank line — is treated as "no", so an
// accidental Enter never confirms a destructive action.
func confirmFolderDeletion(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (yes/no): ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}

func runFolderDelete(cmd *cobra.Command, args []string) error {
	if folderDeleteID == 0 {
		return fmt.Errorf("folder ID is required (use --id)")
	}

	// Deleting a folder (and everything nested under it) is irreversible, so require
	// an explicit confirmation unless the caller opted out with --force (e.g. for
	// scripted/CI use) — mirrors `secret delete`/`user delete`.
	if !folderDeleteForce {
		prompt := fmt.Sprintf("Delete folder %d? This cannot be undone.", folderDeleteID)
		if !confirmFolderDeletion(prompt) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		path := fmt.Sprintf("/api/v1/folders/%d", folderDeleteID)
		if err := rc.Delete(ctx, path); err != nil {
			return fmt.Errorf("failed to delete folder: %w", err)
		}
		fmt.Printf("Folder %d deleted.\n", folderDeleteID)
		return nil
	}

	// Embedded mode: use the core service directly.
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	if err := service.DeleteSecret(ctx, folderDeleteID); err != nil {
		return fmt.Errorf("failed to delete folder: %w", err)
	}
	fmt.Printf("Folder %d deleted.\n", folderDeleteID)
	return nil
}
