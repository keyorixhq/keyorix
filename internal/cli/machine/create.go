package machine

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	createProjectName    string
	createName           string
	createType           string
	createDescription    string
	createClassification string
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a machine identity in a project",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createProjectName, "project", "", "Project name (defaults to the active project)")
	createCmd.Flags().StringVar(&createName, "name", "", "Machine identity name (required)")
	createCmd.Flags().StringVar(&createType, "type", "other", "Identity type: ci | k8s | service | automation | other")
	createCmd.Flags().StringVar(&createDescription, "description", "", "Description")
	createCmd.Flags().StringVar(&createClassification, "classification", "", "Data classification: public | internal | confidential | restricted")
}

func runCreate(cmd *cobra.Command, args []string) error {
	if createName == "" {
		return fmt.Errorf("--name is required")
	}
	ctx := context.Background()
	_, projectID, err := resolveProjectContext(createProjectName)
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		body := map[string]interface{}{
			"name":           createName,
			"identity_type":  createType,
			"description":    createDescription,
			"classification": createClassification,
		}
		var resp struct {
			MachineIdentity models.MachineIdentity `json:"machine_identity"`
		}
		path := fmt.Sprintf("/api/v1/projects/%d/machine-identities", projectID)
		if err := rc.Post(ctx, path, body, &resp); err != nil {
			return fmt.Errorf("failed to create machine identity: %w", err)
		}
		fmt.Printf("Machine identity created: id=%d name=%q type=%s state=%s\n",
			resp.MachineIdentity.ID, resp.MachineIdentity.Name, resp.MachineIdentity.IdentityType, resp.MachineIdentity.State)
		return nil
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	// #G67: operator-asserted actor (KEYORIX_CLI_ACTOR), not a hardcoded placeholder.
	m, err := svc.CreateMachineIdentity(ctx, projectID, createName, createType, createDescription, createClassification, common.ResolveActorID())
	if err != nil {
		return fmt.Errorf("failed to create machine identity: %w", err)
	}
	fmt.Printf("Machine identity created: id=%d name=%q type=%s state=%s\n", m.ID, m.Name, m.IdentityType, m.State)
	return nil
}
