// env_clone.go — keyorix project env clone <src-env-name> <dst-env-name>
// Copies all secrets from a source environment to a destination environment
// within the same project (staging → production promotion).
package project

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var envCloneProjectFlag string

var envCloneCmd = &cobra.Command{
	Use:   "clone <src-env-name> <dst-env-name>",
	Short: "Clone all secrets from one environment to another in the same project",
	Long: `Copies every secret from the source environment into the destination environment
within the same project. Secrets that already exist by name in the destination are
skipped (not overwritten). Only the latest version of each secret is copied.`,
	Args: cobra.ExactArgs(2),
	RunE: runEnvClone,
}

func init() {
	envCloneCmd.Flags().StringVar(&envCloneProjectFlag, "project", "", descOverrideProject)
}

func runEnvClone(cmd *cobra.Command, args []string) error {
	srcName := args[0]
	dstName := args[1]

	_, projectID, err := resolveProjectContext(envCloneProjectFlag)
	if err != nil {
		return err
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runEnvCloneRemote(ctx, rc, projectID, srcName, dstName)
	}

	return runEnvCloneEmbedded(ctx, projectID, srcName, dstName)
}

func runEnvCloneRemote(ctx context.Context, rc *common.RemoteClient, projectID uint, srcName, dstName string) error {
	// Resolve environment names → IDs via the project's environment list.
	var resp struct {
		Environments []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"environments"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/environments", projectID)
	if err := rc.Get(ctx, path, &resp); err != nil {
		return fmt.Errorf("failed to list environments: %w", err)
	}

	var srcID, dstID uint
	for _, e := range resp.Environments {
		switch e.Name {
		case srcName:
			srcID = e.ID
		case dstName:
			dstID = e.ID
		}
	}
	if srcID == 0 {
		return fmt.Errorf("source environment %q not found in project", srcName)
	}
	if dstID == 0 {
		return fmt.Errorf("destination environment %q not found in project", dstName)
	}

	var result core.EnvCloneResult
	clonePath := fmt.Sprintf("/api/v1/projects/%d/environments/%d/clone", projectID, srcID)
	body := map[string]interface{}{"destination_environment_id": dstID}
	if err := rc.Post(ctx, clonePath, body, &result); err != nil {
		return fmt.Errorf("failed to clone environment: %w", err)
	}

	printCloneResult(srcName, dstName, &result)
	return nil
}

func runEnvCloneEmbedded(ctx context.Context, projectID uint, srcName, dstName string) error {
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	envs, err := svc.ListEnvironmentsByProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list environments: %w", err)
	}

	var srcID, dstID uint
	for _, e := range envs {
		switch e.Name {
		case srcName:
			srcID = e.ID
		case dstName:
			dstID = e.ID
		}
	}
	if srcID == 0 {
		return fmt.Errorf("source environment %q not found in project", srcName)
	}
	if dstID == 0 {
		return fmt.Errorf("destination environment %q not found in project", dstName)
	}

	result, err := svc.CloneEnvironment(ctx, projectID, srcID, dstID, "cli", 0)
	if err != nil {
		return fmt.Errorf("failed to clone environment: %w", err)
	}

	printCloneResult(srcName, dstName, result)
	return nil
}

func printCloneResult(srcName, dstName string, result *core.EnvCloneResult) {
	fmt.Printf("Cloned environment %q → %q\n", srcName, dstName)
	fmt.Printf("  Secrets cloned:  %d\n", result.SecretsCloned)
	if result.SecretsSkipped > 0 {
		fmt.Printf("  Secrets skipped: %d  (already exist in destination)\n", result.SecretsSkipped)
	}
}
