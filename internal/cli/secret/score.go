// score.go — keyorix secret score <name>
//
// Shows the risk score for a named secret. In remote mode it resolves the name
// to an ID via the list endpoint, then calls GET /api/v1/secrets/{id}/risk. In
// embedded mode it calls coreService.ComputeSecretRiskScore directly.
package secret

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/spf13/cobra"
)

var (
	scoreProject string
	scoreEnv     uint
)

// coreServiceInit is the factory used by runScoreEmbedded to obtain a core
// service instance. It is a package-level variable so tests can swap it out to
// inject a mock that triggers specific error paths.
var coreServiceInit = common.InitializeCoreService

var scoreCmd = &cobra.Command{
	Use:   "score <name>",
	Short: "Show the risk score for a secret",
	Long: `Print the composite risk score for a named secret.

The score is 0-100 (higher = riskier) and is broken down into four weighted
factors: rotation age (30%), expiry (30%), usage (20%), and exposure (20%).

In remote mode the secret name is resolved to an ID via the list endpoint, then
GET /api/v1/secrets/{id}/risk is called.

Examples:
  keyorix secret score my-api-key
  keyorix secret score my-api-key --project web
  keyorix secret score my-api-key --project web --env 2`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runScore,
}

func init() {
	scoreCmd.Flags().StringVar(&scoreProject, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
	scoreCmd.Flags().UintVar(&scoreEnv, "env", 0, "Environment ID filter (optional)")
	SecretCmd.AddCommand(scoreCmd)
}

func runScore(_ *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runScoreRemote(ctx, rc, name)
	}
	return runScoreEmbedded(ctx, name)
}

// ── Remote mode ────────────────────────────────────────────────────────────

// scoreRiskFactor is the wire shape of one risk factor returned by the API.
type scoreRiskFactor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

// scoreRiskResult is the wire shape of the GET /api/v1/secrets/{id}/risk response.
type scoreRiskResult struct {
	SecretID   uint              `json:"secret_id"`
	SecretName string            `json:"secret_name"`
	Score      int               `json:"score"`
	Band       string            `json:"band"`
	Factors    []scoreRiskFactor `json:"factors"`
	Degraded   bool              `json:"degraded"`
}

func runScoreRemote(ctx context.Context, rc *common.RemoteClient, name string) error {
	// 1. Resolve name → ID via list endpoint.
	secretID, err := resolveSecretIDByName(ctx, rc, name)
	if err != nil {
		return err
	}

	// 2. Fetch the risk score.
	var result scoreRiskResult
	path := fmt.Sprintf("/api/v1/secrets/%d/risk", secretID)
	if err := rc.Get(ctx, path, &result); err != nil {
		return fmt.Errorf("failed to get risk score: %w", err)
	}

	printRiskScore(result.SecretName, result.Score, result.Band, result.Factors, result.Degraded)
	return nil
}

// resolveSecretIDByName finds the ID of a secret by its name via the list endpoint.
func resolveSecretIDByName(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	path := "/api/v1/secrets?page=1&page_size=500"

	projectName, _ := common.ResolveProject(scoreProject)
	if projectName != "" {
		param, err := resolveProjectIDParam(ctx, rc, projectName)
		if err != nil {
			return 0, err
		}
		path += param
	}
	if scoreEnv != 0 {
		path += fmt.Sprintf("&environment_id=%d", scoreEnv)
	}

	// The list endpoint returns SecretWithSharingInfo whose SecretNode fields are
	// PascalCase JSON (same as GET /api/v1/secrets/{id}).
	var resp struct {
		Secrets []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"secrets"`
	}
	if err := rc.Get(ctx, path, &resp); err != nil {
		return 0, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, s := range resp.Secrets {
		if strings.EqualFold(s.Name, name) {
			return s.ID, nil
		}
	}
	return 0, fmt.Errorf("secret %q not found", name)
}

// ── Embedded mode ──────────────────────────────────────────────────────────

func runScoreEmbedded(ctx context.Context, name string) error {
	svc, err := coreServiceInit()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	filter := &coreStorage.SecretFilter{
		Page:     1,
		PageSize: 500,
	}
	projectName, _ := common.ResolveProject(scoreProject)
	if projectName != "" {
		projectID, err := common.LookupProjectIDByName(ctx, svc.Storage(), projectName)
		if err != nil {
			return err
		}
		filter.ProjectID = &projectID
	}
	if scoreEnv != 0 {
		filter.EnvironmentID = &scoreEnv
	}

	secrets, _, err := svc.ListSecrets(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	var secretID uint
	for _, s := range secrets {
		if strings.EqualFold(s.Name, name) {
			secretID = s.ID
			break
		}
	}
	if secretID == 0 {
		return fmt.Errorf("secret %q not found", name)
	}

	rs, err := svc.ComputeSecretRiskScore(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to compute risk score: %w", err)
	}

	// Convert core types to the display shape.
	factors := make([]scoreRiskFactor, len(rs.Factors))
	for i, f := range rs.Factors {
		factors[i] = scoreRiskFactor{
			Key:    f.Key,
			Label:  f.Label,
			Score:  f.Score,
			Weight: f.Weight,
			Detail: f.Detail,
		}
	}
	printRiskScore(rs.SecretName, rs.Score, rs.Band, factors, rs.Degraded)
	return nil
}

// ── Display ────────────────────────────────────────────────────────────────

func printRiskScore(secretName string, score int, band string, factors []scoreRiskFactor, degraded bool) {
	fmt.Printf("Secret: %s\n", secretName)
	fmt.Printf("Score:  %d/100  band: %s\n", score, strings.ToUpper(band))
	if degraded {
		fmt.Println("  (exposure data incomplete — score is a lower bound)")
	}
	fmt.Println()
	fmt.Println("Factors:")
	for _, f := range factors {
		fmt.Printf("  %-14s score=%-3d  weight=%-4s  detail=%s\n",
			f.Key, f.Score, fmt.Sprintf("%.0f%%", f.Weight*100), f.Detail)
	}

	if strings.EqualFold(band, "high") {
		fmt.Fprintln(os.Stderr, "⚠ This secret is HIGH risk. Consider rotating or restricting access.")
	}
}
