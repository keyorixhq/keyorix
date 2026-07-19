// health.go — keyorix project health <name>
//
// Shows a health summary for a project: total secrets, band counts, and a
// ranked table of the highest-risk secrets.
package project

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	healthLimit  int
	healthFormat string
)

var healthCmd = &cobra.Command{
	Use:   "health <name>",
	Short: "Show the secret health summary for a project",
	Long: `Print a ranked list of the highest-risk secrets in a project together with
overall band counts (HIGH / MEDIUM / LOW).

In remote mode the project name is resolved to an ID via the list endpoint, then
GET /api/v1/projects/{id}/health is called.

Examples:
  keyorix project health my-project
  keyorix project health my-project --limit 10
  keyorix project health my-project --format json`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runHealth,
}

func init() {
	healthCmd.Flags().IntVar(&healthLimit, "limit", 20, "Maximum number of secrets to display (1-100)")
	healthCmd.Flags().StringVar(&healthFormat, "format", "table", "Output format (table, json)")
	ProjectCmd.AddCommand(healthCmd)
}

// ── Wire types (remote API response shape) ────────────────────────────────

type healthRiskFactor struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail"`
}

type healthSecretScore struct {
	SecretID   uint               `json:"secret_id"`
	SecretName string             `json:"secret_name"`
	Score      int                `json:"score"`
	Band       string             `json:"band"`
	Factors    []healthRiskFactor `json:"factors"`
}

type healthSummary struct {
	ProjectID       uint                `json:"project_id"`
	TotalSecrets    int                 `json:"total_secrets"`
	HighRiskCount   int                 `json:"high_risk_count"`
	MediumRiskCount int                 `json:"medium_risk_count"`
	LowRiskCount    int                 `json:"low_risk_count"`
	TopRiskSecrets  []healthSecretScore `json:"secrets"`
}

// ── Command runner ─────────────────────────────────────────────────────────

func runHealth(_ *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runHealthRemote(ctx, rc, name)
	}
	return runHealthEmbedded(ctx, name)
}

// ── Remote mode ────────────────────────────────────────────────────────────

func runHealthRemote(ctx context.Context, rc *common.RemoteClient, name string) error {
	// Resolve project name → ID.
	var listResp struct {
		Projects []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &listResp); err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	var projectID uint
	for _, p := range listResp.Projects {
		if strings.EqualFold(p.Name, name) {
			projectID = p.ID
			break
		}
	}
	if projectID == 0 {
		return fmt.Errorf("project %q not found", name)
	}

	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/health"
	if healthLimit != 20 {
		path += fmt.Sprintf("?limit=%d", healthLimit)
	}

	var summary healthSummary
	if err := rc.Get(ctx, path, &summary); err != nil {
		return fmt.Errorf("failed to get project health: %w", err)
	}

	return printHealth(name, &summary)
}

// ── Embedded mode ──────────────────────────────────────────────────────────

func runHealthEmbedded(ctx context.Context, name string) error {
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	projectID, err := common.LookupProjectIDByName(ctx, svc.Storage(), name)
	if err != nil {
		return err
	}

	result, err := svc.GetProjectHealthSummary(ctx, projectID, healthLimit)
	if err != nil {
		return fmt.Errorf("failed to compute project health: %w", err)
	}

	// Convert core types to display shape.
	secrets := make([]healthSecretScore, len(result.TopRiskSecrets))
	for i, rs := range result.TopRiskSecrets {
		factors := make([]healthRiskFactor, len(rs.Factors))
		for j, f := range rs.Factors {
			factors[j] = healthRiskFactor{
				Key: f.Key, Label: f.Label, Score: f.Score, Weight: f.Weight, Detail: f.Detail,
			}
		}
		secrets[i] = healthSecretScore{
			SecretID:   rs.SecretID,
			SecretName: rs.SecretName,
			Score:      rs.Score,
			Band:       rs.Band,
			Factors:    factors,
		}
	}

	summary := &healthSummary{
		ProjectID:       result.ProjectID,
		TotalSecrets:    result.TotalSecrets,
		HighRiskCount:   result.HighRiskCount,
		MediumRiskCount: result.MediumRiskCount,
		LowRiskCount:    result.LowRiskCount,
		TopRiskSecrets:  secrets,
	}
	return printHealth(name, summary)
}

// ── Display ────────────────────────────────────────────────────────────────

func printHealth(projectName string, s *healthSummary) error {
	switch healthFormat {
	case "json":
		return printHealthJSON(s)
	case "table":
		printHealthTable(projectName, s)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", healthFormat)
	}
}

func printHealthJSON(s *healthSummary) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal health summary: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

func printHealthTable(projectName string, s *healthSummary) {
	fmt.Printf("Project: %s  (%d secrets: %d HIGH · %d MEDIUM · %d LOW)\n\n",
		projectName, s.TotalSecrets, s.HighRiskCount, s.MediumRiskCount, s.LowRiskCount)

	if len(s.TopRiskSecrets) == 0 {
		fmt.Println("No secrets found.")
		return
	}

	fmt.Printf("%-30s  %5s  %-8s  %s\n", "SECRET NAME", "SCORE", "BAND", "TOP FACTOR")
	fmt.Printf("%-30s  %5s  %-8s  %s\n",
		strings.Repeat("-", 30), "-----", "--------", strings.Repeat("-", 30))

	for _, rs := range s.TopRiskSecrets {
		topFactor := topFactorDetail(rs.Factors)
		name := rs.SecretName
		if len(name) > 30 {
			name = name[:27] + "..."
		}
		fmt.Printf("%-30s  %5d  %-8s  %s\n",
			name, rs.Score, strings.ToUpper(rs.Band), topFactor)
	}
}

// topFactorDetail returns the Detail of the highest-scoring factor.
func topFactorDetail(factors []healthRiskFactor) string {
	if len(factors) == 0 {
		return ""
	}
	best := factors[0]
	for _, f := range factors[1:] {
		if f.Score > best.Score {
			best = f
		}
	}
	return best.Detail
}
