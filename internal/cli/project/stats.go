// stats.go — keyorix project stats <name>
//
// Shows rich per-project statistics: secret counts, rotation health, access
// metrics, and a classification breakdown.
package project

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var statsFormat string

var statsCmd = &cobra.Command{
	Use:   "stats <name>",
	Short: "Show rich statistics for a project",
	Long: `Print per-project statistics: secret counts, rotation health, unique
accessors, open anomalies, and a classification breakdown.

In remote mode the project name is resolved to an ID via the list endpoint,
then GET /api/v1/projects/{id}/stats is called.

Examples:
  keyorix project stats my-project
  keyorix project stats my-project --format json`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runStats,
}

func init() {
	statsCmd.Flags().StringVar(&statsFormat, "format", "table", "Output format (table, json)")
}

// ── Wire types (remote API response shape) ─────────────────────────────────

type projectStats struct {
	ProjectID   uint   `json:"project_id"`
	ProjectName string `json:"project_name"`

	TotalSecrets     int `json:"total_secrets"`
	ActiveSecrets    int `json:"active_secrets"`
	ExpiredSecrets   int `json:"expired_secrets"`
	ExpiringIn30Days int `json:"expiring_in_30_days"`

	RotationEnabled int        `json:"rotation_enabled"`
	OverdueRotation int        `json:"overdue_rotation"`
	LastRotationAt  *time.Time `json:"last_rotation_at,omitempty"`

	UniqueAccessors int `json:"unique_accessors"`
	OpenAnomalies   int `json:"open_anomalies"`

	ClassificationCounts map[string]int `json:"classification_counts"`

	ComputedAt time.Time `json:"computed_at"`
}

// ── Command runner ──────────────────────────────────────────────────────────

func runStats(_ *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runStatsRemote(ctx, rc, name)
	}
	return runStatsEmbedded(ctx, name)
}

// ── Remote mode ─────────────────────────────────────────────────────────────

func runStatsRemote(ctx context.Context, rc *common.RemoteClient, name string) error {
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

	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/stats"
	var stats projectStats
	if err := rc.Get(ctx, path, &stats); err != nil {
		return fmt.Errorf("failed to get project stats: %w", err)
	}

	return printStats(name, &stats)
}

// ── Embedded mode ───────────────────────────────────────────────────────────

func runStatsEmbedded(ctx context.Context, name string) error {
	svc, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	projectID, err := common.LookupProjectIDByName(ctx, svc.Storage(), name)
	if err != nil {
		return err
	}

	result, err := svc.GetProjectStats(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to compute project stats: %w", err)
	}

	// Convert core type to display shape (same JSON tags, safe to copy field by field).
	stats := &projectStats{
		ProjectID:            result.ProjectID,
		ProjectName:          result.ProjectName,
		TotalSecrets:         result.TotalSecrets,
		ActiveSecrets:        result.ActiveSecrets,
		ExpiredSecrets:       result.ExpiredSecrets,
		ExpiringIn30Days:     result.ExpiringIn30Days,
		RotationEnabled:      result.RotationEnabled,
		OverdueRotation:      result.OverdueRotation,
		LastRotationAt:       result.LastRotationAt,
		UniqueAccessors:      result.UniqueAccessors,
		OpenAnomalies:        result.OpenAnomalies,
		ClassificationCounts: result.ClassificationCounts,
		ComputedAt:           result.ComputedAt,
	}
	return printStats(name, stats)
}

// ── Display ─────────────────────────────────────────────────────────────────

func printStats(projectName string, s *projectStats) error {
	switch statsFormat {
	case "json":
		return printStatsJSON(s)
	case "table":
		printStatsTable(projectName, s)
		return nil
	default:
		return fmt.Errorf("unsupported format: %s (use 'table' or 'json')", statsFormat)
	}
}

func printStatsJSON(s *projectStats) error {
	b, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal stats: %w", err)
	}
	fmt.Println(string(b))
	return nil
}

func printStatsTable(projectName string, s *projectStats) {
	fmt.Printf("Project: %s\n\n", projectName)

	fmt.Println("Secrets")
	fmt.Printf("  %-22s %d\n", "Total:", s.TotalSecrets)
	fmt.Printf("  %-22s %d\n", "Active:", s.ActiveSecrets)
	fmt.Printf("  %-22s %d\n", "Expired:", s.ExpiredSecrets)
	fmt.Printf("  %-22s %d\n", "Expiring (30d):", s.ExpiringIn30Days)
	fmt.Println()

	fmt.Println("Rotation")
	fmt.Printf("  %-22s %d\n", "With config:", s.RotationEnabled)
	fmt.Printf("  %-22s %d\n", "Overdue:", s.OverdueRotation)
	lastRot := "never"
	if s.LastRotationAt != nil {
		lastRot = s.LastRotationAt.Format("2006-01-02")
	}
	fmt.Printf("  %-22s %s\n", "Last rotation:", lastRot)
	fmt.Println()

	fmt.Println("Access")
	fmt.Printf("  %-22s %d\n", "Unique accessors:", s.UniqueAccessors)
	fmt.Printf("  %-22s %d\n", "Open anomalies:", s.OpenAnomalies)
	fmt.Println()

	if len(s.ClassificationCounts) > 0 {
		fmt.Println("Classification")
		// Sort keys for deterministic output.
		keys := make([]string, 0, len(s.ClassificationCounts))
		for k := range s.ClassificationCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-22s %d\n", k+":", s.ClassificationCounts[k])
		}
	}
}
