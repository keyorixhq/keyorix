//go:build !nomigrate_gcp

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/gcpsource"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
)

var (
	gcpServer        string
	gcpKeyorixToken  string
	gcpTokenFile     string
	gcpProjectIDFlag int
	gcpEnvironmentID int
	gcpApply         bool
	gcpForce         bool
	gcpReportPath    string

	gcpGCPProjectID string
	gcpNamePrefix   string
	gcpSplitJSON    bool
)

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Import secrets from GCP Secret Manager",
	Long: `Import secrets from GCP Secret Manager into Keyorix.

  keyorix-migrate gcp --gcp-project my-gcp-project --name-prefix team-a- \
    --server https://keyorix.example.com --project 7 --environment 3

Defaults to a dry run: prints the mapping plan (source secret -> Keyorix
secret name, and create/update/skip/conflict for each) without writing
anything. Pass --apply to execute it. Before printing the plan (and again
before executing it), the Keyorix token is checked: valid, not revoked, not
expiring within the next hour, and scoped to write in the target
project/environment.

GCP credentials come from Application Default Credentials (ADC: environment,
gcloud CLI login, or the workload identity) — never from a flag. A secret
whose latest version is disabled or destroyed, or that has no versions at
all, is reported as skipped, not imported.

A secret whose value is a JSON object can be split into one Keyorix secret
per top-level key with --split-json; without it, the whole JSON string is
imported as a single secret.

Credentials (--token) can also be passed via the sibling --*-file flag (a
path, or "-" for stdin) instead of directly on the command line, which is
visible via ps/proc and shell history.`,
	SilenceUsage: true,
	RunE:         runGCP,
}

func init() {
	gcpCmd.Flags().StringVar(&gcpServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	gcpCmd.Flags().StringVar(&gcpKeyorixToken, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	gcpCmd.Flags().StringVar(&gcpTokenFile, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")
	gcpCmd.Flags().IntVar(&gcpProjectIDFlag, "project", 0, "target Keyorix project ID (required)")
	gcpCmd.Flags().IntVar(&gcpEnvironmentID, "environment", 0, "target Keyorix environment ID (required)")
	gcpCmd.Flags().BoolVar(&gcpApply, "apply", false, "execute the plan (default: dry run, print the plan only)")
	gcpCmd.Flags().BoolVar(&gcpForce, "force", false, "overwrite a conflicting secret this tool did not create (requires --apply)")
	gcpCmd.Flags().StringVar(&gcpReportPath, "report", "", "write the JSON per-item report to this path (optional)")

	gcpCmd.Flags().StringVar(&gcpGCPProjectID, "gcp-project", "", "GCP project ID to read Secret Manager from (required, or $GOOGLE_CLOUD_PROJECT)")
	gcpCmd.Flags().StringVar(&gcpNamePrefix, "name-prefix", "", "only import secrets whose name has this prefix")
	gcpCmd.Flags().BoolVar(&gcpSplitJSON, "split-json", false, "import each top-level key of a JSON-object secret as its own Keyorix secret")

	rootCmd.AddCommand(gcpCmd)
}

func runGCP(cmd *cobra.Command, _ []string) error {
	if gcpProjectIDFlag == 0 || gcpEnvironmentID == 0 {
		return fmt.Errorf("--project and --environment are both required")
	}
	if gcpForce && !gcpApply {
		return fmt.Errorf("--force requires --apply")
	}
	gcpProject := envDefault(gcpGCPProjectID, "GOOGLE_CLOUD_PROJECT")
	if gcpProject == "" {
		return fmt.Errorf("--gcp-project (or $GOOGLE_CLOUD_PROJECT) is required")
	}

	ctx := cmd.Context()

	serverURL, err := resolveServer(gcpServer)
	if err != nil {
		return err
	}
	keyorixTok, err := resolveCredential(cmd, "token", gcpKeyorixToken, gcpTokenFile, "KEYORIX_TOKEN")
	if err != nil {
		return err
	}
	if keyorixTok == "" {
		return fmt.Errorf("no token configured: use --token, --token-file, or $KEYORIX_TOKEN (a Keyorix Personal Access Token)")
	}
	apiClient, err := newAPIClient(serverURL, keyorixTok)
	if err != nil {
		return err
	}
	tgt := target.New(apiClient, gcpProjectIDFlag, gcpEnvironmentID)

	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	src := gcpsource.New(gcpsource.Config{ProjectID: gcpProject, NamePrefix: gcpNamePrefix, SplitJSON: gcpSplitJSON})
	cloudEntries, skipped, err := src.List(ctx)
	if err != nil {
		return err
	}
	if len(cloudEntries) == 0 && len(skipped) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no secrets found in this GCP project")
		return nil
	}

	skippedItems := make([]plan.Item, 0, len(skipped))
	for _, s := range skipped {
		skippedItems = append(skippedItems, plan.Item{Entry: plan.Entry{SourceKind: "gcp", Path: s.Locator}, Outcome: plan.Skip, Reason: s.Reason})
	}

	planEntries := buildCloudPlanEntries("gcp", cloudEntries, func(e cloudentry.Entry) string {
		field := e.Field
		if field == "" {
			field = "value"
		}
		return plan.SourceID("gcp-secret-manager", gcpProject, e.RawName, field)
	})

	unique, collided := splitIntraBatchNameCollisions(planEntries)
	built, err := plan.BuildPlan(ctx, tgt, unique)
	if err != nil {
		return err
	}
	items := make([]plan.Item, 0, len(skippedItems)+len(collided)+len(built))
	items = append(items, skippedItems...)
	items = append(items, collided...)
	items = append(items, built...)

	return runCloudPlan(ctx, tgt, keyorixTok, items, built, gcpApply, gcpForce, gcpReportPath)
}
