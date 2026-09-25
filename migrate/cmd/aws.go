//go:build !nomigrate_aws

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/awssource"
	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
)

var (
	awsServer        string
	awsKeyorixToken  string
	awsTokenFile     string
	awsProjectID     int
	awsEnvironmentID int
	awsApply         bool
	awsForce         bool
	awsReportPath    string

	awsRegion     string
	awsNamePrefix string
	awsSplitJSON  bool
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Import secrets from AWS Secrets Manager",
	Long: `Import secrets from AWS Secrets Manager into Keyorix.

  keyorix-migrate aws --region us-east-1 --name-prefix team-a/ \
    --server https://keyorix.example.com --project 7 --environment 3

Defaults to a dry run: prints the mapping plan (source secret -> Keyorix
secret name, and create/update/skip/conflict for each) without writing
anything. Pass --apply to execute it. Before printing the plan (and again
before executing it), the Keyorix token is checked: valid, not revoked, not
expiring within the next hour, and scoped to write in the target
project/environment.

AWS credentials come from the standard AWS chain (environment, shared
profile, EC2 instance profile, or IAM role for service accounts) — never
from a flag. --region selects which Secrets Manager region to read; when
omitted, the SDK's own default region resolution is used.

A secret whose value is a JSON object can be split into one Keyorix secret
per top-level key with --split-json; without it, the whole JSON string is
imported as a single secret.

Credentials (--token) can also be passed via the sibling --*-file flag (a
path, or "-" for stdin) instead of directly on the command line, which is
visible via ps/proc and shell history.`,
	SilenceUsage: true,
	RunE:         runAWS,
}

func init() {
	awsCmd.Flags().StringVar(&awsServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	awsCmd.Flags().StringVar(&awsKeyorixToken, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	awsCmd.Flags().StringVar(&awsTokenFile, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")
	awsCmd.Flags().IntVar(&awsProjectID, "project", 0, "target Keyorix project ID (required)")
	awsCmd.Flags().IntVar(&awsEnvironmentID, "environment", 0, "target Keyorix environment ID (required)")
	awsCmd.Flags().BoolVar(&awsApply, "apply", false, "execute the plan (default: dry run, print the plan only)")
	awsCmd.Flags().BoolVar(&awsForce, "force", false, "overwrite a conflicting secret this tool did not create (requires --apply)")
	awsCmd.Flags().StringVar(&awsReportPath, "report", "", "write the JSON per-item report to this path (optional)")

	awsCmd.Flags().StringVar(&awsRegion, "region", "", "AWS region to read Secrets Manager from (or the SDK's own default region resolution)")
	awsCmd.Flags().StringVar(&awsNamePrefix, "name-prefix", "", "only import secrets whose name has this prefix")
	awsCmd.Flags().BoolVar(&awsSplitJSON, "split-json", false, "import each top-level key of a JSON-object secret as its own Keyorix secret")

	rootCmd.AddCommand(awsCmd)
}

func runAWS(cmd *cobra.Command, _ []string) error {
	if awsProjectID == 0 || awsEnvironmentID == 0 {
		return fmt.Errorf("--project and --environment are both required")
	}
	if awsForce && !awsApply {
		return fmt.Errorf("--force requires --apply")
	}

	ctx := cmd.Context()

	serverURL, err := resolveServer(awsServer)
	if err != nil {
		return err
	}
	keyorixTok, err := resolveCredential(cmd, "token", awsKeyorixToken, awsTokenFile, "KEYORIX_TOKEN")
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
	tgt := target.New(apiClient, awsProjectID, awsEnvironmentID)

	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	region := envDefault(awsRegion, "AWS_REGION")
	src := awssource.New(awssource.Config{Region: region, NamePrefix: awsNamePrefix, SplitJSON: awsSplitJSON})
	cloudEntries, skipped, err := src.List(ctx)
	if err != nil {
		return err
	}
	if len(cloudEntries) == 0 && len(skipped) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no secrets found in AWS Secrets Manager")
		return nil
	}

	skippedItems := make([]plan.Item, 0, len(skipped))
	for _, s := range skipped {
		skippedItems = append(skippedItems, plan.Item{Entry: plan.Entry{SourceKind: "aws", Path: s.Locator}, Outcome: plan.Skip, Reason: s.Reason})
	}

	locatorRegion := region
	if locatorRegion == "" {
		locatorRegion = "default"
	}
	planEntries := buildCloudPlanEntries("aws", cloudEntries, func(e cloudentry.Entry) string {
		field := e.Field
		if field == "" {
			field = "value"
		}
		return plan.SourceID("aws-secrets-manager", locatorRegion, e.RawName, field)
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

	return runCloudPlan(ctx, tgt, keyorixTok, items, built, awsApply, awsForce, awsReportPath)
}
