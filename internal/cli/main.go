package cli

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/accessreview"
	"github.com/keyorixhq/keyorix/internal/cli/anomalies"
	"github.com/keyorixhq/keyorix/internal/cli/audit"
	"github.com/keyorixhq/keyorix/internal/cli/auth"
	"github.com/keyorixhq/keyorix/internal/cli/breakglass"
	bundlecli "github.com/keyorixhq/keyorix/internal/cli/bundle"
	"github.com/keyorixhq/keyorix/internal/cli/compliance"
	cliconfigcmd "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/cli/connect"
	"github.com/keyorixhq/keyorix/internal/cli/dynamic"
	"github.com/keyorixhq/keyorix/internal/cli/encryption"
	"github.com/keyorixhq/keyorix/internal/cli/group"
	"github.com/keyorixhq/keyorix/internal/cli/hygiene"
	"github.com/keyorixhq/keyorix/internal/cli/invite"
	"github.com/keyorixhq/keyorix/internal/cli/legalhold"
	licensecli "github.com/keyorixhq/keyorix/internal/cli/license"
	"github.com/keyorixhq/keyorix/internal/cli/machine"
	"github.com/keyorixhq/keyorix/internal/cli/migrate"
	"github.com/keyorixhq/keyorix/internal/cli/pat"
	"github.com/keyorixhq/keyorix/internal/cli/project"
	"github.com/keyorixhq/keyorix/internal/cli/rbac"
	"github.com/keyorixhq/keyorix/internal/cli/request"
	"github.com/keyorixhq/keyorix/internal/cli/risk"
	"github.com/keyorixhq/keyorix/internal/cli/rotation"
	"github.com/keyorixhq/keyorix/internal/cli/run"
	"github.com/keyorixhq/keyorix/internal/cli/secret"
	"github.com/keyorixhq/keyorix/internal/cli/share"
	sodcli "github.com/keyorixhq/keyorix/internal/cli/sod"
	"github.com/keyorixhq/keyorix/internal/cli/status"
	"github.com/keyorixhq/keyorix/internal/cli/system"
	trustcli "github.com/keyorixhq/keyorix/internal/cli/trust"
	"github.com/keyorixhq/keyorix/internal/cli/user"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/spf13/cobra"
)

var version = "dev" // overwritten via ldflags at build time

var rootCmd = &cobra.Command{
	Use:     "keyorix",
	Short:   "Keyorix - A secure secret management tool",
	Long:    `Keyorix is a tool for securely storing, managing, and sharing secrets.`,
	Version: version,
}

func init() {
	// Add all available commands
	rootCmd.AddCommand(run.RunCmd)
	rootCmd.AddCommand(secret.SecretCmd)
	rootCmd.AddCommand(project.ProjectCmd)
	rootCmd.AddCommand(machine.MachineCmd)
	rootCmd.AddCommand(migrate.MigrateCmd)
	rootCmd.AddCommand(user.UserCmd)
	rootCmd.AddCommand(group.GroupCmd)
	rootCmd.AddCommand(invite.InviteCmd)
	rootCmd.AddCommand(legalhold.LegalHoldCmd)
	rootCmd.AddCommand(risk.RiskCmd)
	rootCmd.AddCommand(request.RequestCmd)
	rootCmd.AddCommand(share.ShareCmd)
	rootCmd.AddCommand(auth.AuthCmd)
	rootCmd.AddCommand(cliconfigcmd.ConfigCmd)
	rootCmd.AddCommand(connect.ConnectCmd)
	rootCmd.AddCommand(encryption.EncryptionCmd)
	rootCmd.AddCommand(rbac.RbacCmd)
	rootCmd.AddCommand(status.StatusCmd)
	rootCmd.AddCommand(system.SystemCmd)
	rootCmd.AddCommand(anomalies.AnomaliesCmd)
	rootCmd.AddCommand(dynamic.DynamicSecretCmd)
	rootCmd.AddCommand(pat.PATCmd)
	rootCmd.AddCommand(audit.AuditCmd)
	rootCmd.AddCommand(rotation.RotationCmd)
	rootCmd.AddCommand(accessreview.AccessReviewCmd)
	rootCmd.AddCommand(breakglass.BreakGlassCmd)
	rootCmd.AddCommand(compliance.ComplianceCmd)
	rootCmd.AddCommand(sodcli.SoDCmd)
	rootCmd.AddCommand(hygiene.HygieneCmd)
	rootCmd.AddCommand(trustcli.TrustCmd)
	rootCmd.AddCommand(bundlecli.BundleCmd)
	rootCmd.AddCommand(licensecli.LicenseCmd)
}

// bootstrapI18n initializes i18n with the user's actual configured locale
// (keyorix.yaml's locale.language), not a hardcoded English default.
// i18n.Initialize is guarded by a process-wide sync.Once, so whichever call
// reaches it FIRST wins for the life of the process — this bootstrap call
// must therefore carry the real config up front, or every subcommand's
// later, correctly-configured call (common.InitializeCoreService ->
// i18n.Initialize(cfg)) becomes a silent no-op and the CLI can never honor a
// non-English locale setting. Falls back to English only when no config file
// can be loaded (e.g. first run, or a command that never touches storage),
// mirroring common.InitializeCoreService's own no-config fallback.
func bootstrapI18n() error {
	cfg, err := config.Load("")
	if err != nil {
		cfg = &config.Config{
			Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		}
	}
	return i18n.Initialize(cfg)
}

// Execute runs the root command
func Execute() {
	if err := bootstrapI18n(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize i18n: %v\n", err)
		// Continue anyway - don't fail completely
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
