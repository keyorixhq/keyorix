// Package license provides `keyorix license` — offline license tooling (ADR-065, ADR-062
// Phase 2). `issue` mints a signed license token (Keyorix-internal, with the offline
// license-signing key); `install` validates and stores a token; `status` reports the
// locally-evaluated entitlement. Evaluation is fail-safe: a missing/expired/invalid license
// degrades to the community baseline, it never errors the tool or denies access.
package license

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ilicense "github.com/keyorixhq/keyorix/internal/license"
	"github.com/keyorixhq/keyorix/internal/securefiles"
	"github.com/keyorixhq/keyorix/internal/trust"
	"github.com/spf13/cobra"
)

const (
	flagDeploymentID = "deployment-id"
)

// LicenseCmd is the `keyorix license` command group.
var LicenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Offline license: issue (internal), install, and check status",
	Long: `Issue, install, and inspect Keyorix offline licenses (ADR-062 Phase 2).

A license is a compact signed token validated locally against the license public key
embedded in this binary at build time — no phone-home. Enforcement is fail-safe: a missing,
expired, or invalid license degrades to the community baseline with a warning; it never
denies access to existing secrets or stops the server.`,
}

var (
	issueLicensee   string
	issuePlan       string
	issueFeatures   string
	issueNotAfter   string
	issueDeployment string
	issueMaxSeats   int
	issueKeyID      string
	issueSignKey    string

	statusFile       string
	statusDeployment string
	statusGraceHours int

	installDest       string
	installDeployment string
	installGraceHours int
)

var issueCmd = &cobra.Command{
	Use:          "issue",
	Short:        "Mint a signed license token (Keyorix-internal; needs the offline signing key)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		notAfter, err := time.Parse(time.RFC3339, issueNotAfter)
		if err != nil {
			return fmt.Errorf("--not-after must be RFC3339: %w", err)
		}
		keyPEM, err := os.ReadFile(issueSignKey) // #nosec G304 -- operator-supplied key path
		if err != nil {
			return fmt.Errorf("read signing key: %w", err)
		}
		priv, err := ilicense.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return err
		}
		var features []string
		for _, f := range strings.Split(issueFeatures, ",") {
			if f = strings.TrimSpace(f); f != "" {
				features = append(features, f)
			}
		}
		token, err := ilicense.Issue(ilicense.License{
			Licensee:     issueLicensee,
			Plan:         issuePlan,
			Features:     features,
			IssuedAt:     time.Now().UTC(),
			NotAfter:     notAfter.UTC(),
			DeploymentID: issueDeployment,
			MaxSeats:     issueMaxSeats,
			KeyID:        issueKeyID,
		}, priv)
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	},
}

var installCmd = &cobra.Command{
	Use:          "install <token-file>",
	Short:        "Validate a license token and store it for the server to load",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		if installDest == "" {
			return fmt.Errorf("--dest is required")
		}
		token, err := readToken(args[0])
		if err != nil {
			return err
		}
		reg, err := trust.DefaultRegistry()
		if err != nil {
			return fmt.Errorf("load trusted keys: %w", err)
		}
		st := ilicense.Evaluate(token, reg, installDeployment, time.Now().UTC(), graceOf(installGraceHours))
		// Fail-safe: a degraded license still installs (so a later renewal/clock-fix can
		// activate it), but we warn loudly and never store an unparseable/forged token.
		if st.State == ilicense.StateInvalid {
			return fmt.Errorf("refusing to install an invalid license: %s", st.Reason)
		}
		// SecureWriteFileSync (#265) refuses to write through a pre-planted symlink
		// (O_NOFOLLOW) and enforces the mode even if a file already existed with a
		// looser one — a plain os.WriteFile silently follows a symlink and never
		// chmods an existing file.
		if err := securefiles.SecureWriteFileSync(filepath.Dir(installDest), filepath.Base(installDest), []byte(token+"\n"), 0o600); err != nil {
			return fmt.Errorf("write license: %w", err)
		}
		fmt.Printf("Installed license for %q (plan %s) → %s\n", st.Licensee, st.Plan, installDest)
		printStatus(st)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show the locally-evaluated license entitlement",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		var token string
		if statusFile != "" {
			t, err := readToken(statusFile)
			if err != nil {
				return err
			}
			token = t
		}
		reg, err := trust.DefaultRegistry()
		if err != nil {
			return fmt.Errorf("load trusted keys: %w", err)
		}
		st := ilicense.Evaluate(token, reg, statusDeployment, time.Now().UTC(), graceOf(statusGraceHours))
		printStatus(st)
		return nil
	},
}

func printStatus(st ilicense.Status) {
	fmt.Printf("  state:    %s\n", st.State)
	if st.Licensee != "" {
		fmt.Printf("  licensee: %s\n", st.Licensee)
	}
	if st.Plan != "" {
		fmt.Printf("  plan:     %s\n", st.Plan)
	}
	if !st.NotAfter.IsZero() {
		fmt.Printf("  expires:  %s\n", st.NotAfter.UTC().Format(time.RFC3339))
	}
	if st.Grants() && len(st.Features) > 0 {
		fmt.Printf("  features: %s\n", strings.Join(st.Features, ", "))
	} else {
		fmt.Printf("  features: (community baseline — no commercial features)\n")
	}
	if st.Reason != "" {
		fmt.Printf("  note:     %s\n", st.Reason)
	}
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied license path
	if err != nil {
		return "", fmt.Errorf("read license token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// graceOf converts a grace flag (hours) into a duration, defaulting to 14 days when unset.
func graceOf(hours int) time.Duration {
	if hours <= 0 {
		return 14 * 24 * time.Hour
	}
	return time.Duration(hours) * time.Hour
}

func init() {
	issueCmd.Flags().StringVar(&issueLicensee, "licensee", "", "licensee name (required)")
	issueCmd.Flags().StringVar(&issuePlan, "plan", "", "plan name, e.g. enterprise-airgap")
	issueCmd.Flags().StringVar(&issueFeatures, "features", "", "comma-separated commercial feature keys")
	issueCmd.Flags().StringVar(&issueNotAfter, "not-after", "", "expiry, RFC3339 (required)")
	issueCmd.Flags().StringVar(&issueDeployment, flagDeploymentID, "", "optional binding to a deployment id")
	issueCmd.Flags().IntVar(&issueMaxSeats, "max-seats", 0, "optional informational seat count")
	issueCmd.Flags().StringVar(&issueKeyID, "key-id", "", "license signing key-id (required)")
	issueCmd.Flags().StringVar(&issueSignKey, "sign-key", "", "PKCS#8 PEM ed25519 license signing key (required; keep offline)")
	_ = issueCmd.MarkFlagRequired("licensee")
	_ = issueCmd.MarkFlagRequired("not-after")
	_ = issueCmd.MarkFlagRequired("key-id")
	_ = issueCmd.MarkFlagRequired("sign-key")

	installCmd.Flags().StringVar(&installDest, "dest", "", "path to store the validated license token (required)")
	installCmd.Flags().StringVar(&installDeployment, flagDeploymentID, "", "this deployment's id, to check a bound license")
	installCmd.Flags().IntVar(&installGraceHours, "grace-hours", 0, "post-expiry grace window in hours (default 336 = 14d)")
	_ = installCmd.MarkFlagRequired("dest")

	statusCmd.Flags().StringVar(&statusFile, "license", "", "license token file to evaluate")
	statusCmd.Flags().StringVar(&statusDeployment, flagDeploymentID, "", "this deployment's id, to check a bound license")
	statusCmd.Flags().IntVar(&statusGraceHours, "grace-hours", 0, "post-expiry grace window in hours (default 336 = 14d)")

	LicenseCmd.AddCommand(issueCmd)
	LicenseCmd.AddCommand(installCmd)
	LicenseCmd.AddCommand(statusCmd)
}
