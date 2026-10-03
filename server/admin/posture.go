package admin

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/startup"
)

// postureFlag is `admin validate --posture` — reports every ADR-112 secure-
// baseline deviation and exits non-zero if any is found, instead of running
// the ordinary config/permissions/encryption/database validation above.
var postureFlag bool

func init() {
	validateCmd.Flags().BoolVar(&postureFlag, "posture", false, "Report every ADR-112 secure-baseline deviation and exit non-zero if any is found, instead of the ordinary validation")
}

// needsAndreiMarker is the exact substring this session's own item-2 registry
// entries use (internal/config/insecure_settings_registry.go) to flag a
// setting whose insecure_ rename was ambiguous and deferred rather than
// guessed. Those entries carry no DeprecatedAlias and exist only so a future
// decision has somewhere to land — counting them as a posture deviation here
// would make a shipped production template non-zero through no fault of its
// own. Detecting them by this marker, not a hand-maintained name list, means
// a future NEEDS ANDREI entry added to the registry is automatically excluded
// without this file needing a matching edit.
const needsAndreiMarker = "NEEDS ANDREI"

// postureDeviation is one line of `admin validate --posture` output: a
// concrete, named reason the install does not match the ADR-112 secure
// baseline. Every non-informational deviation counts toward the command's
// exit code.
type postureDeviation struct {
	category string
	detail   string
}

// postureReport is the full output of one `admin validate --posture` run.
type postureReport struct {
	deviations    []postureDeviation
	informational []string
}

func (r *postureReport) deviate(category, detail string) {
	r.deviations = append(r.deviations, postureDeviation{category: category, detail: detail})
}

func (r *postureReport) info(line string) {
	r.informational = append(r.informational, line)
}

func runAdminValidatePosture(cfg *config.Config) error {
	report := &postureReport{}

	collectInsecureSettingsPosture(cfg, report)
	collectFilePermissionPosture(cfg, report)
	collectKeyFileSetPosture(cfg, report)
	collectTLSPosture(cfg, report)
	collectKEKAgePosture(cfg, report)

	if err := withUsableStorage(cfg, func(store corestorage.Storage) error {
		coreService := core.NewKeyorixCore(store)
		ctx := context.Background()
		if err := collectAdminMFAPosture(ctx, cfg, coreService, report); err != nil {
			return err
		}
		return collectBreakGlassReviewPosture(ctx, cfg, coreService, report)
	}); err != nil {
		return fmt.Errorf("posture check could not query the database: %w", err)
	}

	printPostureReport(report)

	if len(report.deviations) > 0 {
		return fmt.Errorf("%d secure-baseline deviation(s) found", len(report.deviations))
	}
	return nil
}

// collectInsecureSettingsPosture reports every item-2 registry entry
// currently in effect, excluding NEEDS ANDREI entries (informational/pending
// instead — see needsAndreiMarker).
func collectInsecureSettingsPosture(cfg *config.Config, report *postureReport) {
	for _, s := range config.InsecureSettingsRegistry {
		if !s.InEffect(cfg) {
			continue
		}
		if strings.Contains(s.Describe, needsAndreiMarker) {
			report.info(fmt.Sprintf("pending decision (not counted): %s is in effect — %s", s.Name, s.Describe))
			continue
		}
		report.deviate("insecure-setting", fmt.Sprintf("%s is in effect — %s", s.Name, s.Describe))
	}
}

// collectFilePermissionPosture reports the secure-baseline file-permission
// deviations: the check turned off outright (always an explicit choice — the
// ADR-112 default never resolves to false, see config.Load), and a real
// on-disk permission/encryption/database problem ValidateStartup finds. The
// grace-period case (ImplicitDefault true, relying on the new secure default
// without having explicitly reviewed it, AND a real problem exists) is
// reported as its own deviation category so an operator sees both "there is a
// real problem" and "the grace period covering it is not yet closed out" --
// server/main.go's runStartupValidation/enforceKeyFilePermissions soften this
// exact case from a boot-time failure into a warning, so this command, not
// the boot path, is where it must surface as something that needs fixing.
func collectFilePermissionPosture(cfg *config.Config, report *postureReport) {
	if !cfg.Security.EnableFilePermissionCheck {
		report.deviate("file-permissions", "security.enable_file_permission_check is disabled (ADR-112 requires it enabled by default)")
		return
	}
	if cfg.Security.EnableFilePermissionCheckImplicitDefault {
		report.info("security.enable_file_permission_check is enforcing via its new secure-by-default value (grace period) — relies on the implicit default, never set explicitly")
	}

	configPath := config.ResolvedPath("")
	result, err := startup.ValidateStartup(configPath, false)
	if result == nil {
		report.deviate("file-permissions", fmt.Sprintf("could not run startup validation: %v", err))
		return
	}
	if !result.PermissionsOK {
		report.deviate("file-permissions", fmt.Sprintf("file permission validation failed: %v", err))
		if cfg.Security.EnableFilePermissionCheckImplicitDefault {
			report.deviate("grace-period", "security.enable_file_permission_check's grace period is not yet complied with — the file-permissions deviation above would hard-fail startup once the setting is reviewed and set explicitly")
		}
		return
	}
	if !result.EncryptionOK {
		report.deviate("startup-validation", fmt.Sprintf("encryption validation failed: %v", err))
		return
	}
	if !result.DatabaseOK {
		report.deviate("startup-validation", fmt.Sprintf("database validation failed: %v", err))
	}
}

// collectKeyFileSetPosture reports item 6's boot-time key-file-set
// consistency check as a deviation when it would refuse to boot.
func collectKeyFileSetPosture(cfg *config.Config, report *postureReport) {
	if !cfg.Storage.Encryption.Enabled {
		return
	}
	if err := keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, "."); err != nil {
		report.deviate("key-file-set-consistency", err.Error())
	}
}

// collectTLSPosture mirrors checkTransportTLSPosture's own boot-time
// judgment call exactly, rather than tightening it: a cleartext-serving
// listener is a deviation only when security.require_transport_tls is set
// but TLS is nonetheless disabled (a contradiction checkTransportTLSPosture
// already refuses to boot over, so this is unreachable for a running
// install — kept here for defense in depth). Cleartext with
// require_transport_tls left false is informational only, same as the boot
// path's own warning: server/config/production.yaml deliberately ships this
// shape (TLS terminated by a fronting reverse proxy), and a deployment
// making that documented, deliberate choice is not a secure-baseline
// deviation. TLS mode itself (default vs strict) is informational only:
// ADR-112's recorded decision keeps TLS 1.2 compliant, so neither mode is,
// by itself, a deviation.
func collectTLSPosture(cfg *config.Config, report *postureReport) {
	check := func(name string, inst config.ServerInstanceConfig) {
		if !inst.Enabled {
			return
		}
		mode := inst.TLSMode
		if mode == "" {
			mode = "default (TLS 1.2 floor, forward-secret AEAD)"
		}
		report.info(fmt.Sprintf("%s tls_mode: %s", name, mode))
		if inst.TLS.Enabled {
			return
		}
		if cfg.Security.RequireTransportTLS {
			report.deviate("tls", fmt.Sprintf("%s listener has no TLS but security.require_transport_tls is set", name))
			return
		}
		report.info(fmt.Sprintf("%s listener is serving cleartext (no TLS) — acceptable only if a TLS-terminating reverse proxy fronts it; set security.require_transport_tls to fail closed if not", name))
	}
	check("HTTP", cfg.Server.HTTP)
	check("gRPC", cfg.Server.GRPC)
}

// collectKEKAgePosture reports the KEK salt file's age, informationally only
// -- no rotation-age threshold exists anywhere in this codebase or ADR-112
// itself, and scheduled KEK rotation is explicitly out of scope for this
// work; inventing a threshold here would be a guess, not a derived fact.
func collectKEKAgePosture(cfg *config.Config, report *postureReport) {
	if !cfg.Storage.Encryption.Enabled || cfg.Storage.Encryption.SaltPath == "" {
		return
	}
	info, err := os.Stat(cfg.Storage.Encryption.SaltPath)
	if err != nil {
		return // key-file-set-consistency above already reports a missing/partial set
	}
	age := time.Since(info.ModTime()).Round(time.Hour)
	report.info(fmt.Sprintf("KEK salt file age: %s (no rotation-age threshold is defined — informational only)", age))
}

// collectAdminMFAPosture reports every active global admin-tier holder with
// no second factor enrolled (item 1's require_mfa grace period, finally made
// visible as a concrete, named list rather than a boot-time warning with no
// way to see who still needs to comply).
func collectAdminMFAPosture(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore, report *postureReport) error {
	admins, err := coreService.ListAdminsWithoutMFA(ctx)
	if err != nil {
		return fmt.Errorf("failed to list admins without MFA: %w", err)
	}
	if len(admins) == 0 {
		return nil
	}
	names := make([]string, 0, len(admins))
	for _, u := range admins {
		names = append(names, fmt.Sprintf("%s (%s)", u.Username, u.Email))
	}
	report.deviate("admin-mfa", fmt.Sprintf("%d admin(s) without MFA or a passkey enrolled: %s", len(admins), strings.Join(names, ", ")))
	if cfg.Security.RequireMFAImplicitDefault {
		report.deviate("grace-period", "security.require_mfa's grace period is not yet complied with — the admin-mfa deviation above lists who still needs to enrol")
	}
	return nil
}

// collectBreakGlassReviewPosture reports every break-glass activation older
// than break_glass.review_window that has never received a post-hoc review
// (item 5).
func collectBreakGlassReviewPosture(ctx context.Context, cfg *config.Config, coreService *core.KeyorixCore, report *postureReport) error {
	unreviewed, err := coreService.ListUnreviewedBreakGlassActivations(ctx, cfg.BreakGlass.GetReviewWindow())
	if err != nil {
		return fmt.Errorf("failed to list unreviewed break-glass activations: %w", err)
	}
	if len(unreviewed) == 0 {
		return nil
	}
	ids := make([]string, 0, len(unreviewed))
	for _, a := range unreviewed {
		ids = append(ids, fmt.Sprintf("#%d (project %d, activated %s)", a.ID, a.ProjectID, a.CreatedAt.Format(time.RFC3339)))
	}
	report.deviate("break-glass-review", fmt.Sprintf("%d break-glass activation(s) older than %s with no review: %s", len(unreviewed), cfg.BreakGlass.GetReviewWindow(), strings.Join(ids, ", ")))
	return nil
}

func printPostureReport(report *postureReport) {
	fmt.Println("ADR-112 Secure Baseline Posture")
	fmt.Println("===============================")
	if len(report.deviations) == 0 {
		fmt.Println("No deviations found.")
	} else {
		fmt.Printf("%d deviation(s) found:\n", len(report.deviations))
		for _, d := range report.deviations {
			fmt.Printf("  [%s] %s\n", d.category, d.detail)
		}
	}
	if len(report.informational) > 0 {
		fmt.Println("\nInformational (not counted toward the exit code):")
		for _, line := range report.informational {
			fmt.Printf("  - %s\n", line)
		}
	}
}
