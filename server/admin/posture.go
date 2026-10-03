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

// deviationOrigin says WHY a deviation is present, so an operator can tell
// "this install has not been hardened yet" from "someone turned this off".
// It changes how a deviation READS, never whether it counts: both values are
// counted toward the exit code. Keeping the distinction in the output rather
// than in the exit code is the whole correction to this report's first shape,
// which excluded a class of settings from counting at all.
type deviationOrigin string

const (
	// originExplicit: the config file asked for this state.
	originExplicit deviationOrigin = "explicit"
	// originShippedDefault: the weak state is what a config file that says
	// nothing gets. Still a deviation from the secure baseline -- the fix is to
	// change the default, not to stop reporting it.
	originShippedDefault deviationOrigin = "shipped-default"
)

// postureDeviation is one line of `admin validate --posture` output: a
// concrete, named reason the install does not match the ADR-112 secure
// baseline. EVERY deviation counts toward the command's exit code; only
// report.info lines do not.
type postureDeviation struct {
	category string
	detail   string
	origin   deviationOrigin
}

// postureReport is the full output of one `admin validate --posture` run.
type postureReport struct {
	deviations    []postureDeviation
	informational []string
}

// deviate records a deviation whose cause is an explicit config choice.
func (r *postureReport) deviate(category, detail string) {
	r.deviations = append(r.deviations, postureDeviation{category: category, detail: detail, origin: originExplicit})
}

// deviateShippedDefault records a deviation the install gets without asking
// for it. Counted identically to deviate -- see deviationOrigin.
func (r *postureReport) deviateShippedDefault(category, detail string) {
	r.deviations = append(r.deviations, postureDeviation{category: category, detail: detail, origin: originShippedDefault})
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
		// TODO(#2461): add collectBreakGlassReviewPosture here -- see its
		// comment below for the two findings Andrei decided on and why they
		// cannot be implemented until that PR's API lands.
		return collectAdminMFAPosture(ctx, cfg, coreService, report)
	}); err != nil {
		return fmt.Errorf("posture check could not query the database: %w", err)
	}

	printPostureReport(report)

	if len(report.deviations) > 0 {
		return fmt.Errorf("%d secure-baseline deviation(s) found", len(report.deviations))
	}
	return nil
}

// collectInsecureSettingsPosture reports EVERY item-2 registry entry currently
// in effect as a deviation. No entry is excluded, and nothing about how a
// setting is NAMED affects whether it counts.
//
// The first shape of this function skipped any entry whose Describe contained
// the substring "NEEDS ANDREI" -- the marker the registry uses for a setting
// whose insecure_ rename needs a product decision -- and recorded it as
// uncounted informational instead. That was wrong in two separate ways, and
// the coordinator's review of this PR caught both:
//
//  1. It defeated the report. The marker covered THIRTEEN entries, including
//     encryption-at-rest disabled, database TLS disabled (ssl_mode=disable), a
//     forgeable Shamir KEK commitment, unauthenticated /metrics and
//     log-delivered setup links. An install with encryption at rest switched
//     off printed "No deviations found." and exited 0, and nothing else caught
//     it: collectKeyFileSetPosture early-returns when encryption is off, for
//     the good reason that there is then no key material to check. A report
//     whose one job is answering "does this install match the secure baseline"
//     answered yes for an install storing every secret in plaintext.
//
//  2. The mechanism was unsound regardless of which entries it hit. Keying
//     security control flow on a prose match against a human-readable
//     description string means any future entry whose Describe happens to
//     contain that phrase silently stops counting -- a reviewer editing a
//     sentence could switch off a deviation without touching a line of logic.
//
// The review suggested scoping the exclusion to the defensible shipped-template
// cases via an explicit per-entry registry field. Andrei's instruction is
// stronger, and is what is implemented: every insecure setting counts as a
// deviation, whether or not its naming is settled. So there is no exclusion
// field to key on, and no way to add one by accident.
//
// What a shipped template needs is honesty about WHY, not an exemption, so the
// origin distinction does that job instead: a weakening that is simply the
// current default reads as "shipped-default" and still counts. If a shipped
// config template exits non-zero here, the install genuinely does not match
// the secure baseline, and the fix is to change the default (which is what the
// rest of ADR-112 is for) rather than to stop reporting it.
func collectInsecureSettingsPosture(cfg *config.Config, report *postureReport) {
	for _, s := range config.InsecureSettingsRegistry {
		if !s.InEffect(cfg) {
			continue
		}
		detail := fmt.Sprintf("%s is in effect — %s", s.Name, s.Describe)
		// An entry still awaiting its rename decision is, today, derived from a
		// key whose weak state is what a config file that says nothing gets.
		// That makes it a shipped default, not an explicit choice -- a real
		// distinction worth showing, and the only thing the old marker was
		// right about.
		if s.DeprecatedAlias == "" && strings.Contains(s.Describe, "NEEDS ANDREI") {
			report.deviateShippedDefault("insecure-setting", detail)
			continue
		}
		report.deviate("insecure-setting", detail)
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

	// All three checks are reported, with no early return between them
	// (coordinator review, secondary finding). ValidateStartup stops at its
	// FIRST failure, so a failed permission check leaves EncryptionOK and
	// DatabaseOK false simply because they were never evaluated -- and the old
	// shape returned after the first one, so an install with a permission
	// problem got a report that said nothing about its encryption or database
	// at all. Reporting all three means a reader is never silently missing a
	// section; validationDetail is what keeps an unevaluated check from being
	// reported as a failure.
	for _, c := range []struct {
		ok       bool
		category string
		what     string
	}{
		{result.PermissionsOK, "file-permissions", "file permission validation"},
		{result.EncryptionOK, "startup-validation", "encryption validation"},
		{result.DatabaseOK, "startup-validation", "database validation"},
	} {
		if c.ok {
			continue
		}
		report.deviate(c.category, fmt.Sprintf("%s did not pass: %s", c.what, validationDetail(result, err)))
	}

	if !result.PermissionsOK && cfg.Security.EnableFilePermissionCheckImplicitDefault {
		report.deviate("grace-period", "security.enable_file_permission_check's grace period is not yet complied with — the file-permissions deviation above would hard-fail startup once the setting is reviewed and set explicitly")
	}
}

// validationDetail renders what ValidateStartup actually reported, instead of
// formatting its error with %v at every call site.
//
// Two reasons, both from the coordinator's review of this PR. First, err is
// NIL whenever ValidateStartup stopped before reaching a check: printing it
// gave "database validation failed: <nil>", which reads as a failure with no
// cause when the truth is "not evaluated". Second, result.Errors carries the
// per-check messages ValidateStartup collected, which are more specific than
// the single wrapped error -- and are present even in the cases where err is
// nil.
func validationDetail(result *startup.ValidationResult, err error) string {
	if len(result.Errors) > 0 {
		return strings.Join(result.Errors, "; ")
	}
	if err != nil {
		return err.Error()
	}
	return "not evaluated (startup validation stopped at an earlier check — see the deviations above)"
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
		// TODO(FIX-4): report inst.TLSMode here (informational only -- ADR-112's
		// recorded decision keeps TLS 1.2 compliant, so neither mode is a
		// deviation by itself). The field arrived on main with the tls_mode:
		// strict PR, which is NOT in this PR's base chain
		// (#2446 -> #2454 -> #2462), so referencing it here would not compile.
		// Re-add in one line once this stack is rebased onto a main that has it.
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

// collectBreakGlassReviewPosture is the two findings Andrei decided on #2461:
// an unreviewed break-glass activation past its review window is a FAILING
// finding, and a single-admin deployment reports "independent review
// impossible" as a finding of its own.
//
// Both are TODOs rather than code, because #2461 is still OPEN and its API is
// not on main or anywhere in this PR's base chain
// (#2446 -> #2454 -> #2462): core.ListUnreviewedBreakGlassActivations,
// BreakGlassConfig.GetReviewWindow and the review endpoint all arrive with it.
// An earlier revision of this branch was stacked on #2461 and had the first
// finding implemented; that stack is gone now that this PR sits on #2462, and
// reimplementing the API here would fork it.
//
// TODO(#2461): when #2461 merges, restore both findings:
//
//  1. report.deviate("break-glass-review", ...) for every activation older
//     than cfg.BreakGlass.GetReviewWindow() with no review, listing each
//     activation id, project and activation time. The implementation is in
//     this branch's history (the commit before the rebase onto #2462) and was
//     working; it needs no redesign, only the API back.
//  2. report.deviate("break-glass-review", "independent review impossible")
//     when the install has exactly ONE admin-tier holder. This one is a
//     SEPARATE finding, not a detail of the first: with a single admin, every
//     activation is reviewed by the person who activated it, so a clean
//     review record carries no independent assurance at all. It must fire even
//     when every activation HAS been reviewed -- otherwise the install with
//     the weakest possible review process is the one that looks compliant.
//     collectAdminMFAPosture already resolves the admin-tier holder set, so
//     the count is available without new storage work; it is left out here
//     only because "independent review impossible" is meaningless to report
//     before the review requirement it refers to exists.
//
// Deliberately not approximated in the meantime. A finding that said
// "break-glass review status unknown" would be a third thing to maintain and
// would read, in a report whose entire purpose is a trustworthy yes/no, as if
// the check existed.

func printPostureReport(report *postureReport) {
	fmt.Println("ADR-112 Secure Baseline Posture")
	fmt.Println("===============================")
	if len(report.deviations) == 0 {
		fmt.Println("No deviations found.")
	} else {
		// The origin is printed per line, and the counts are summarised, so an
		// operator reading a non-zero exit can immediately see how much of it is
		// "not hardened yet" versus "deliberately turned off". Both are counted:
		// see deviationOrigin.
		var shipped int
		for _, d := range report.deviations {
			if d.origin == originShippedDefault {
				shipped++
			}
		}
		fmt.Printf("%d deviation(s) found (%d from shipped defaults, %d explicitly configured) — all counted:\n",
			len(report.deviations), shipped, len(report.deviations)-shipped)
		for _, d := range report.deviations {
			fmt.Printf("  [%s/%s] %s\n", d.category, d.origin, d.detail)
		}
	}
	if len(report.informational) > 0 {
		fmt.Println("\nInformational (not counted toward the exit code):")
		for _, line := range report.informational {
			fmt.Printf("  - %s\n", line)
		}
	}
}
