// g81_guard_test.go — guard test for the G81 timezone bug class (see the
// BeforeSave hooks in internal/storage/models/models.go and
// g81_audit_event_timezone_test.go). Two checks:
//
//  1. Reflection: every entry below marked HasHook actually has a BeforeSave
//     hook on the model it names.
//  2. AST freshness: every time-shaped column name appearing in a range
//     comparison (>=, <=, <, >) anywhere in this package's non-test source is
//     present in g81MaintainedFields below. A NEW range-queried time-ish
//     column that shows up without a corresponding entry fails this test —
//     add an entry (with hook status + exemption reason) rather than ignore
//     the failure.
//
// This cannot fully resolve WHICH MODEL a bare column name belongs to from
// static analysis alone: tracing a GORM method chain back to its Model()/
// Table() call reliably needs real dataflow analysis this codebase's query
// style doesn't support with simple AST walking (single-chain calls,
// reassigned `query = query.Where(...)` across statements, raw
// `Table("literal_string")` calls). The freshness check is therefore keyed by
// COLUMN NAME, not (model, column) — several models can and do share a column
// name (expires_at, created_at). Each entry still records which model it's
// really about, for the reflection check and for human review, but a
// genuinely new query against an EXISTING column name on an untracked model
// will not be caught by this test alone. That's a known, accepted limitation
// of a maintained list — see the G81 bug-class sweep's Stage 1 report for the
// fuller discussion of why full automation isn't feasible here.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// beforeSaver is satisfied by any model with a BeforeSave hook (any receiver
// type GORM would actually invoke it on).
type beforeSaver interface {
	BeforeSave(*gorm.DB) error
}

// g81FieldEntry records one range-queried time-ish column this package
// compares against a bound. Value is a pointer instance of the model, used
// for the reflection check; Column is the exact string as it appears in a
// SQL WHERE/HAVING fragment (no table alias).
type g81FieldEntry struct {
	Model   string
	Column  string
	Value   any
	HasHook bool
	// Exempt is required when HasHook is false: why no hook covers this
	// column, or why none is needed.
	Exempt string
}

// g81MaintainedFields is the maintained list. Every entry either has
// HasHook: true (verified by reflection below to actually have a BeforeSave
// method) or a non-empty Exempt reason.
var g81MaintainedFields = []g81FieldEntry{
	// --- Live G81 recurrences, hook + read-side fixed ---
	{Model: "AuditEvent", Column: "event_time", Value: &models.AuditEvent{}, HasHook: true},
	{Model: "AnomalyAlert", Column: "detected_at", Value: &models.AnomalyAlert{}, HasHook: true},
	{Model: "SecretAccessLog", Column: "access_time", Value: &models.SecretAccessLog{}, HasHook: true},
	{Model: "PersonalAccessToken", Column: "expires_at", Value: &models.PersonalAccessToken{}, HasHook: true},
	{Model: "ShareRecord", Column: "expires_at", Value: &models.ShareRecord{}, HasHook: true},
	{Model: "SecretNode", Column: "expiration", Value: &models.SecretNode{}, HasHook: true},
	{Model: "LoginAttempt", Column: "attempted_at", Value: &models.LoginAttempt{}, HasHook: true},

	// --- Latent G81 recurrences, hook-only fixed (self-consistent write/read
	// today, but the same recurring risk class) ---
	{Model: "MFAStepupToken", Column: "expires_at", Value: &models.MFAStepupToken{}, HasHook: true},
	{Model: "MFAStepUpGrant", Column: "expires_at", Value: &models.MFAStepUpGrant{}, HasHook: true},
	{Model: "UserRole", Column: "expires_at", Value: &models.UserRole{}, HasHook: true},
	{Model: "GroupRole", Column: "expires_at", Value: &models.GroupRole{}, HasHook: true},
	{Model: "DynamicSecretLease", Column: "expires_at", Value: &models.DynamicSecretLease{}, HasHook: true},
	{Model: "MFAChallenge", Column: "expires_at", Value: &models.MFAChallenge{}, HasHook: true},
	{Model: "Session", Column: "expires_at", Value: &models.Session{}, HasHook: true},
	{Model: "WebAuthnSession", Column: "expires_at", Value: &models.WebAuthnSession{}, HasHook: true},
	{Model: "MachineIdentityCredential", Column: "expires_at", Value: &models.MachineIdentityCredential{}, HasHook: true},
	{Model: "SetupToken", Column: "created_at", Value: &models.SetupToken{}, HasHook: true},
	{Model: "User", Column: "created_at", Value: &models.User{}, HasHook: true},
	{Model: "MachineIdentity", Column: "created_at", Value: &models.MachineIdentity{}, HasHook: true},
	{Model: "BreakGlassActivation", Column: "created_at", Value: &models.BreakGlassActivation{}, HasHook: true},
	{Model: "ProjectMembership", Column: "invited_at", Value: &models.ProjectMembership{}, HasHook: true},
	{Model: "AccessReviewCampaign", Column: "closed_at", Value: &models.AccessReviewCampaign{}, HasHook: true},
	{Model: "AccessRequest", Column: "resolved_at", Value: &models.AccessRequest{}, HasHook: true},

	// --- Exempt: no hook, with reasons ---
	{
		Model: "User", Column: "last_login_at", Value: &models.User{}, HasHook: false,
		Exempt: "sole write path (UpdateLastLogin, UpdateColumn) bypasses all model hooks; " +
			"normalized explicitly at internal/core/auth.go's RecordLogin instead, mirroring " +
			"local_mfa_stepup.go's MFAStepupToken ON CONFLICT precedent",
	},
	{
		Model: "StatsSnapshot", Column: "created_at", Value: &models.StatsSnapshot{}, HasHook: false,
		Exempt: "GORM-implicit auto-timestamp, never explicitly set in Go — empirically verified " +
			"BeforeSave fires BEFORE GORM's own auto-CreatedAt assignment, so a hook would " +
			"normalize a zero value and then be silently overwritten; see the doc comment on " +
			"models.StatsSnapshot",
	},
	{
		Model: "Session", Column: "last_seen_at", Value: &models.Session{}, HasHook: false,
		Exempt: "sole write path (TouchSession, UpdateColumn) bypasses all model hooks; latent " +
			"today (write and read both use unnormalized local time, consistently) — tracked " +
			"in #1507, not fixed, since it isn't live",
	},
	{
		Model: "PersonalAccessToken", Column: "last_used_at", Value: &models.PersonalAccessToken{}, HasHook: false,
		Exempt: "sole write path (TouchPersonalAccessToken, UpdateColumn) bypasses all model " +
			"hooks; latent today — tracked in #1507, not fixed",
	},
	{
		Model: "MachineIdentityCredential", Column: "last_used_at", Value: &models.MachineIdentityCredential{}, HasHook: false,
		Exempt: "sole write path (TouchMachineIdentityCredential, UpdateColumn) bypasses all " +
			"model hooks; latent today — tracked in #1507, not fixed",
	},
	{
		Model: "SecretNode", Column: "created_at", Value: &models.SecretNode{}, HasHook: false,
		Exempt: "storage.SecretFilter.CreatedAfter/CreatedBefore, the only caller of this range " +
			"query, is set only in _test.go files today — dead in production. Would need this " +
			"model's existing hook extended to cover CreatedAt too if that filter is ever wired " +
			"up to a real caller",
	},
	{
		Model: "(various — gorm.DeletedAt)", Column: "deleted_at", Value: nil, HasHook: false,
		Exempt: "gorm.DeletedAt, not time.Time/*time.Time — a distinct type GORM manages itself " +
			"via its own soft-delete machinery (stamped by the *gorm.DB connection's local " +
			"NowFunc at delete time), not a plain application field a BeforeSave hook can " +
			"normalize the same way. Out of scope for the G81 bug class by definition (which is " +
			"about time.Time/*time.Time fields specifically) — see retention_proxy.go's package " +
			"doc for how its callers handle this column's Location explicitly instead",
	},
	{
		Model: "DeploymentStatsSnapshot", Column: "snapshot_date", Value: &models.DeploymentStatsSnapshot{}, HasHook: false,
		Exempt: "written with explicit time.Now().UTC() at every call site and queried with an " +
			"explicit .UTC() bound; no hook needed",
	},
	{
		Model: "CompliancePostureSnapshot", Column: "snapshot_date", Value: &models.CompliancePostureSnapshot{}, HasHook: false,
		Exempt: "written with explicit time.Now().UTC() at every call site and queried with an " +
			"explicit .UTC() bound (GetPreviousCompliancePostureSnapshot); no hook needed",
	},
}

// TestG81_MaintainedFieldsHaveWorkingHooks is the reflection check: every
// entry claiming HasHook: true must actually implement BeforeSave, and every
// entry claiming HasHook: false must carry a non-empty Exempt reason.
func TestG81_MaintainedFieldsHaveWorkingHooks(t *testing.T) {
	for _, f := range g81MaintainedFields {
		t.Run(f.Model+"."+f.Column, func(t *testing.T) {
			if f.HasHook {
				if f.Value == nil {
					t.Fatalf("%s.%s: HasHook is true but Value is nil, cannot verify", f.Model, f.Column)
				}
				if _, ok := f.Value.(beforeSaver); !ok {
					t.Errorf("%s.%s is listed as hook-covered but %T has no BeforeSave(*gorm.DB) error method",
						f.Model, f.Column, f.Value)
				}
				if f.Exempt != "" {
					t.Errorf("%s.%s has HasHook: true but also an Exempt reason set — pick one", f.Model, f.Column)
				}
			} else if f.Exempt == "" {
				t.Errorf("%s.%s has HasHook: false but no Exempt reason recorded", f.Model, f.Column)
			}
		})
	}
}

// g81TimeColumnPattern matches a column reference immediately followed by a
// >=, <=, <, or > comparison against a bind placeholder — the exact shape
// every range query in this package uses (see the Stage 1 sweep report).
// Deliberately excludes plain "=" (equality isn't a range comparison and
// isn't subject to this bug class) and ">"/"<" used for anything other than
// a bind placeholder immediately after (ruling out unrelated numeric
// comparisons like "count > 0" written as a literal, though "id > ?" style
// non-time columns still need the time-ish name filter below to be excluded).
var g81TimeColumnPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_.]*)\s*(>=|<=|<|>)\s*\?`)

// g81TimeLikeColumn reports whether a bare (alias-stripped) column name looks
// like a time.Time/*time.Time column by this codebase's naming conventions.
// The suffix check covers the overwhelming majority; the explicit set covers
// the handful of columns found during the sweep that don't follow it
// (SecretNode.Expiration, User.LoginLockedUntil, MachineIdentityCredential's
// sibling CertNotAfter on a different model) — see the Stage 1 report for how
// these were found (a suffix-only grep misses them).
var g81ExplicitTimeLikeColumns = map[string]bool{
	"expiration":         true,
	"login_locked_until": true,
	"cert_not_after":     true,
}

func g81TimeLikeColumn(col string) bool {
	if g81ExplicitTimeLikeColumns[col] {
		return true
	}
	return strings.HasSuffix(col, "_at") || strings.HasSuffix(col, "_time") || strings.HasSuffix(col, "_date")
}

// TestG81_NoUntrackedRangeQueriedTimeColumns is the AST freshness check: parse
// every non-test .go file in this package, collect every column name that
// appears in a range comparison against a bind placeholder, and assert each
// time-like one is accounted for in g81MaintainedFields. Fails with the
// offending file:line so a new range query on a new column can't silently
// skip this bug class.
func TestG81_NoUntrackedRangeQueriedTimeColumns(t *testing.T) {
	known := make(map[string]bool, len(g81MaintainedFields))
	for _, f := range g81MaintainedFields {
		known[f.Column] = true
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("failed to list package directory: %v", err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range g81TimeColumnPattern.FindAllStringSubmatch(s, -1) {
				col := m[1]
				if idx := strings.LastIndex(col, "."); idx != -1 {
					col = col[idx+1:]
				}
				if !g81TimeLikeColumn(col) {
					continue
				}
				if !known[col] {
					pos := fset.Position(lit.Pos())
					t.Errorf("%s:%d: range query on untracked time-like column %q (in %q) — "+
						"add a g81FieldEntry to g81_guard_test.go recording which model this is, "+
						"whether it has a BeforeSave hook, and why (or why not)",
						pos.Filename, pos.Line, col, s)
				}
			}
			return true
		})
	}
}
