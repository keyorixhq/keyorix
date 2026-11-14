// audit_walk_racing_purge_guard_test.go — AUDIT-WALK-TAILS-1 item 2 (#3944).
//
// A retention purge takes no audit lock that a chain walk holds, so one that
// lands while a walk from the chain start is between store batches removes rows
// past its cursor and the valid chain reads broken (LinkBroken).
// walkAuditChainRacingPurge (audit_verify_purge_restart.go) re-reads the
// authenticated anchor and walks once more from it. A new from-the-start
// walker that calls the plain walk instead brings that false BROKEN back (or,
// on a write path, a refusal), so every call site of a plain walk is
// allowlisted here with the reason it does not need the re-walk, and any other
// fails.
//
// What it recognises: any selector expression (a call or a method value) named
// walkAuditChain or walkAuditChainGaps (internal/core/audit_seal.go), or the
// storage walks under them, VerifyAuditChain and VerifyAuditChainSegment, in a
// non-test .go file of the core family (srcpath.CoreFamilyGoFiles: internal/core
// and the packages split out of it), keyed by file and enclosing
// top-level function. KeyorixCore.VerifyAuditChain shares the storage method's
// name and walks through the racing-purge walk itself, so a call of it on the
// enclosing *KeyorixCore method's own receiver (c.VerifyAuditChain) is not a
// site; the same name on anything else (c.storage, a tx handle) is.
//
// What it does not see: a call through reflection or through a func value
// taken elsewhere under another name (taking the method value is itself a
// reported site), packages outside the core family (the methods are
// unexported; the storage walks there are the implementations, not callers),
// and whether an allowlisted site still walks the way its reason says: the
// reason is a reviewed claim, re-read it when the site changes.
//
// The red proof is TestAuditWalkRacingPurgeGuard_RejectsAPlainWalker, which
// runs the same scan over fixture packages under testdata.
package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

var plainAuditWalks = []string{"walkAuditChain", "walkAuditChainGaps", "VerifyAuditChain", "VerifyAuditChainSegment"}

// acceptLossNoPurge is why accept-loss planning may walk plainly.
const acceptLossNoPurge = "accept-loss planning: `admin audit accept-loss` runs only under the exclusive database lock with every server stopped (server/admin/audit_accept_loss.go), so no retention purge runs during it"

// allowedPlainAuditWalkSites: "file:enclosing function|callee" -> why this
// site may walk without walkAuditChainRacingPurge.
var allowedPlainAuditWalkSites = map[string]string{
	"audit_verify_purge_restart.go:KeyorixCore.walkAuditChainRacingPurge|walkAuditChain": "the racing-purge walk itself: its first walk and its re-walk from the moved anchor",
	"audit_seal.go:KeyorixCore.walkAuditChain|walkAuditChainGaps":                        "walkAuditChain is walkAuditChainGaps with the trusted seal list; it is the plain walk callers must not reach directly",
	"audit_seal.go:KeyorixCore.walkAuditChainGaps|VerifyAuditChain":                      "the storage walk under walkAuditChainGaps",
	"audit_seal.go:KeyorixCore.walkAuditChainGaps|VerifyAuditChainSegment":               "the storage walk under walkAuditChainGaps",
	"audit_verify_incremental.go:KeyorixCore.auditTailCheck|walkAuditChain":              "tail walk from the latest checkpoint's head (AfterID != 0), not from the chain start: the anchor re-walk does not apply (walkAuditChainRacingPurge is for AfterID == 0)",
	"audit_verify_incremental.go:KeyorixCore.advanceAuditRollingCycle|walkAuditChain":    "method value: the rolling cycle picks walkAuditChainRacingPurge for its chain-start segment (AfterID == 0) and the plain walk for a segment seeded from a previous one",
	"audit_seal_accept.go:KeyorixCore.PlanAuditLossAcceptance|walkAuditChainGaps":        acceptLossNoPurge,
	"audit_seal_accept.go:KeyorixCore.auditLossResumeCheck|walkAuditChainGaps":           acceptLossNoPurge,
	"audit_seal_accept.go:KeyorixCore.planAuditGaps|walkAuditChainGaps":                  acceptLossNoPurge,
	"audit_seal_accept.go:KeyorixCore.planAuditGaps|VerifyAuditChainSegment":             acceptLossNoPurge + "; a one-row pin check of a named id",
	"audit_seal_accept.go:KeyorixCore.planAuditTruncation|walkAuditChainGaps":            acceptLossNoPurge,
}

func auditWalkFuncKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// coreReceiverName is the receiver's name when fd is a *KeyorixCore method.
func coreReceiverName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 || len(fd.Recv.List[0].Names) == 0 {
		return ""
	}
	star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return ""
	}
	if id, ok := star.X.(*ast.Ident); !ok || id.Name != "KeyorixCore" {
		return ""
	}
	return fd.Recv.List[0].Names[0].Name
}

// scanPlainAuditWalks returns every "file:func|callee" site in files (non-test
// .go files), each file keyed by key(path).
func scanPlainAuditWalks(t testing.TB, files []string, key func(string) string) []string {
	t.Helper()
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, path := range files {
		name := key(path)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			recv := coreReceiverName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !slices.Contains(plainAuditWalks, sel.Sel.Name) {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && recv != "" && id.Name == recv && sel.Sel.Name == "VerifyAuditChain" {
					return true // KeyorixCore.VerifyAuditChain: walks through walkAuditChainRacingPurge
				}
				seen[name+":"+auditWalkFuncKey(fd)+"|"+sel.Sel.Name] = true
				return true
			})
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func unlistedPlainAuditWalks(sites []string, allow map[string]string) []string {
	var out []string
	for _, s := range sites {
		if _, ok := allow[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

func TestEveryPlainAuditWalkIsAllowlisted(t *testing.T) {
	sites := scanPlainAuditWalks(t, coreFamilySources(t), srcpath.CoreFamilyRel)
	for _, s := range unlistedPlainAuditWalks(sites, allowedPlainAuditWalkSites) {
		t.Errorf("internal/core/%s walks the audit chain without walkAuditChainRacingPurge: a retention purge landing between the walk's batches reads a valid chain BROKEN (#3944). Walk from the chain start through walkAuditChainRacingPurge (and use its Reanchored anchor's purged count), or add the site to allowedPlainAuditWalkSites with the reason no purge can race it", s)
	}
	for key := range allowedPlainAuditWalkSites {
		if !slices.Contains(sites, key) {
			t.Errorf("allowedPlainAuditWalkSites has %q, which no longer exists: remove the entry", key)
		}
	}
}

// Calibration pair: the bad fixture holds a plain from-the-start walk (a call
// and a method value), which the scan reports; the good fixture walks through
// the racing-purge walk only, and its one plain site is accepted once listed.
func TestAuditWalkRacingPurgeGuard_RejectsAPlainWalker(t *testing.T) {
	dir := srcpath.PkgDir()
	rel := func(p string) string {
		r, err := filepath.Rel(dir, p)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(r)
	}

	bad := scanPlainAuditWalks(t, []string{filepath.Join(dir, "testdata/auditwalk/bad/walker.go")}, rel)
	got := unlistedPlainAuditWalks(bad, allowedPlainAuditWalkSites)
	want := []string{
		"testdata/auditwalk/bad/walker.go:KeyorixCore.exportChain|walkAuditChain",
		"testdata/auditwalk/bad/walker.go:KeyorixCore.sealedReport|walkAuditChainGaps",
		"testdata/auditwalk/bad/walker.go:pickWalk|walkAuditChain",
		"testdata/auditwalk/bad/walker.go:rawStoreWalk|VerifyAuditChain",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("guard did not reject the fixture's plain walkers:\n got  %q\n want %q", got, want)
	}

	// Keyed by base name, so the racing-purge walk's own site matches its
	// allowlist entry.
	good := scanPlainAuditWalks(t, []string{filepath.Join(dir, "testdata/auditwalk/good/audit_verify_purge_restart.go")}, filepath.Base)
	if !slices.Equal(good, []string{"audit_verify_purge_restart.go:KeyorixCore.walkAuditChainRacingPurge|walkAuditChain"}) {
		t.Fatalf("good fixture sites = %q", good)
	}
	if extra := unlistedPlainAuditWalks(good, allowedPlainAuditWalkSites); len(extra) != 0 {
		t.Fatalf("the racing-purge walk's own site was rejected: %q", extra)
	}
	if unlisted := unlistedPlainAuditWalks(good, nil); len(unlisted) != 1 {
		t.Fatalf("without the entry the good fixture must be rejected, got %q", unlisted)
	}
}
