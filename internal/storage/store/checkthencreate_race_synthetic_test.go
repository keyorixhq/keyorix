// checkthencreate_race_synthetic_test.go — positive control for
// checkthencreate_race_completeness_test.go: proves the detector actually
// catches the unguarded check-then-create shape (not just that it passes
// vacuously against main, where every real site happens to already be
// fixed) by running it against a minimal synthetic source snippet that
// reproduces the bug pattern, both without and with a backing unique index.
package store

import (
	"go/parser"
	"go/token"
	"testing"
)

// syntheticCheckThenCreateSrc reproduces the exact shape this repo's own
// history hit repeatedly (#117/#121/#136/#305/#309/#313/#462/MT-006): an
// existence check via a Get<Entity>By<Key>-shaped call, immediately followed
// by a Create<Entity> call building the row from a models.X composite
// literal. Syntactically self-contained — go/parser only needs valid syntax,
// not a resolvable "models" import, so this never touches the real package.
const syntheticCheckThenCreateSrc = `package synthetic

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type fakeStorage struct{}

func (s *fakeStorage) GetWidgetByName(ctx context.Context, name string) (*models.Widget, error) {
	return nil, nil
}

func (s *fakeStorage) CreateWidget(ctx context.Context, w *models.Widget) (*models.Widget, error) {
	return w, nil
}

// CreateWidgetIfMissing is the unguarded check-then-create shape: two
// concurrent callers can both pass the GetWidgetByName check before either
// commits the CreateWidget insert, unless widgets carries a DB-level unique
// index on name.
func CreateWidgetIfMissing(ctx context.Context, s *fakeStorage, name string) (*models.Widget, error) {
	existing, err := s.GetWidgetByName(ctx, name)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("widget %q already exists", name)
	}
	w := &models.Widget{Name: name}
	return s.CreateWidget(ctx, w)
}
`

func parseSynthetic(t *testing.T) (*token.FileSet, []ctcSite) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", syntheticCheckThenCreateSrc, 0)
	if err != nil {
		t.Fatalf("parsing synthetic source: %v", err)
	}
	sites := findSitesInFile(fset, f, "synthetic.go")
	return fset, sites
}

// TestCheckThenCreate_SyntheticSite_IsDiscovered proves discoverCheckThenCreateSites'
// underlying per-file scan (findSitesInFile) actually recognizes the
// check-then-create shape at all: without this, a bug in the AST walk could
// make the real completeness test above pass vacuously (zero sites found ==
// zero violations, for the wrong reason).
func TestCheckThenCreate_SyntheticSite_IsDiscovered(t *testing.T) {
	_, sites := parseSynthetic(t)
	if len(sites) != 1 {
		t.Fatalf("expected exactly 1 check-then-create site in the synthetic fixture, got %d: %+v", len(sites), sites)
	}
	got := sites[0]
	if got.Func != "CreateWidgetIfMissing" {
		t.Errorf("Func = %q, want CreateWidgetIfMissing", got.Func)
	}
	if got.CheckCall != "GetWidgetByName" {
		t.Errorf("CheckCall = %q, want GetWidgetByName", got.CheckCall)
	}
	if got.CreateCall != "CreateWidget" {
		t.Errorf("CreateCall = %q, want CreateWidget", got.CreateCall)
	}
	if got.Model != "Widget" {
		t.Errorf("Model = %q, want Widget (resolved from the &models.Widget{} composite literal, not the method name)", got.Model)
	}
}

// TestCheckThenCreate_SyntheticSite_FlaggedWhenUnindexed is the actual
// negative-case proof: feed the synthetic site's resolved model into a
// registry that has NO unique index for "widgets" (reproducing the exact
// pre-fix state of, e.g., secret_nodes before MT-006, or legal_holds before
// #305) and confirm the guard's own pass/fail predicate — hasAnyUniqueIndex —
// says "unguarded", i.e. this site WOULD fail TestCheckThenCreateSitesAreUniqueIndexBacked.
func TestCheckThenCreate_SyntheticSite_FlaggedWhenUnindexed(t *testing.T) {
	_, sites := parseSynthetic(t)
	if len(sites) != 1 {
		t.Fatalf("expected exactly 1 check-then-create site, got %d", len(sites))
	}
	registry := uniqueIndexRegistry{} // deliberately empty: "widgets" has no unique index anywhere
	table := structNameToTable(sites[0].Model)
	if table != "widgets" {
		t.Fatalf("structNameToTable(%q) = %q, want widgets", sites[0].Model, table)
	}
	if registry.hasAnyUniqueIndex(table) {
		t.Fatal("expected hasAnyUniqueIndex(widgets) to be false against an empty registry — the positive control is broken")
	}
}

// TestCheckThenCreate_SyntheticSite_PassesWhenIndexed is the corresponding
// positive case: the same site, but the registry now carries a unique index
// on widgets.name (as if a `uniqueIndex` gorm tag or a factory.go
// ensure*Index helper had been added, mirroring every real fix in this
// repo's history) — confirms the guard does NOT flag a properly-fixed site,
// i.e. it isn't trivially failing on everything.
func TestCheckThenCreate_SyntheticSite_PassesWhenIndexed(t *testing.T) {
	_, sites := parseSynthetic(t)
	if len(sites) != 1 {
		t.Fatalf("expected exactly 1 check-then-create site, got %d", len(sites))
	}
	registry := uniqueIndexRegistry{}
	table := structNameToTable(sites[0].Model)
	registry.add(table, "name")
	if !registry.hasAnyUniqueIndex(table) {
		t.Fatal("expected hasAnyUniqueIndex(widgets) to be true once a unique index on widgets.name is registered")
	}
}
