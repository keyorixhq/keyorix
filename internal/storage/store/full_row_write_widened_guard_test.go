// full_row_write_widened_guard_test.go — STALE-ROW-WRITES-NOV-1 item 5 (#2704).
//
// TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels sweeps two roots,
// internal/storage/store and internal/core, and three call shapes. A new stale full-row
// write of a security-state model outside those, or in another shape, passed it:
//
//   - a Save in any other production package holding a *gorm.DB (internal/encryption,
//     internal/encryptionops, server/admin, internal/storage's factory, server, ...).
//     All of their writes are map-scoped today; nothing stopped the next one.
//   - UpdateColumns(x) with a struct: Updates without hooks, the same full-row effect.
//   - CreateInBatches(xs, n) under Clauses(clause.OnConflict{UpdateAll: true}).
//
// This sibling reports exactly those additions, with the same exemption ledger
// (docs/full-row-write-exempt.tsv) and the same model derivation. The package set is
// derived (fullRowWidenedRoots), not listed: every directory of the root module whose
// non-test files import gorm.io/gorm or internal/storage/models, each scanned flat (its
// own files only), minus the two roots the original guard already sweeps recursively
// and the non-shipped trees named in fullRowWidenedExcluded.
//
// What it does NOT check: a separate Go module (cli/, operator/: no gorm writes there),
// an OnConflict clause built into a variable before Clauses(v), and a composite literal
// that copies a stale security column (Updates(models.T{State: old.State})). Report-only
// until its first green nightly (docs/guard-rollout.d).
package store

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// fullRowWidenedExcluded are repo-relative trees the widened sweep skips, each with why.
var fullRowWidenedExcluded = map[string]string{
	"internal/storage/store": "swept recursively by the original guard",
	"internal/core":          "swept recursively by the original guard",
	"internal/testutil":      "test fixtures (fuzzworld, pgcanary, ...), linked only into test binaries",
	"internal/testhelper":    "test fixtures, linked only into test binaries",
	"scripts":                "dev and CI tooling, not shipped in the server binary",
	"examples":               "sample programs, not shipped",
}

const fullRowRepoRoot = "../../.."

// fullRowWidenedRoots derives the packages to sweep flat, as paths relative to this
// package directory.
func fullRowWidenedRoots(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(fullRowRepoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel := repoRelPath(t, path)
		if path != fullRowRepoRoot {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, ok := fullRowWidenedExcluded[rel]; ok {
				return filepath.SkipDir
			}
			if _, serr := os.Stat(filepath.Join(path, "go.mod")); serr == nil {
				return filepath.SkipDir // another module (cli/, operator/, ...)
			}
		}
		if fullRowDirImportsModels(t, path) {
			out = append(out, path)
		}
		return nil
	})
	require.NoError(t, err)
	sort.Strings(out)
	return out
}

// fullRowDirImportsModels: some non-test .go file directly in dir imports gorm or the
// models package.
func fullRowDirImportsModels(t *testing.T, dir string) bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, n), nil, parser.ImportsOnly)
		require.NoError(t, perr)
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "gorm.io/gorm" || p == "github.com/keyorixhq/keyorix/internal/storage/models" {
				return true
			}
		}
	}
	return false
}

// fullRowWidenedHits are the security-state hits the widened sweep finds that the
// original guard does not (keyed by file and line).
func fullRowWidenedHits(t *testing.T) []fullRowHit {
	t.Helper()
	base, _ := fullRowWriteHits(t, fullRowWriteRoots)
	seen := map[string]bool{}
	for _, h := range base {
		seen[fmt.Sprintf("%s:%d", h.File, h.Line)] = true
	}
	deep, _ := fullRowWriteScan(t, fullRowScanOpts{roots: fullRowWriteRoots, widened: true})
	flat, _ := fullRowWriteScan(t, fullRowScanOpts{roots: fullRowWidenedRoots(t), flat: true, widened: true})
	var out []fullRowHit
	for _, h := range append(deep, flat...) {
		k := fmt.Sprintf("%s:%d", h.File, h.Line)
		if !seen[k] {
			seen[k] = true
			out = append(out, h)
		}
	}
	return out
}

// TestFullRowWriteGuard_WidenedScanNoStaleFullRowWrite is the widened guard.
func TestFullRowWriteGuard_WidenedScanNoStaleFullRowWrite(t *testing.T) {
	g := guardrules.Rollout(t)
	exempt := map[string]bool{}
	for _, r := range loadFullRowExempt(t) {
		if !isFullRowCallerRow(r) {
			exempt[r.key()] = true
		}
	}
	var bad []string
	for _, h := range fullRowWidenedHits(t) {
		if exempt[h.key()] {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s:%d %s %s(%s) — write only the columns this operation owns (Updates(map…), Update(col, v), Select(named cols)), or add a reviewed row to docs/full-row-write-exempt.tsv", h.File, h.Line, h.Func, h.Call, h.Model))
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		g.Errorf("%d stale full-row write(s) on security-state models outside the original guard's reach:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestFullRowWriteGuard_WidenedRootsAreDerived pins the derivation against the
// packages that hold a *gorm.DB and write models today, and against the trees it
// must leave to the original guard or skip.
func TestFullRowWriteGuard_WidenedRootsAreDerived(t *testing.T) {
	got := map[string]bool{}
	for _, r := range fullRowWidenedRoots(t) {
		got[repoRelPath(t, r)] = true
		t.Logf("widened root: %s", repoRelPath(t, r))
	}
	for ex, why := range fullRowWidenedExcluded {
		t.Logf("skipped tree: %s (%s)", ex, why)
	}
	for _, want := range []string{"internal/encryption", "internal/encryptionops", "internal/storage", "server", "server/admin"} {
		require.Truef(t, got[want], "%s holds gorm writes of models but is not derived as a widened root", want)
	}
	for r := range got {
		for ex := range fullRowWidenedExcluded {
			require.Falsef(t, r == ex || strings.HasPrefix(r, ex+"/"), "%s is under excluded tree %s", r, ex)
		}
		require.Falsef(t, r == "cli" || strings.HasPrefix(r, "cli/") || strings.HasPrefix(r, "operator/"), "%s belongs to another module", r)
	}
}

// TestFullRowWriteGuard_WidenedScanCalibration: the original scan misses each added
// shape and the widened one reports it; the column-scoped forms stay clean; a flat
// root does not descend into its subdirectories.
func TestFullRowWriteGuard_WidenedScanCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package x
import "github.com/keyorixhq/keyorix/internal/storage/models"
func ColumnsStruct(db *gorm.DB, u *models.User) error { return db.Model(u).UpdateColumns(u).Error }
func ColumnsMap(db *gorm.DB, u *models.User) error {
	return db.Model(u).UpdateColumns(map[string]any{"display_name": u.DisplayName}).Error
}
func ColumnsSelect(db *gorm.DB, u *models.User) error {
	return db.Model(u).Select("display_name").UpdateColumns(u).Error
}
func BatchUpsert(db *gorm.DB, us []models.User) error {
	return db.Clauses(clause.OnConflict{UpdateAll: true}).CreateInBatches(us, 100).Error
}
func BatchPlain(db *gorm.DB, us []models.User) error { return db.CreateInBatches(us, 100).Error }
`
	sub := `package y
import "github.com/keyorixhq/keyorix/internal/storage/models"
func Nested(db *gorm.DB, g *models.Group) error { return db.Save(g).Error }
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "y.go"), []byte(sub), 0o600))

	names := func(hs []fullRowHit) []string {
		var out []string
		for _, h := range hs {
			out = append(out, h.Func+":"+h.Call+":"+h.Model)
		}
		sort.Strings(out)
		return out
	}
	base, _ := fullRowWriteHits(t, []string{dir})
	require.Equal(t, []string{"Nested:Save:Group"}, names(base), "the original scan sees only the Save")

	flat, _ := fullRowWriteScan(t, fullRowScanOpts{roots: []string{dir}, flat: true, widened: true})
	require.Equal(t, []string{
		"BatchUpsert:CreateInBatches+UpdateAll:User",
		"ColumnsStruct:UpdateColumns:User",
	}, names(flat), "widened flat scan: the two added shapes, nothing from sub/")
}
