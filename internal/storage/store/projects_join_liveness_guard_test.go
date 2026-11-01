// projects_join_liveness_guard_test.go -- READPATH-DANGLING-ROLE-1 item 2 (#2795).
//
// The class: a reader LEFT JOINs projects (so that project_id 0, "global", needs no
// row) and treats a scoped row as live when projects.deleted_at IS NULL. With no
// projects row at all the joined deleted_at is NULL as well, so a role grant whose
// project was hard-deleted or purged still authorized. The fix is to require the
// joined row to exist: projects.id IS NOT NULL (or <alias>.id IS NOT NULL) next to
// the deleted_at test, as local_project_machine_suspend.go already did.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - every Go string literal in a non-test .go file of internal/storage/store that
//     contains `JOIN projects` (any case, any JOIN kind), optionally followed by an
//     alias (`JOIN projects p`, `JOIN projects AS p`); without an alias the
//     qualifier is `projects`;
//   - its unit: the innermost simple statement holding the literal (an expression,
//     assignment, return or declaration statement, so a whole GORM chain
//     `ls.db.Joins(...).Where(...)...`, or a `q := "..." + "..."` concatenation), or
//     the package-level const/var spec it is the value of;
//   - the unit passes when the concatenated text of ITS string literals carries
//     `<qualifier>.id IS NOT NULL` at least as many times as it carries a projects
//     join with that qualifier.
//
// What it does NOT catch:
//   - a join built without a literal naming the table (GORM association joins such
//     as Joins("Project"), fmt.Sprintf with the table name as an argument, a table
//     name held in a variable);
//   - a predicate in another statement or another const than the join (a named
//     const holding only `LEFT JOIN projects ...` is a hit: put the liveness test
//     beside it);
//   - whether the IS NOT NULL test sits in the right OR branch: it counts, it does
//     not parse SQL. TestDanglingProjectRoleGrant_* pin the behaviour of today's
//     readers;
//   - the same shape on other tables (environments, groups) and packages other than
//     internal/storage/store.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryProjectsJoinRequiresTheRow.tsv).

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var projectsJoinRe = regexp.MustCompile(`(?i)\bJOIN\s+"?projects"?\b(?:\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*))?`)

// sqlWordsAfterTable are the words that can follow `JOIN projects` without being
// an alias.
var sqlWordsAfterTable = map[string]bool{
	"on": true, "using": true, "where": true, "left": true, "right": true, "inner": true,
	"outer": true, "full": true, "cross": true, "join": true, "natural": true,
}

type projectsJoinHit struct {
	pos       string // file:line of the unit
	qualifier string
	joins     int
	notNull   int
}

// scanProjectsJoins returns the units of src whose projects joins outnumber their
// `<qualifier>.id IS NOT NULL` tests, and how many projects joins it saw in all.
func scanProjectsJoins(t *testing.T, filename string, src []byte) ([]projectsJoinHit, int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	require.NoError(t, err, "parse %s", filename)

	units := map[ast.Node]bool{}
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || !projectsJoinRe.MatchString(lit.Value) {
			return true
		}
		for _, anc := range slices.Backward(stack) {
			switch anc.(type) {
			case *ast.ExprStmt, *ast.AssignStmt, *ast.ReturnStmt, *ast.DeclStmt, *ast.ValueSpec:
				units[anc] = true
				return true
			}
		}
		units[lit] = true // a literal outside any statement (a struct tag, say)
		return true
	})

	var hits []projectsJoinHit
	total := 0
	for u := range units {
		text := unitLiteralText(u)
		joins := map[string]int{}
		for _, m := range projectsJoinRe.FindAllStringSubmatch(text, -1) {
			q := "projects"
			if m[1] != "" && !sqlWordsAfterTable[strings.ToLower(m[1])] {
				q = m[1]
			}
			joins[q]++
			total++
		}
		for q, n := range joins {
			re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(q) + `\.id\s+IS\s+NOT\s+NULL\b`)
			if have := len(re.FindAllStringIndex(text, -1)); have < n {
				p := fset.Position(u.Pos())
				hits = append(hits, projectsJoinHit{
					pos: filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line), qualifier: q, joins: n, notNull: have,
				})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	return hits, total
}

// unitLiteralText is the unquoted text of every string literal in n, joined by
// newlines (Go comments are not literals, so a comment cannot satisfy the guard).
func unitLiteralText(n ast.Node) string {
	var b strings.Builder
	ast.Inspect(n, func(c ast.Node) bool {
		if lit, ok := c.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				b.WriteString(s)
			} else {
				b.WriteString(lit.Value)
			}
			b.WriteByte('\n')
		}
		return true
	})
	return b.String()
}

func TestEveryProjectsJoinRequiresTheRow(t *testing.T) {
	g := guardrules.Rollout(t)
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	total := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- this package's own sources
		require.NoError(t, err)
		hits, n := scanProjectsJoins(t, name, src)
		total += n
		for _, h := range hits {
			g.Errorf("%s: %d JOIN projects (qualifier %q) but %d %s.id IS NOT NULL: a scoped row with no projects row would read as live (#2795); add `%s.id IS NOT NULL AND %s.deleted_at IS NULL`",
				h.pos, h.joins, h.qualifier, h.notNull, h.qualifier, h.qualifier, h.qualifier)
		}
	}
	// Not vacuous: today's readers join projects in at least these places
	// (GetUserRoleIDsAt, GetUserGroupRoleIDsAt, GetMachineRoleIDsAt, the
	// combined principal-permission statements, ListUserRoleGrants, the read-path
	// prefetch, the machine-suspend sweep).
	require.GreaterOrEqual(t, total, 10, "the scan found too few projects joins: is it reading the package?")
}

// Calibration: the scanner flags the shapes it claims to and passes the fixed ones.
func TestEveryProjectsJoinRequiresTheRow_Calibration(t *testing.T) {
	cases := []struct {
		name string
		src  string
		hits int
	}{
		{"gorm chain without the row test", `package p
func f() { db.Joins("LEFT JOIN projects ON projects.id = user_roles.project_id").
	Where("user_roles.project_id = 0 OR (user_roles.project_id = ? AND projects.deleted_at IS NULL)", 1) }`, 1},
		{"gorm chain with the row test", `package p
func f() { db.Joins("LEFT JOIN projects ON projects.id = user_roles.project_id").
	Where("user_roles.project_id = 0 OR (user_roles.project_id = ? AND projects.id IS NOT NULL AND projects.deleted_at IS NULL)", 1) }`, 0},
		{"aliased raw SQL without the row test", "package p\nconst q = `SELECT 1 FROM r LEFT JOIN projects AS p ON p.id = r.project_id WHERE r.project_id = 0 OR p.deleted_at IS NULL`", 1},
		{"aliased raw SQL with the row test", "package p\nconst q = `SELECT 1 FROM r LEFT JOIN projects p ON p.id = r.project_id WHERE r.project_id = 0 OR (p.id IS NOT NULL AND p.deleted_at IS NULL)`", 0},
		{"the wrong qualifier does not count", "package p\nconst q = `SELECT 1 FROM r LEFT JOIN projects p ON p.id = r.project_id WHERE projects.id IS NOT NULL AND p.deleted_at IS NULL`", 1},
		{"two joins, one row test", "package p\nconst q = `SELECT 1 FROM a LEFT JOIN projects ON projects.id = a.project_id WHERE projects.id IS NOT NULL UNION SELECT 1 FROM b LEFT JOIN projects ON projects.id = b.project_id WHERE projects.deleted_at IS NULL`", 1},
		{"a comment does not count", `package p
func f() {
	// projects.id IS NOT NULL
	db.Joins("LEFT JOIN projects ON projects.id = x.project_id").Where("projects.deleted_at IS NULL")
}`, 1},
		{"a predicate in another statement does not count", `package p
func f() {
	q := db.Joins("LEFT JOIN projects ON projects.id = x.project_id")
	q = q.Where("projects.id IS NOT NULL")
}`, 1},
		{"concatenated SQL in one assignment", `package p
func f() { joins := "LEFT JOIN projects ON projects.id = m.project_id\n" + " WHERE (m.project_id = 0 OR (projects.id IS NOT NULL AND projects.deleted_at IS NULL))"; _ = joins }`, 0},
		{"inner join is held to the same rule", `package p
func f() { db.Joins("JOIN projects ON projects.id = x.project_id AND projects.deleted_at IS NULL") }`, 1},
		{"projects_* tables are not projects", `package p
func f() { db.Joins("LEFT JOIN projects_archive ON projects_archive.id = x.project_id") }`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits, _ := scanProjectsJoins(t, "fixture.go", []byte(c.src))
			require.Len(t, hits, c.hits, "%+v", hits)
		})
	}
}
