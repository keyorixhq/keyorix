package storage

// migrate_timestamp_guard_test.go -- #3440 guard: no hand-written timestamp
// column type in internal/storage DDL.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var (
	// A PostgreSQL-only timestamp type spelled out: SQLite stores it, then the driver
	// returns its values as strings.
	pgTimestampTypeRe = regexp.MustCompile(`(?i)\btimestamp\s+with(out)?\s+time\s+zone\b|\btimestamptz\b`)
	// SQLite's DATETIME as a type (not the datetime('now') function), which
	// PostgreSQL does not know.
	datetimeTypeRe = regexp.MustCompile(`(?i)\bdatetime\b\s*(\(?)`)
	// Any timestamp type in an ADD COLUMN.
	addColumnTimestampRe = regexp.MustCompile(`(?is)\badd\s+column\b.*\b(timestamp|datetime)\b`)
)

// handWrittenTimestampType reports why the SQL text s spells out a timestamp
// column type, or "" when it does not.
func handWrittenTimestampType(s string) string {
	if pgTimestampTypeRe.MatchString(s) {
		return "names a PostgreSQL timestamp type"
	}
	for _, m := range datetimeTypeRe.FindAllStringSubmatch(s, -1) {
		if m[1] == "" {
			return "names the SQLite DATETIME type"
		}
	}
	if addColumnTimestampRe.MatchString(s) {
		return "adds a column with a literal timestamp type"
	}
	return ""
}

func TestHandWrittenTimestampType_Matcher(t *testing.T) {
	bad := []string{
		"ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP WITH TIME ZONE",
		"ALTER TABLE users ADD COLUMN x timestamp without time zone",
		",\n\t\texpires_at TIMESTAMP WITH TIME ZONE",
		"ALTER TABLE t ADD COLUMN x TIMESTAMPTZ",
		"ALTER TABLE t ADD COLUMN x DATETIME",
		"DATETIME",
		"ALTER TABLE t ADD COLUMN x TIMESTAMP",
		"CREATE TABLE t (id INTEGER, at datetime NOT NULL)",
	}
	good := []string{
		"ALTER TABLE users ADD COLUMN last_login_at ",
		"ALTER TABLE t ADD COLUMN n INTEGER NOT NULL DEFAULT 0",
		"INSERT INTO system_metadata (key, value, updated_at) VALUES ('k', '0', datetime('now'))",
		"UPDATE t SET at = datetime ('now')",
		"invalid timestamp in audit row",
		"TIMESTAMP",
	}
	for _, s := range bad {
		if handWrittenTimestampType(s) == "" {
			t.Errorf("matcher missed a hand-written timestamp type in %q", s)
		}
	}
	for _, s := range good {
		if why := handWrittenTimestampType(s); why != "" {
			t.Errorf("matcher flagged %q (%s)", s, why)
		}
	}
}

// TestNoHandWrittenTimestampColumnDDL fails on a Go string literal in
// non-test code under internal/storage that spells out a timestamp column type
// (#3440). Such DDL must take sqlTimestampType(db) or go through
// Migrator().AddColumn, so SQLite gets DATETIME and PostgreSQL TIMESTAMP WITH
// TIME ZONE.
//
// Recognised: each string literal on its own (a type split across concatenated
// literals is still seen in the literal that holds the type word). Exempt:
// sqlTimestampType itself and internal/storage/sqlitedialect (the dialect that
// maps model fields to DATETIME). Not covered: SQL outside internal/storage
// (internal/solewriter's PostgreSQL-only fence table, the legacy migrations/*.sql
// files), and a type name built at run time from non-literal parts.
func TestNoHandWrittenTimestampColumnDDL(t *testing.T) {
	g := guardrules.Rollout(t)
	root := filepath.Join(repoRootU1(), "internal", "storage")
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "sqlitedialect" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		rel, _ := filepath.Rel(repoRootU1(), path)
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "sqlTimestampType" {
				return false
			}
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if why := handWrittenTimestampType(s); why != "" {
				g.Errorf("%s:%d: string literal %s; use sqlTimestampType(db) or Migrator().AddColumn (#3440): %q",
					rel, fset.Position(lit.Pos()).Line, why, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		g.Fatalf("walking %s: %v", root, err)
	}
	if files < 50 {
		g.Fatalf("scanned only %d Go files under %s; the walk is not seeing the package", files, root)
	}
}
