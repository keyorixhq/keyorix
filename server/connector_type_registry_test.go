// connector_type_registry_test.go — regression test for #1476's structural
// concern: initializeCoreService's Connect-wiring switch (main.go, "switch
// cn.Type") dispatches on literal case labels rather than deriving from
// connect.KnownTypes (each case needs a different constructor call, some with
// type-specific side effects that don't reduce to a uniform map[string]func
// lookup — see connect.KnownTypes' own doc comment). Nothing stops that switch's
// case set from silently drifting away from connect.KnownTypes, the list
// internal/config.Validate()'s validateConnectTypes checks a configured
// connector's Type against — a case added to one without the other would
// either make a Validate()-accepted type fall through to the switch's Fatal
// default (a boot-time crash for a config that was supposed to be legal), or
// make the switch accept a type Validate() should have already rejected (dead
// code, but a sign the two have drifted).
//
// Rather than hand-maintain a second literal copy of the case-label set here
// (exactly the duplication this test exists to prevent), this parses
// server/main.go's own source via go/ast and extracts the actual case string
// literals from the switch inside initializeCoreService, then diffs that
// discovered set against connect.KnownTypes.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/connect"
)

// TestConnectorTypeRegistry_SwitchMatchesKnownTypes is the regression test
// described above.
func TestConnectorTypeRegistry_SwitchMatchesKnownTypes(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate server/main.go relative to this test file")
	}
	mainGoPath := filepath.Join(filepath.Dir(thisFile), "main.go")
	if _, err := os.Stat(mainGoPath); err != nil {
		t.Fatalf("server/main.go not found at %s: %v", mainGoPath, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGoPath, nil, 0)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", mainGoPath, err)
	}

	discovered := discoverConnectorTypeSwitchCases(t, file)
	if len(discovered) == 0 {
		t.Fatal("discovered zero case labels on the Connect-wiring switch in server/main.go — " +
			"the AST walk is almost certainly broken (the switch has 4 cases today), not that the switch was removed")
	}

	known := map[string]bool{}
	for _, typ := range connect.KnownTypes {
		known[typ] = true
	}

	var missingFromRegistry, missingFromSwitch []string
	for c := range discovered {
		if !known[c] {
			missingFromRegistry = append(missingFromRegistry, c)
		}
	}
	for _, k := range connect.KnownTypes {
		if !discovered[k] {
			missingFromSwitch = append(missingFromSwitch, k)
		}
	}
	sort.Strings(missingFromRegistry)
	sort.Strings(missingFromSwitch)

	if len(missingFromRegistry) > 0 {
		t.Errorf("server/main.go's Connect-wiring switch has case(s) not present in connect.KnownTypes: %v\n"+
			"internal/config.Validate() would reject a connector with this Type before boot reaches the switch, "+
			"making the case dead code — add the type to connect.KnownTypes if it's genuinely supported.", missingFromRegistry)
	}
	if len(missingFromSwitch) > 0 {
		t.Errorf("connect.KnownTypes lists type(s) with no matching case in server/main.go's Connect-wiring switch: %v\n"+
			"A connector with this Type would pass cfg.Validate() but then hit the switch's Fatal default at boot — "+
			"add a case for it (with the right constructor call), or remove it from connect.KnownTypes.", missingFromSwitch)
	}
}

// TestInitializeCoreService_UnrecognizedConnectorType_FailsBoot is #1476's
// pairing test: before #1475 (cfg.Validate() at the top of
// initializeCoreService) landed, this config booted successfully — nothing
// called Validate() at all. Before THIS commit's validateConnectTypes existed,
// Validate() would run (once #1475 landed) but never inspect connector Type,
// so this would still boot successfully. Both preconditions are required for
// this test to fail as intended — that pairing is the point.
func TestInitializeCoreService_UnrecognizedConnectorType_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "typo-connector", Type: "aws-secrets-mangler", Scope: "platform"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an unrecognized connector type")
	}
	if !strings.Contains(err.Error(), "typo-connector") {
		t.Fatalf("expected error to name the offending connector, got: %v", err)
	}
}

// TestInitializeCoreService_UnrecognizedConnectorType_AggregatesMultiple
// confirms the boot-time error names every offending connector in one message,
// not just the first, and excludes a validly-typed connector from that list —
// mirroring validateConnectScopes's own aggregation behavior (ADR-082).
func TestInitializeCoreService_UnrecognizedConnectorType_AggregatesMultiple(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "bad1", Type: "bogus-type-1", Scope: "platform"},
			{Name: "bad2", Type: "bogus-type-2", Scope: "platform"},
			{Name: "ok", Type: "vault", Scope: "platform"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot")
	}
	for _, want := range []string{"bad1", "bad2"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected error to name %q, got: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), `"ok"`) {
		t.Fatalf("validly-typed connector must not appear in the error, got: %v", err)
	}
}

// discoverConnectorTypeSwitchCases walks file looking for a *ast.SwitchStmt whose
// tag is exactly `cn.Type` (matching server/main.go's Connect-wiring switch,
// `switch cn.Type { ... }`), and returns the set of string literal values across
// all of its non-default case clauses.
func discoverConnectorTypeSwitchCases(t *testing.T, file *ast.File) map[string]bool {
	t.Helper()
	discovered := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		sel, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Type" {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "cn" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cc.List { // nil List = the `default:` clause, skipped
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}
				discovered[val] = true
			}
		}
		return true
	})
	return discovered
}
