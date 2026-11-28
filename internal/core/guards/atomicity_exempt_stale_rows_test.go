package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// TestAtomicityExempt_EveryRowStillMatchesCode fails on a docs/atomicity-exempt.tsv
// row that no longer matches any code (R1.18, AUDIT-DISCLOSURE-NOV-1). The two
// atomicity checks only ask "is every hit listed?", never "is every listed row
// still a hit?", so a row outlived the fix that made its function atomic (or its
// rename, or its deletion) and kept pardoning whatever that name came to mean.
//
// What a row must still match, by key namespace:
//   - plain "(*R).fn" and "JIT:(*R).fn": a hit of
//     TestAtomicityGuard_UnclassifiedMultiWriteFunction (scanAtomicityHits),
//     except a class-B (consume-first) row, which only needs the method to be
//     declared: server/faultops' oracle exemptions rest on its class
//     (TestConsumeFirstExemptions_MatchAtomicityLedger, login_fault_classes_test.go)
//     whether or not its writes still show up as 2+ to this scan;
//   - "AUDIT:(*R).fn": a hit of TestAtomicityGuard_AuditBeforeWrite
//     (scanAuditBeforeWriteHits);
//   - "CONSUME:(*R).fn": a method still declared in the core family (the
//     consume-first oracle exemption in server/faultops reads it; the scan has no
//     consume-first notion to check it against);
//   - any other namespace: refused.
//
// It does not judge whether a still-matching row's class or reason is right (the
// review sidecar, TestExemptLedgers_EveryRowIndependentlyReviewed, covers who read
// it), and it sees only what the two scanners see (their doc comments list their
// blind spots).
func TestAtomicityExempt_EveryRowStillMatchesCode(t *testing.T) {
	g := guardrules.Rollout(t)
	files := coreFamilySources(t)

	writeHits := map[string]bool{}
	for _, h := range scanAtomicityHits(t, files) {
		writeHits[h.fn] = true
	}
	auditHits := map[string]bool{}
	for _, h := range scanAuditBeforeWriteHits(t, files) {
		auditHits[h.fn] = true
	}
	declared := declaredGuardedMethods(t, files)

	const ledger = "../../../docs/atomicity-exempt.tsv"
	for _, row := range atomicityLedgerRows(t, ledger) {
		key := row.key
		ns, fn := "", key
		if i := strings.Index(key, ":"); i > 0 && !strings.HasPrefix(key, "(") {
			ns, fn = key[:i], key[i+1:]
		}
		var ok bool
		var want string
		switch {
		case ns == "" && row.class == "B":
			ok, want = declared[fn], "a declared *KeyorixCore/*AnomalyDetector method"
		case ns == "", ns == "JIT":
			ok, want = writeHits[fn], "a function with 2+ storage/core writes outside WithTransaction"
		case ns == "AUDIT":
			ok, want = auditHits[fn], "a function whose success audit precedes a later storage write"
		case ns == "CONSUME":
			ok, want = declared[fn], "a declared *KeyorixCore/*AnomalyDetector method"
		default:
			g.Errorf("%s: row %q has unknown key namespace %q (known: plain, JIT:, AUDIT:, CONSUME:)", ledger, key, ns)
			continue
		}
		if !ok {
			g.Errorf("%s: stale row %q: %s is no longer %s. Delete the row and its "+
				"docs/atomicity-exempt.reviewed.d/ sidecar file (or, if the function was renamed, re-key both)",
				ledger, key, fn, want)
		}
	}
}

type atomicityLedgerRow struct{ key, class string }

// atomicityLedgerRows returns the key and class of every row of the ledger.
func atomicityLedgerRows(t *testing.T, path string) []atomicityLedgerRow {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	var rows []atomicityLedgerRow
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			t.Fatalf("%s: malformed row %q", path, line)
		}
		rows = append(rows, atomicityLedgerRow{key: fields[0], class: fields[1]})
	}
	if len(rows) == 0 {
		t.Fatalf("%s: no rows read: wrong path or format", path)
	}
	return rows
}

// declaredGuardedMethods lists "(*R).fn" for every method on the two receivers the
// atomicity scanners walk.
func declaredGuardedMethods(t *testing.T, files []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, p := range files {
		if strings.Contains(filepath.Base(p), "generated") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("cannot parse %s: %v", p, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				continue
			}
			recv := atomicityExprStr(fd.Recv.List[0].Type)
			if recv == "*KeyorixCore" || recv == "*AnomalyDetector" {
				out["("+recv+")."+fd.Name.Name] = true
			}
		}
	}
	return out
}
