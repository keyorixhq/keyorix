package main

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const maxEvidence = 25

// Analyze scans root and builds the report. skipSelf excludes this tool's own
// directory (set for the real repo, unset for fixtures).
func Analyze(root string, skipSelf bool) (*Report, error) {
	ix, err := walk(root, skipSelf)
	if err != nil {
		return nil, err
	}

	// Merge definitions by ID.
	byID := map[string]*Invariant{}
	pkgOf := map[string]string{}
	texts := map[string][]string{}
	var order []string
	for _, pd := range ix.defs {
		inv := byID[pd.ID]
		if inv == nil {
			inv = &Invariant{ID: pd.ID}
			byID[pd.ID] = inv
			order = append(order, pd.ID)
			pkgOf[pd.ID] = pd.Dir
		}
		inv.Defs = append(inv.Defs, pd.Def)
		texts[pd.ID] = append(texts[pd.ID], pd.Def.Text)
	}
	defined := map[string]bool{}
	for id := range byID {
		defined[id] = true
	}
	ix.collectMentions(defined)

	// Evidence from mentions.
	unknown := map[string]*UnknownRef{}
	refCount := map[string]int{}
	spanCache := map[string][]funcSpan{}
	for _, m := range ix.mentions {
		if defined[m.ID] {
			refCount[m.ID]++
		}
		_, isDef := isDefFile2(m.File)
		kind := fileKind(m.File)
		if !defined[m.ID] {
			u := unknown[m.ID]
			if u == nil {
				u = &UnknownRef{ID: m.ID}
				unknown[m.ID] = u
			}
			u.RefsTotal++
			if kind != "doc" && !isDef {
				u.InCode = true
			}
			if len(u.Refs) < 10 {
				u.Refs = append(u.Refs, RefLoc{m.File, m.Line})
			}
			continue
		}
		inv := byID[m.ID]
		var ev *Evidence
		switch kind {
		case "fuzz-conf":
			name := confTargetAfter(ix.fileData[m.File].Content, m.Line)
			ev = &Evidence{Kind: "fuzz", Strength: "strong", Source: "ref", File: m.File, Line: m.Line, Name: name}
			if name != "" {
				ok := ix.fuzzFuncs[name] != nil
				if !ok {
					inv.StaleChecks = appendUniq(inv.StaleChecks, "targets.d names missing fuzz func "+name)
					continue
				}
				r := ix.isRegistered(name)
				ev.Registered = &r
			}
		case "go-test", "go-src":
			fc := ix.fileData[m.File].Content
			sp, ok := spanCache[m.File]
			if !ok {
				sp = spans(m.File, fc)
				spanCache[m.File] = sp
			}
			own, has := owner(sp, m.Line)
			lowerPath := strings.ToLower(m.File)
			switch {
			case strings.Contains(lowerPath, "/fuzzutil/") || strings.Contains(path.Base(lowerPath), "oracle") || strings.Contains(lowerPath, "/oracle"):
				ev = &Evidence{Kind: "fuzz", Strength: "strong", Source: "ref", File: m.File, Line: m.Line, Name: ownerName(own, has)}
			case has && strings.HasPrefix(own.Name, "Fuzz"):
				r := ix.isRegistered(own.Name)
				ev = &Evidence{Kind: "fuzz", Strength: "strong", Source: "ref", File: m.File, Line: m.Line, Name: own.Name, Registered: &r}
			case has && strings.HasPrefix(own.Name, "Test"):
				ev = &Evidence{Kind: "test", Source: "ref", File: m.File, Line: m.Line, Name: own.Name}
			case kind == "go-test" && ix.fuzzFiles[m.File]:
				ev = &Evidence{Kind: "fuzz", Strength: "file", Source: "ref", File: m.File, Line: m.Line, Name: ownerName(own, has)}
			case kind == "go-test":
				ev = &Evidence{Kind: "test", Source: "ref", File: m.File, Line: m.Line, Name: ownerName(own, has)}
			default:
				continue // production source comment: not a check
			}
		case "script", "ci", "ts-test", "ledger":
			ev = &Evidence{Kind: "test", Source: "ref", File: m.File, Line: m.Line}
		default:
			continue // docs and other prose are not checks
		}
		inv.EvidenceTotal++
		inv.Evidence = append(inv.Evidence, *ev)
	}

	// Doc-declared guards.
	for _, id := range order {
		inv := byID[id]
		pkg := pkgOf[id]
		for _, t := range texts[id] {
			if strings.Contains(t, "UNGUARDED") {
				inv.Unguarded = true
			}
			g := guardText(t)
			if g == "" {
				continue
			}
			inv.HasGuardText = true
			syms, files := guardRefs(g)
			for _, s := range syms {
				label := s.Name
				if s.Prefix {
					label += "*"
				}
				if !ix.funcExists(s) {
					inv.StaleChecks = appendUniq(inv.StaleChecks, label)
					continue
				}
				if strings.HasPrefix(s.Name, "Fuzz") {
					r := ix.isRegistered(s.Name)
					inv.Evidence = append(inv.Evidence, Evidence{Kind: "fuzz", Strength: "strong", Source: "guard", Name: s.Name, Registered: &r})
				} else {
					inv.Evidence = append(inv.Evidence, Evidence{Kind: "test", Source: "guard", Name: s.Name})
				}
				inv.EvidenceTotal++
			}
			for _, f := range files {
				if !ix.fileExists(f, pkg) {
					inv.StaleChecks = appendUniq(inv.StaleChecks, f)
					continue
				}
				inv.Evidence = append(inv.Evidence, Evidence{Kind: "test", Source: "guard", File: f})
				inv.EvidenceTotal++
			}
		}
	}

	// Classify, score, flag.
	rep := &Report{Schema: 1}
	sum := &rep.Summary
	sum.ByClass = map[string]int{ClassFuzz: 0, ClassTest: 0, ClassDocOnly: 0}
	areaTally := map[string]*AreaCount{}
	sort.Strings(order)
	for _, id := range order {
		inv := byID[id]
		inv.Area = pkgOf[id]
		if inv.Area == "" {
			inv.Area = "."
		}
		inv.Section = inv.Defs[0].Section
		inv.Statement = statementOf(id, texts[id][0])
		inv.Severity, inv.SecurityScore = severity(inv, texts[id])
		sort.SliceStable(inv.Evidence, func(i, j int) bool { return evLess(inv.Evidence[i], inv.Evidence[j]) })
		if len(inv.Evidence) > maxEvidence {
			inv.Evidence = inv.Evidence[:maxEvidence]
		}
		sort.Strings(inv.StaleChecks)
		classify(inv)
		if len(inv.Defs) > 1 {
			inv.Flags = append(inv.Flags, "duplicate-id")
			sum.Duplicates++
		}
		if pfx := ix.prefixes[pkgOf[id]]; pfx != "" && idPrefix(id) != pfx {
			inv.Flags = append(inv.Flags, "prefix-mismatch")
		}
		for _, d := range inv.Defs {
			if d.Fragment && strings.TrimSuffix(path.Base(d.File), ".md") != id {
				inv.Flags = append(inv.Flags, "filename-mismatch")
				break
			}
		}
		if len(inv.StaleChecks) > 0 {
			inv.Flags = append(inv.Flags, "stale-check")
			sum.WithStale++
		}
		if inv.Class == ClassFuzz && allUnregistered(inv) {
			inv.Flags = append(inv.Flags, "fuzz-unregistered")
		}
		if inv.Unguarded {
			sum.Unguarded++
		}
		sort.Strings(inv.Flags)
		sum.ByClass[inv.Class]++
		if inv.Class == ClassFuzz && inv.FuzzStrength == "file" {
			sum.FuzzFileOnly++
		}
		at := areaTally[inv.Area]
		if at == nil {
			at = &AreaCount{Area: inv.Area}
			areaTally[inv.Area] = at
		}
		at.Total++
		switch inv.Class {
		case ClassFuzz:
			at.Fuzz++
		case ClassTest:
			at.Test++
		default:
			at.DocOnly++
		}
		rep.Invariants = append(rep.Invariants, *inv)
	}
	sum.Invariants = len(rep.Invariants)
	areas := make([]string, 0, len(areaTally))
	for a := range areaTally {
		areas = append(areas, a)
	}
	sort.Strings(areas)
	for _, a := range areas {
		rep.ByArea = append(rep.ByArea, *areaTally[a])
	}

	// Unknown refs, with rename/typo suggestions.
	ids := make([]string, 0, len(unknown))
	for id := range unknown {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := unknown[id]
		u.Suggestion = nearest(id, order)
		rep.UnknownRefs = append(rep.UnknownRefs, *u)
	}
	sum.Unknown = len(rep.UnknownRefs)

	rep.Inconsistency = inconsistencies(rep.Invariants, order, refCount, rep.UnknownRefs)
	rep.IndexMismatch = indexMismatch(ix.indexDoc, rep.Invariants)
	rep.Ledger = ledger(ix)
	for _, r := range rep.Ledger {
		sum.LedgerRows++
		if r.Class == "STALE" {
			sum.LedgerStale++
		}
	}
	sum.FuzzTargets = len(ix.registered)
	return rep, nil
}

func isDefFile2(rel string) (string, bool) {
	p, _, ok := isDefFile(rel)
	return p, ok
}

func ownerName(s funcSpan, ok bool) string {
	if ok {
		return s.Name
	}
	return ""
}

func appendUniq(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func allUnregistered(inv *Invariant) bool {
	any := false
	for _, e := range inv.Evidence {
		if e.Kind == "fuzz" && e.Strength == "strong" && e.Registered != nil {
			any = true
			if *e.Registered {
				return false
			}
		}
		if e.Kind == "fuzz" && e.Strength == "strong" && e.Registered == nil {
			return false // oracle code: no target to register
		}
	}
	return any
}

func evLess(a, b Evidence) bool {
	if a.Kind != b.Kind {
		return a.Kind == "fuzz"
	}
	if a.Strength != b.Strength {
		return a.Strength == "strong"
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.File != b.File {
		return a.File < b.File
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Name < b.Name
}

// classify sets Class and FuzzStrength from existing (non-stale) evidence.
func classify(inv *Invariant) {
	strong, file, test := false, false, false
	for _, e := range inv.Evidence {
		switch {
		case e.Kind == "fuzz" && e.Strength == "strong":
			strong = true
		case e.Kind == "fuzz":
			file = true
		default:
			test = true
		}
	}
	// The evidence list is capped; recompute from totals is unnecessary since
	// sorting puts strong fuzz first, so the cap never hides a class.
	switch {
	case strong:
		inv.Class, inv.FuzzStrength = ClassFuzz, "strong"
	case file:
		inv.Class, inv.FuzzStrength = ClassFuzz, "file"
	case test:
		inv.Class = ClassTest
	default:
		inv.Class = ClassDocOnly
	}
}

var confTargetRe = regexp.MustCompile(`^\s*([^#|\s][^|]*)\|([A-Za-z0-9_]+)\|`)

// confTargetAfter returns the Fuzz func of the first target line at or after
// the given 1-based line in a targets.d file ("" if none).
func confTargetAfter(content string, line int) string {
	lines := strings.Split(content, "\n")
	for i := line - 1; i < len(lines); i++ {
		if m := confTargetRe.FindStringSubmatch(lines[i]); m != nil {
			return m[2]
		}
	}
	// Mention after the last target line: fall back to the last target.
	for _, l := range slices.Backward(lines) {
		if m := confTargetRe.FindStringSubmatch(l); m != nil {
			return m[2]
		}
	}
	return ""
}

// fileKind classifies a file that mentions an ID.
func fileKind(rel string) string {
	ext := strings.ToLower(path.Ext(rel))
	switch {
	case strings.HasPrefix(rel, "scripts/fuzzing/targets.d/") && ext == ".conf", rel == "scripts/fuzzing/targets.conf":
		return "fuzz-conf"
	case ext == ".go" && strings.HasSuffix(rel, "_test.go"):
		return "go-test"
	case ext == ".go":
		return "go-src"
	case ext == ".yml" || ext == ".yaml":
		if strings.HasPrefix(rel, ".github/") || strings.HasPrefix(rel, "scripts/") {
			return "ci"
		}
		return "doc"
	case ext == ".sh" || ext == ".bash" || ext == ".py":
		return "script"
	case ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".mjs":
		if testSufRe.MatchString(rel) {
			return "ts-test"
		}
		return "ts-src"
	case ext == ".tsv":
		return "ledger"
	}
	return "doc"
}

// ---- ledger -----------------------------------------------------------

var splitTests = regexp.MustCompile(`[,;|+\s]+`)

func ledger(ix *index) []LedgerRow {
	var out []LedgerRow
	sort.Slice(ix.ledgers, func(i, j int) bool { return ix.ledgers[i].Rel < ix.ledgers[j].Rel })
	for _, lf := range ix.ledgers {
		for l := range strings.SplitSeq(lf.Content, "\n") {
			if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
				continue
			}
			f := strings.Split(l, "\t")
			if len(f) < 4 || f[0] == "claim_id" {
				continue
			}
			row := LedgerRow{Claim: f[0], File: lf.Rel}
			tests := strings.TrimSpace(f[2])
			if tests == "" || tests == "-" {
				row.Class = "MANUAL"
				out = append(out, row)
				continue
			}
			class := "TEST"
			for _, t := range splitTests.Split(tests, -1) {
				t = strings.TrimSpace(strings.SplitN(t, "/", 2)[0])
				if t == "" || t == "-" {
					continue
				}
				row.Tests = append(row.Tests, t)
				if _, ok := ix.funcDirs[t]; !ok {
					row.Missing = append(row.Missing, t)
				} else if strings.HasPrefix(t, "Fuzz") && class == "TEST" {
					class = "FUZZ"
				}
			}
			if len(row.Missing) > 0 {
				class = "STALE"
			}
			row.Class = class
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Claim != out[j].Claim {
			return out[i].Claim < out[j].Claim
		}
		return out[i].File < out[j].File
	})
	return out
}

// ---- inconsistencies --------------------------------------------------

func inconsistencies(invs []Invariant, order []string, refCount map[string]int, unknown []UnknownRef) []Inconsistency {
	var out []Inconsistency
	for _, inv := range invs {
		if len(inv.Defs) > 1 {
			var where []string
			for _, d := range inv.Defs {
				where = append(where, fmt.Sprintf("%s:%d", d.File, d.Line))
			}
			d := fmt.Sprintf("defined %d times (%s)", len(inv.Defs), strings.Join(where, ", "))
			if n := refCount[inv.ID]; n > 0 {
				d += fmt.Sprintf("; %d references cannot tell which rule they mean", n)
			}
			out = append(out, Inconsistency{"duplicate-id", []string{inv.ID}, d})
		}
		for _, f := range inv.Flags {
			if f == "prefix-mismatch" || f == "filename-mismatch" {
				out = append(out, Inconsistency{f, []string{inv.ID}, "ID does not match its package prefix / fragment file name (" + inv.Defs[0].File + ")"})
			}
		}
	}
	// Near-duplicate IDs: same prefix, normalised-equal or tiny edit distance.
	for i := range order {
		for j := i + 1; j < len(order); j++ {
			a, b := order[i], order[j]
			if idPrefix(a) != idPrefix(b) || isNumeric(a) || isNumeric(b) {
				continue
			}
			na, nb := strings.ReplaceAll(a, "-", ""), strings.ReplaceAll(b, "-", "")
			if na == nb || (len(a) > 20 && lev(a, b) <= 2) {
				out = append(out, Inconsistency{"near-duplicate", []string{a, b}, "IDs differ only trivially; one may be a rename or typo of the other"})
			}
		}
	}
	for _, u := range unknown {
		if u.Suggestion != "" {
			out = append(out, Inconsistency{"possible-rename", []string{u.ID, u.Suggestion}, "referenced ID is undefined; closest defined ID suggested"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return strings.Join(out[i].IDs, ",") < strings.Join(out[j].IDs, ",")
	})
	return out
}

var numTail = regexp.MustCompile(`-\d+[a-z]?$`)

func isNumeric(id string) bool { return numTail.MatchString(id) }

// nearest returns the defined ID closest to id (edit distance <= 3, same
// prefix), or "".
func nearest(id string, defined []string) string {
	best, bd := "", 4
	for _, d := range defined {
		if idPrefix(d) != idPrefix(id) {
			continue
		}
		if x := lev(id, d); x < bd {
			best, bd = d, x
		}
	}
	return best
}

func lev(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			c := 1
			if ra[i-1] == rb[j-1] {
				c = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// ---- docs/INVARIANTS.md index cross-check ------------------------------

var indexRowRe = regexp.MustCompile("^\\|\\s*`?([^|`]+?)`?[^|]*\\|\\s*\\[([^\\]]+)\\]\\([^)]*\\)\\s*\\|\\s*(\\d+)\\s*\\|")

func indexMismatch(doc string, invs []Invariant) []string {
	if doc == "" {
		return nil
	}
	counts := map[string]int{}
	for _, inv := range invs {
		counts[inv.Area+"/INVARIANTS.md"]++
	}
	var out []string
	for l := range strings.SplitSeq(doc, "\n") {
		m := indexRowRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		want, _ := strconv.Atoi(m[3])
		got := counts[m[2]]
		if got != want {
			out = append(out, fmt.Sprintf("%s: index says %d, docs define %d distinct IDs", m[2], want, got))
		}
	}
	sort.Strings(out)
	return out
}
