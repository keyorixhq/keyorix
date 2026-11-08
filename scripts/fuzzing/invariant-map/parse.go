package main

import (
	"path"
	"regexp"
	"strings"
)

var (
	defRe     = regexp.MustCompile(`^\s*(?:[-*]|\d+\.)?\s*\*\*(INV-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+)\*\*`)
	headingRe = regexp.MustCompile(`^#{2,6}\s+(.*\S)\s*$`)
	sectionRe = regexp.MustCompile(`<!--\s*section:\s*(.*?)\s*-->`)
	formatRe  = regexp.MustCompile("Format:\\s*`INV-([A-Z0-9]+)-")
	guardRe   = regexp.MustCompile(`Guards?\s*[:(]|Guarded by`)
	sevRe     = regexp.MustCompile(`(?i)\bSeverity:\s*(critical|high|medium|low)\b`)
)

// parsedDef is a definition before merging by ID.
type parsedDef struct {
	ID  string
	Def Def
	Dir string // package directory (parent of INVARIANTS.md / INVARIANTS.d)
}

// isDefFile reports whether rel is an invariant definition document and
// returns the package directory it belongs to.
func isDefFile(rel string) (pkgDir string, fragment bool, ok bool) {
	base := path.Base(rel)
	dir := path.Dir(rel)
	if base == "INVARIANTS.md" {
		if rel == "docs/INVARIANTS.md" {
			return "", false, false // the index, parsed separately
		}
		return dir, false, true
	}
	if path.Base(dir) == "INVARIANTS.d" && strings.HasSuffix(base, ".md") {
		return path.Dir(dir), true, true
	}
	return "", false, false
}

// parseDefs extracts every `**INV-...**` bullet from one definition document.
// An entry runs from its bullet line until the next line that is neither blank
// nor indented.
func parseDefs(rel string, content string, pkgDir string, fragment bool) []parsedDef {
	lines := strings.Split(content, "\n")
	var out []parsedDef
	section := ""
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if m := headingRe.FindStringSubmatch(l); m != nil && !fragment {
			section = m[1]
			continue
		}
		if m := sectionRe.FindStringSubmatch(l); m != nil {
			section = m[1]
			continue
		}
		m := defRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		j := i + 1
		for j < len(lines) {
			t := lines[j]
			if strings.TrimSpace(t) == "" || t[0] == ' ' || t[0] == '\t' {
				j++
				continue
			}
			break
		}
		text := strings.TrimRight(strings.Join(lines[i:j], "\n"), " \n\t")
		out = append(out, parsedDef{
			ID:  m[1],
			Dir: pkgDir,
			Def: Def{File: rel, Line: i + 1, Fragment: fragment, Section: section, Text: text},
		})
		i = j - 1
	}
	return out
}

// declaredPrefix returns the package prefix a legacy INVARIANTS.md declares in
// its `Format: INV-<PKG>-NN` line, or "".
func declaredPrefix(content string) string {
	if m := formatRe.FindStringSubmatch(content); m != nil {
		return m[1]
	}
	return ""
}

// idPrefix returns the PKG component of INV-<PKG>-....
func idPrefix(id string) string {
	p := strings.SplitN(id, "-", 3)
	if len(p) < 2 {
		return ""
	}
	return p[1]
}

var mdNoise = regexp.MustCompile("[*`]")

// statementOf renders a short plain-text statement: the rule up to the first
// "Why:" / "Guard" marker, markdown stripped, whitespace collapsed, capped.
func statementOf(id, text string) string {
	t := strings.TrimSpace(text)
	if k := strings.Index(t, "**"+id+"**"); k >= 0 {
		t = t[k+len(id)+4:]
	}
	if k := strings.Index(t, " Why:"); k >= 0 {
		t = t[:k]
	}
	if loc := guardRe.FindStringIndex(t); loc != nil {
		t = t[:loc[0]]
	}
	t = mdNoise.ReplaceAllString(t, "")
	t = strings.Join(strings.Fields(t), " ")
	const max = 320
	if len(t) > max {
		t = t[:max]
		if k := strings.LastIndex(t, " "); k > 200 {
			t = t[:k]
		}
		t += "..."
	}
	return t
}

// guardText returns the part of an entry after its Guard marker ("" if none).
func guardText(text string) string {
	loc := guardRe.FindStringIndex(text)
	if loc == nil {
		return ""
	}
	return text[loc[0]:]
}

var (
	backtickRe = regexp.MustCompile("`([^`\n]+)`")
	symbolRe   = regexp.MustCompile(`\b((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]+)([*…]?)`)
	pathTokRe  = regexp.MustCompile(`[A-Za-z0-9_./\-]+\.(?:go|ts|tsx|sh|yml|yaml|mjs|tsv|py)\b`)
)

// guardRefs extracts the checks an entry's Guard text names: Go test/fuzz/
// benchmark symbols (a trailing * or … makes it a prefix) and file paths. Only
// backticked spans are considered.
func guardRefs(guard string) (symbols []symRef, files []string) {
	seenS := map[string]bool{}
	seenF := map[string]bool{}
	for _, m := range backtickRe.FindAllStringSubmatch(guard, -1) {
		span := m[1]
		for _, s := range symbolRe.FindAllStringSubmatch(span, -1) {
			k := s[1] + s[2]
			if !seenS[k] {
				seenS[k] = true
				symbols = append(symbols, symRef{Name: s[1], Prefix: s[2] != "" || strings.HasSuffix(s[1], "_")})
			}
		}
		for _, f := range pathTokRe.FindAllString(span, -1) {
			stem := strings.TrimSuffix(path.Base(f), path.Ext(f))
			if strings.Contains(f, "*") || seenF[f] || len(stem) < 3 || strings.HasPrefix(stem, "_") || strings.HasPrefix(stem, ".") {
				continue // wildcard or fragment like "_test.go", not a real file name
			}
			seenF[f] = true
			files = append(files, f)
		}
	}
	return
}

// symRef is a test/fuzz symbol named by a Guard clause.
type symRef struct {
	Name   string
	Prefix bool
}
