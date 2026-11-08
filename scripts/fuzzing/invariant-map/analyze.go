package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// skipDirs are never walked.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "coverage": true,
}

// selfDir is excluded when analysing the real repository so the tool's own
// fixtures and examples never count as references.
const selfDir = "scripts/fuzzing/invariant-map"

const maxFileSize = 2 << 20

var (
	idRe      = regexp.MustCompile(`\bINV-[A-Z][A-Z0-9]*(?:-[A-Za-z0-9]+)+`)
	idUndRe   = regexp.MustCompile(`\bINV_[A-Z][A-Z0-9]*_[0-9]+[a-z]?\b`)
	funcRe    = regexp.MustCompile(`(?m)^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)`)
	fuzzDecl  = regexp.MustCompile(`(?m)^func\s+Fuzz[A-Za-z0-9_]*\s*\(`)
	testSufRe = regexp.MustCompile(`\.test\.(?:ts|tsx|js|mjs)$|(?:^|/)__tests__/|(?:^|/)e2e/|\.spec\.(?:ts|tsx|js)$`)
)

// fileInfo is one scanned file.
type fileInfo struct {
	Rel     string
	Content string
}

// mention is one occurrence of an ID in a non-definition file.
type mention struct {
	ID   string
	File string
	Line int
	Raw  string // as written, before shortening
}

// funcSpan is a Go func declaration's extent (doc comment included).
type funcSpan struct {
	Name       string
	Start, End int
}

// index holds everything learned from one pass over the tree.
type index struct {
	files      []string            // every walked file (rel)
	baseNames  map[string][]string // basename -> rels
	pathSet    map[string]bool
	funcDirs   map[string]map[string]bool // func name -> dirs declaring it
	fuzzFuncs  map[string]map[string]bool // Fuzz func name -> dirs
	fuzzFiles  map[string]bool            // go files declaring a Fuzz func
	registered map[string]bool            // "dir|FuzzName" listed in targets.d / targets.conf
	targetDirs map[string]bool
	defs       []parsedDef
	prefixes   map[string]string // pkg dir -> declared prefix
	mentions   []mention
	defFiles   map[string]bool
	fileData   map[string]*fileInfo // only files containing INV- or targets
	indexDoc   string               // docs/INVARIANTS.md content
	ledgers    []ledgerFile
	targetsRaw []fileInfo
}

type ledgerFile struct {
	Rel     string
	Content string
}

func newIndex() *index {
	return &index{
		baseNames:  map[string][]string{},
		pathSet:    map[string]bool{},
		funcDirs:   map[string]map[string]bool{},
		fuzzFuncs:  map[string]map[string]bool{},
		fuzzFiles:  map[string]bool{},
		registered: map[string]bool{},
		targetDirs: map[string]bool{},
		prefixes:   map[string]string{},
		defFiles:   map[string]bool{},
		fileData:   map[string]*fileInfo{},
	}
}

func scannable(rel string) bool {
	switch strings.ToLower(path.Ext(rel)) {
	case ".go", ".sh", ".bash", ".yml", ".yaml", ".ts", ".tsx", ".js", ".mjs", ".py", ".tsv", ".conf", ".txt", ".md":
		return true
	}
	base := path.Base(rel)
	return base == "Makefile" || base == "Taskfile.yml"
}

// walk reads the tree once.
func walk(root string, skipSelf bool) (*index, error) {
	ix := newIndex()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] || (skipSelf && rel == selfDir) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		ix.files = append(ix.files, rel)
		ix.pathSet[rel] = true
		ix.baseNames[path.Base(rel)] = append(ix.baseNames[path.Base(rel)], rel)
		if !scannable(rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- read-only scan of the operator-chosen checkout; symlinks are skipped and nothing is written
		if err != nil {
			return nil
		}
		ix.ingest(rel, string(b))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(ix.files)
	sort.Slice(ix.defs, func(i, j int) bool {
		a, b := ix.defs[i], ix.defs[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Def.File != b.Def.File {
			return a.Def.File < b.Def.File
		}
		return a.Def.Line < b.Def.Line
	})
	return ix, nil
}

func (ix *index) ingest(rel, content string) {
	dir := path.Dir(rel)
	if strings.HasSuffix(rel, ".go") {
		for _, m := range funcRe.FindAllStringSubmatch(content, -1) {
			if ix.funcDirs[m[1]] == nil {
				ix.funcDirs[m[1]] = map[string]bool{}
			}
			ix.funcDirs[m[1]][dir] = true
			if strings.HasPrefix(m[1], "Fuzz") && fuzzDecl.MatchString("func "+m[1]+"(") {
				if ix.fuzzFuncs[m[1]] == nil {
					ix.fuzzFuncs[m[1]] = map[string]bool{}
				}
				ix.fuzzFuncs[m[1]][dir] = true
			}
		}
		if fuzzDecl.MatchString(content) {
			ix.fuzzFiles[rel] = true
		}
	}
	if rel == "docs/INVARIANTS.md" {
		ix.indexDoc = content
	}
	if strings.HasPrefix(rel, "scripts/fuzzing/targets.d/") && strings.HasSuffix(rel, ".conf") || rel == "scripts/fuzzing/targets.conf" {
		ix.targetsRaw = append(ix.targetsRaw, fileInfo{rel, content})
		ix.registerTargets(content)
	}
	if rel == "docs/adr-conformance-enforced.tsv" || (strings.HasPrefix(rel, "docs/security-closures.d/") && strings.HasSuffix(rel, ".tsv")) || rel == "docs/security-closures.tsv" {
		ix.ledgers = append(ix.ledgers, ledgerFile{rel, content})
	}
	if pkg, frag, ok := isDefFile(rel); ok {
		ix.defFiles[rel] = true
		if !frag {
			if p := declaredPrefix(content); p != "" {
				ix.prefixes[pkg] = p
			}
		}
		ix.defs = append(ix.defs, parseDefs(rel, content, pkg, frag)...)
		// Definition documents also cross-reference other IDs; keep them for
		// unknown-ID detection (as doc mentions).
		ix.fileData[rel] = &fileInfo{rel, content}
		return
	}
	if strings.Contains(content, "INV-") || strings.Contains(content, "INV_") {
		ix.fileData[rel] = &fileInfo{rel, content}
	}
}

// registerTargets records "pkgdir|FuzzName" for each target line.
func (ix *index) registerTargets(content string) {
	for l := range strings.SplitSeq(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "|")
		if len(f) < 2 {
			continue
		}
		dir := strings.TrimPrefix(strings.TrimSpace(f[0]), "./")
		ix.registered[dir+"|"+strings.TrimSpace(f[1])] = true
	}
}

func (ix *index) isRegistered(name string) bool {
	for d := range ix.fuzzFuncs[name] {
		if ix.registered[d+"|"+name] {
			return true
		}
	}
	return false
}

// funcExists reports whether a Go func with this name (or, for prefixes, any
// func starting with it) is declared anywhere in the tree.
func (ix *index) funcExists(s symRef) bool {
	if !s.Prefix {
		_, ok := ix.funcDirs[s.Name]
		return ok
	}
	for n := range ix.funcDirs {
		if strings.HasPrefix(n, s.Name) {
			return true
		}
	}
	return false
}

// fileExists resolves a Guard-named file relative to the repo root, the
// package directory, or (as a last resort) by basename anywhere.
func (ix *index) fileExists(tok, pkgDir string) bool {
	tok = strings.TrimPrefix(tok, "./")
	if ix.pathSet[tok] || ix.pathSet[path.Join(pkgDir, tok)] {
		return true
	}
	for _, r := range ix.baseNames[path.Base(tok)] {
		if r == tok || strings.HasSuffix(r, "/"+tok) {
			return true
		}
	}
	return false
}

// collectMentions scans every non-definition file for IDs, resolving each
// against the set of defined IDs.
func (ix *index) collectMentions(defined map[string]bool) {
	rels := make([]string, 0, len(ix.fileData))
	for r := range ix.fileData {
		rels = append(rels, r)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		fi := ix.fileData[rel]
		lines := strings.Split(fi.Content, "\n")
		for i, l := range lines {
			if !strings.Contains(l, "INV") {
				continue
			}
			for _, raw := range idRe.FindAllString(l, -1) {
				if isPlaceholder(raw) {
					continue
				}
				id := resolveID(raw, defined)
				ix.mentions = append(ix.mentions, mention{ID: id, File: rel, Line: i + 1, Raw: raw})
			}
			for _, raw := range idUndRe.FindAllString(l, -1) {
				id := strings.ReplaceAll(raw, "_", "-")
				if defined[id] {
					ix.mentions = append(ix.mentions, mention{ID: id, File: rel, Line: i + 1, Raw: raw})
				}
			}
		}
	}
}

// isPlaceholder reports whether raw is a format placeholder such as
// "INV-<PKG>-NN" written as INV-CORE-NN, not an invariant reference.
func isPlaceholder(raw string) bool {
	switch raw[strings.LastIndex(raw, "-")+1:] {
	case "NN", "NNN", "XX", "XXX":
		return true
	}
	return false
}

// resolveID maps a raw token to a defined ID, dropping trailing "-word" parts
// when that yields one ("INV-CORE-41-style" -> "INV-CORE-41"). Unresolvable
// tokens are returned unchanged.
func resolveID(raw string, defined map[string]bool) string {
	cur := strings.TrimRight(raw, "-")
	for {
		if defined[cur] {
			return cur
		}
		k := strings.LastIndex(cur, "-")
		if k <= len("INV-X") || strings.Count(cur[:k], "-") < 2 {
			break
		}
		cur = cur[:k]
	}
	return raw
}

// spans parses a Go file and returns func extents (doc comment included).
func spans(rel, content string) []funcSpan {
	fset := token.NewFileSet()
	f, _ := parser.ParseFile(fset, rel, content, parser.ParseComments|parser.SkipObjectResolution)
	if f == nil {
		return nil
	}
	var out []funcSpan
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		start := fd.Pos()
		if fd.Doc != nil {
			start = fd.Doc.Pos()
		}
		out = append(out, funcSpan{fd.Name.Name, fset.Position(start).Line, fset.Position(fd.End()).Line})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// owner finds the func a line belongs to: enclosing, else the next func that
// starts within 5 lines (a detached leading comment).
func owner(sp []funcSpan, line int) (funcSpan, bool) {
	for _, s := range sp {
		if line >= s.Start && line <= s.End {
			return s, true
		}
	}
	for _, s := range sp {
		if s.Start > line && s.Start-line <= 5 {
			return s, true
		}
	}
	return funcSpan{}, false
}
