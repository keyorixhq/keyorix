// Command familycheck implements the implementation-asymmetry scan's preventive
// control: given a family list computed at a PR's base and head commits, plus
// the PR's changed files and body text, it flags PRs that touch some-but-not-all
// members of a family (Mode A, non-blocking nudge) or add a brand-new member to
// an existing family (Mode B, blocking gate).
//
// See keyorix-private/adversarial-review/IMPLEMENTATION-ASYMMETRY-SCAN-2026-09-05.md
// for the method and finding history this is built to prevent from recurring
// (PR #1449 added a rotation-lock mutex to AWS's GenerateUpstream alone; PR #431
// pinned GCP's connector to a project ID alone -- both are 1-of-N family edits
// that should have prompted "did the siblings need this too?").
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type member struct {
	Type          string `json:"type"`
	Package       string `json:"package"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	IsPtrReceiver bool   `json:"is_ptr_receiver"`
}

func (m member) key() string { return m.Package + "." + m.Type }

type family struct {
	ID         string   `json:"id"`
	Interface  string   `json:"interface"`
	Package    string   `json:"package"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	NumMethods int      `json:"num_methods"`
	Members    []member `json:"members"`
}

// securityCategoryPatterns are deliberately broad -- a false-positive here
// only costs an extra non-blocking Mode A nudge (see -json's scope rule
// below), so recall matters more than precision.
var securityCategoryPatterns = regexp.MustCompile(strings.Join([]string{
	`\bnet\.Dial`, `DialContext\b`, `\burl\.Parse\b`, `Hostname\(\)`, `\bResolve\w*Addr\b`, // dial/DNS/URL
	`\btls\.Config\b`, `InsecureSkipVerify`, `\btls\.Dial`, `MinVersion`, // TLS
	`sync\.Mutex`, `sync\.RWMutex`, `sync\.Map`, `\.Lock\(\)`, `\.Unlock\(\)`, `[Ll]ockRef`, `[Aa]dvisoryLock`, // locking
	`[Aa]udit`,                                  // audit/security logging
	`[Vv]alidate`, `[Ss]anitiz`, `[Nn]ormalize`, // input validation
	`[Aa]uthoriz`, `\bauthz\b`, `[Tt]enant`, `allowedRefs`, `projectID`, `vaultURL`, // authz/tenant/scope
	`context\.WithTimeout`, `context\.WithDeadline`, `\.Deadline\(\)`, // context deadlines
	`[Cc]redential`, `[Ss]ecret`, `\bZero\(`, `[Ww]ipe`, `encContext`, `allowFallback`, // credential handling
}, "|"))

func main() {
	baseFamiliesPath := flag.String("base-families", "", "JSON family list at the PR's base commit")
	headFamiliesPath := flag.String("head-families", "", "JSON family list at the PR's head commit")
	changedFilesPath := flag.String("changed-files", "", "newline-separated repo-relative changed file paths")
	prBodyPath := flag.String("pr-body", "", "PR body text, for dismissal/confirmation markers")
	scopePath := flag.String("scope", "", "JSON array of allowlisted in-scope family IDs")
	repoRoot := flag.String("repo-root", ".", "repo root, for reading head-checkout file contents for the keyword scope test")
	flag.Parse()

	if *baseFamiliesPath == "" || *headFamiliesPath == "" || *changedFilesPath == "" {
		fmt.Fprintln(os.Stderr, "usage: familycheck -base-families f.json -head-families f.json -changed-files f.txt [-pr-body f.txt] [-scope f.json] [-repo-root .]")
		os.Exit(2)
	}

	baseFamilies := mustLoadFamilies(*baseFamiliesPath)
	headFamilies := mustLoadFamilies(*headFamiliesPath)
	changed := mustLoadLines(*changedFilesPath)
	prBody := ""
	if *prBodyPath != "" {
		// #nosec G304 -- path is always this CLI's own -pr-body flag, supplied
		// by the CI workflow that invokes this tool.
		b, err := os.ReadFile(*prBodyPath)
		if err == nil {
			prBody = string(b)
		}
	}
	scope := map[string]bool{}
	if *scopePath != "" {
		var ids []string
		mustLoadJSON(*scopePath, &ids)
		for _, id := range ids {
			scope[id] = true
		}
	}

	changedSet := map[string]bool{}
	for _, f := range changed {
		changedSet[f] = true
	}

	baseByID := map[string]family{}
	for _, f := range baseFamilies {
		baseByID[f.ID] = f
	}

	var modeAFindings []modeAFinding
	var modeBFindings []modeBFinding

	for _, fam := range headFamilies {
		var touched []member
		for _, m := range fam.Members {
			if changedSet[m.File] {
				touched = append(touched, m)
			}
		}
		if len(touched) == 0 {
			continue // this family wasn't touched by this PR at all
		}

		// Scope on the WHOLE family's current content, not just the touched
		// files: a brand-new member that's missing a control its siblings
		// have is, by definition, likely to NOT contain that control's
		// keyword -- scoping Mode B by the new file's own content would
		// systematically miss exactly the cases it exists to catch.
		inScope := scope[fam.ID] || anyFileMatchesSecurityCategory(*repoRoot, fam.Members)
		if !inScope {
			continue
		}

		baseFam, existedBefore := baseByID[fam.ID]
		baseMembers := map[string]bool{}
		if existedBefore {
			for _, m := range baseFam.Members {
				baseMembers[m.key()] = true
			}
		}

		var newMembers []member
		for _, m := range touched {
			if !baseMembers[m.key()] {
				newMembers = append(newMembers, m)
			}
		}

		if len(newMembers) > 0 {
			confirmed := hasMarker(prBody, "family-check: new-member-verified", fam.ID, fam.Interface)
			modeBFindings = append(modeBFindings, modeBFinding{fam: fam, newMembers: newMembers, confirmed: confirmed})
			continue // a family that fired Mode B doesn't also need Mode A noise
		}

		if len(touched) < len(fam.Members) {
			dismissed, reason := dismissalReason(prBody, "family-check: intentional", fam.ID, fam.Interface)
			modeAFindings = append(modeAFindings, modeAFinding{fam: fam, touched: touched, dismissed: dismissed, reason: reason})
		}
	}

	exitCode := render(modeAFindings, modeBFindings)
	os.Exit(exitCode)
}

type modeAFinding struct {
	fam       family
	touched   []member
	dismissed bool
	reason    string
}

type modeBFinding struct {
	fam        family
	newMembers []member
	confirmed  bool
}

// anyFileMatchesSecurityCategory reads each touched member's file at repoRoot
// (the head checkout) and checks for the security-category keyword patterns.
// Read errors are silent (fail open on the SCOPE test only -- a file that
// can't be read for the heuristic scope check still gets caught if it's in
// the explicit allowlist; this heuristic is a widener, not the sole gate).
func anyFileMatchesSecurityCategory(repoRoot string, touched []member) bool {
	seen := map[string]bool{}
	for _, m := range touched {
		if seen[m.File] {
			continue
		}
		seen[m.File] = true
		// #nosec G304 -- repoRoot is a CLI flag (the CI job's own checkout path)
		// and m.File comes from asymanalyzer's JSON, itself derived from real
		// on-disk positions go/packages resolved within that same checkout, not
		// from untrusted network input.
		b, err := os.ReadFile(filepath.Join(repoRoot, m.File))
		if err != nil {
			continue
		}
		if securityCategoryPatterns.Match(b) {
			return true
		}
	}
	return false
}

// hasMarker reports whether body contains a case-insensitive line starting
// with marker that also mentions id or name (so a marker for a DIFFERENT
// family doesn't accidentally suppress this one).
func hasMarker(body, marker, id, name string) bool {
	ok, _ := dismissalReason(body, marker, id, name)
	return ok
}

func dismissalReason(body, marker, id, name string) (bool, string) {
	lower := strings.ToLower(body)
	markerLower := strings.ToLower(marker)
	idx := strings.Index(lower, markerLower)
	if idx < 0 {
		return false, ""
	}
	// Take the rest of that line as the reason/scope; require it also names
	// this family (by id or interface name) so one marker can't blanket-
	// dismiss every family in a PR that touches several.
	lineEnd := strings.IndexByte(body[idx:], '\n')
	line := body[idx:]
	if lineEnd >= 0 {
		line = body[idx : idx+lineEnd]
	}
	lowerLine := strings.ToLower(line)
	if !strings.Contains(lowerLine, strings.ToLower(id)) && !strings.Contains(lowerLine, strings.ToLower(name)) {
		return false, ""
	}
	reason := strings.TrimSpace(strings.TrimPrefix(line, marker))
	reason = strings.TrimPrefix(strings.TrimSpace(reason), "—")
	reason = strings.TrimPrefix(strings.TrimSpace(reason), "-")
	return true, strings.TrimSpace(reason)
}

// render prints the Markdown report to stdout (for the CI job to post as a
// PR comment) and returns the process exit code: 0 unless an unconfirmed
// Mode B finding exists.
func render(modeA []modeAFinding, modeB []modeBFinding) int {
	exitCode := 0
	var sb strings.Builder

	var blockingB []modeBFinding
	for _, f := range modeB {
		if !f.confirmed {
			blockingB = append(blockingB, f)
		}
	}
	if len(blockingB) > 0 {
		exitCode = 1
		sb.WriteString("## 🔒 Family-membership check: new member added, confirmation required\n\n")
		for _, f := range blockingB {
			fmt.Fprintf(&sb, "**%s** (`%s`, %d existing member%s) gained a new member:\n\n",
				f.fam.Interface, f.fam.ID, len(f.fam.Members)-len(f.newMembers), plural(len(f.fam.Members)-len(f.newMembers)))
			for _, m := range f.newMembers {
				fmt.Fprintf(&sb, "- **new**: `%s` (%s)\n", m.Type, m.File)
			}
			sb.WriteString("\nExisting siblings — confirm the new member carries every security-relevant control each of these has (dial/DNS/TLS, locking, audit logging, input validation, authz/tenant checks, context deadlines, credential handling):\n\n")
			for _, m := range f.fam.Members {
				if memberIsNew(m, f.newMembers) {
					continue
				}
				fmt.Fprintf(&sb, "- `%s` (%s)\n", m.Type, m.File)
			}
			fmt.Fprintf(&sb, "\nTo unblock: add a line to the PR body naming this family, e.g.\n`family-check: new-member-verified — %s: <what you checked>`\n\n", f.fam.Interface)
		}
	}

	var activeA []modeAFinding
	for _, f := range modeA {
		if !f.dismissed {
			activeA = append(activeA, f)
		}
	}
	if len(activeA) > 0 {
		sb.WriteString("## ℹ️ Family-membership check: partial family edit\n\n")
		sb.WriteString("_Non-blocking — most single-member changes are legitimate. If this one is, dismiss it with a PR-body line (see below) so the dismissal leaves a trail instead of silence._\n\n")
		for _, f := range activeA {
			touchedFiles := memberFiles(f.touched)
			var untouched []member
			for _, m := range f.fam.Members {
				if !containsFile(f.touched, m.File) {
					untouched = append(untouched, m)
				}
			}
			fmt.Fprintf(&sb, "This PR modifies %s, %d of %d member%s of the **%s** family; %s %s not modified.\n",
				strings.Join(touchedFiles, ", "), len(f.touched), len(f.fam.Members), plural(len(f.fam.Members)), f.fam.Interface,
				strings.Join(memberFiles(untouched), ", "), wasWere(len(untouched)))
			fmt.Fprintf(&sb, "\nIf intentional: `family-check: intentional — %s: <reason>`\n\n", f.fam.Interface)
		}
	}

	for _, f := range modeA {
		if f.dismissed {
			fmt.Fprintf(&sb, "(dismissed: %s — %q)\n", f.fam.Interface, f.reason)
		}
	}
	for _, f := range modeB {
		if f.confirmed {
			fmt.Fprintf(&sb, "(new member confirmed: %s)\n", f.fam.Interface)
		}
	}

	if sb.Len() == 0 {
		// Nothing to say: leave stdout (the PR-comment body) empty so the
		// caller can skip posting, but still log status for the CI run.
		fmt.Fprintln(os.Stderr, "family-membership check: no in-scope family asymmetries on this PR")
		return 0
	}
	fmt.Print(sb.String())
	return exitCode
}

func memberIsNew(m member, newMembers []member) bool {
	for _, nm := range newMembers {
		if nm.key() == m.key() {
			return true
		}
	}
	return false
}

func memberFiles(ms []member) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.File)
	}
	sort.Strings(out)
	return out
}

func containsFile(ms []member, file string) bool {
	for _, m := range ms {
		if m.File == file {
			return true
		}
	}
	return false
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

func mustLoadFamilies(path string) []family {
	var fams []family
	mustLoadJSON(path, &fams)
	return fams
}

func mustLoadJSON(path string, v any) {
	// #nosec G304 -- path is always one of this CLI's own -base-families/
	// -head-families/-scope flags, supplied by the CI workflow that invokes
	// this tool, not by untrusted input.
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(2)
	}
	if err := json.Unmarshal(b, v); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(2)
	}
}

func mustLoadLines(path string) []string {
	// #nosec G304 -- path is always this CLI's own -changed-files flag,
	// supplied by the CI workflow that invokes this tool.
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(2)
	}
	var out []string
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
