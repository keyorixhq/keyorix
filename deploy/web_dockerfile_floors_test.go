package deploy

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var (
	// A logical `RUN ... apk add ... --upgrade ...` line (continuations are
	// joined by apkUpgradeArgs before matching).
	apkUpgradeRunRE = regexp.MustCompile(`(?m)^RUN\s.*\bapk add\b.*--upgrade\b.*$`)
	// One floor: a single-quoted `<package>>=<version>-r<release>` argument.
	apkFloorRE = regexp.MustCompile(`^'([a-z0-9][a-z0-9._+-]*)>=(\d[0-9A-Za-z._]*-r\d+)'$`)
)

// TestWebDockerfileApkFloorsWellFormedAndSorted: web/Dockerfile's production
// stage pulls security fixes that the pinned nginx:alpine digest lacks with
// `apk add --upgrade 'pkg>=ver-rN' ...` (see the policy comment above that line).
// The nightly docker-publish trivy gate is the only thing that notices a bad
// floor otherwise, a day after it merged. This asserts the shape, in PR CI:
//
//   - every floor is single-quoted (an unquoted pkg>=1 is a shell redirect to a
//     file named "=1", and the package would silently be installed unfloored);
//   - every floor is `pkg>=version-rN`, a minimum rather than an exact pin
//     (exact pins broke the build on 2026-10-19 when Alpine dropped the revision);
//   - the floors are strictly sorted by package, so the next bump is a one-line
//     diff and a duplicate package cannot hide in the middle of the list.
//
// It does NOT check that a floor is high enough for any CVE, that the version
// exists in the Alpine index, or that the comment table above the line lists the
// same packages: those need the registry or the scanner, which is Trivy's job.
// It fails if it finds no such line, so a rewrite of the Dockerfile cannot turn
// it vacuous.
func TestWebDockerfileApkFloorsWellFormedAndSorted(t *testing.T) {
	lines := apkUpgradeArgs(readRepoFile(t, "web/Dockerfile"))
	if len(lines) != 1 {
		t.Fatalf("web/Dockerfile has %d `apk add --upgrade` RUN lines, want exactly 1: keep the floors on one line so this check (and a reviewer) sees them all", len(lines))
	}
	if len(lines[0]) == 0 {
		t.Fatal("the `apk add --upgrade` line in web/Dockerfile has no package arguments")
	}
	for _, p := range apkFloorProblems(lines[0]) {
		t.Error("web/Dockerfile: " + p)
	}
}

// Both directions of the checker on synthetic input: a vacuous checker would
// pass the real Dockerfile above no matter what it contains.
func TestApkFloorProblems(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // substring of the single expected problem; "" means clean
	}{
		{"sorted", []string{"'brotli-libs>=1.2.1-r0'", "'curl>=8.23.0-r0'", "'libuuid>=2.42.3-r1'", "'musl-utils>=1.2.6-r3'"}, ""},
		{"single", []string{"'tiff>=4.7.2-r0'"}, ""},
		{"unsorted", []string{"'libuuid>=2.42.3-r1'", "'curl>=8.23.0-r0'"}, "not sorted"},
		{"duplicate", []string{"'curl>=8.23.0-r0'", "'curl>=8.24.0-r0'"}, "not sorted"},
		{"unquoted", []string{"libuuid>=2.42.3-r1"}, "malformed"},
		{"exact pin", []string{"'libexpat=2.8.5-r0'"}, "malformed"},
		{"no release", []string{"'tiff>=4.7.2'"}, "malformed"},
		{"no version", []string{"'tiff'"}, "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := apkFloorProblems(c.args)
			switch {
			case c.want == "" && len(got) != 0:
				t.Fatalf("want no problems, got %v", got)
			case c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want)):
				t.Fatalf("want one problem containing %q, got %v", c.want, got)
			}
		})
	}
}

func TestApkUpgradeArgsExtraction(t *testing.T) {
	df := "FROM nginx:alpine\n" +
		"RUN apk add --no-cache git\n" + // no --upgrade: not a floor line
		"RUN apk update && apk add --no-cache --upgrade \\\n" +
		"    'curl>=8.23.0-r0' \\\n" +
		"    'libuuid>=2.42.3-r1'\n" +
		"# RUN apk add --upgrade 'commented>=1-r0'\n"
	got := apkUpgradeArgs(df)
	if want := "[['curl>=8.23.0-r0' 'libuuid>=2.42.3-r1']]"; fmt.Sprint(got) != want {
		t.Fatalf("apkUpgradeArgs = %v, want %s", got, want)
	}
}

// apkUpgradeArgs returns, for each logical `RUN ... apk add ... --upgrade ...`
// line of a Dockerfile, the arguments after --upgrade with option flags removed.
func apkUpgradeArgs(dockerfile string) [][]string {
	joined := strings.ReplaceAll(dockerfile, "\\\n", " ")
	var out [][]string
	for _, line := range apkUpgradeRunRE.FindAllString(joined, -1) {
		_, after, _ := strings.Cut(line, "--upgrade")
		var args []string
		for f := range strings.FieldsSeq(after) {
			if !strings.HasPrefix(f, "-") {
				args = append(args, f)
			}
		}
		out = append(out, args)
	}
	return out
}

// apkFloorProblems reports every malformed floor and every adjacent pair that is
// not in strictly ascending package order.
func apkFloorProblems(args []string) []string {
	var problems []string
	prev := ""
	for _, a := range args {
		m := apkFloorRE.FindStringSubmatch(a)
		if m == nil {
			problems = append(problems, fmt.Sprintf("malformed floor %s: want '<package>>=<version>-r<release>' (single-quoted, a minimum, not an exact pin)", a))
			continue
		}
		if prev != "" && m[1] <= prev {
			problems = append(problems, fmt.Sprintf("floors not sorted by package: %s comes after %s (also catches a duplicate)", m[1], prev))
		}
		prev = m[1]
	}
	return problems
}
