package statemap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// deprecatedCLIFlagNames are the flag names the CLI has marked deprecated on at least one command
// (cobra MarkDeprecated). A name is only a candidate: whether a flag is deprecated on a given
// command is decided by running the built CLI, because `secret export --format` is a live flag and
// `secret list --format` is not. TestScriptsDeprecatedCLIFlags_TableCoversCLISource fails when the
// CLI source deprecates a name missing here.
var deprecatedCLIFlagNames = []string{"--format", "--by"}

// TestScriptsDeprecatedCLIFlags_NoScriptUsesOne fails when a shell script under scripts/ calls a
// `keyorix <command>` with a flag the current CLI deprecates on that command (the CLI prints
// "Flag --x has been deprecated" on every call: the PROD-OPS-1 drills printed 33 such lines a run).
//
// How it decides: it builds the CLI, reads the top-level command names from `keyorix --help`, and
// for each script line (backslash continuations joined) that names a candidate flag it finds the
// first token that is a top-level command, resolves the longest subcommand path that follows it
// against `<path> --help`, then runs `keyorix <path> <flag> [value] --help` and looks for
// "has been deprecated" on stderr. --help never contacts a server.
//
// What it does NOT see (stated so a green run is not read as more than it is): a command built at
// run time (`"${cmd[@]}"`, `$CLI $sub`), a command whose words are on a different logical line than
// the flag, scripts that are not *.sh, and flags passed through a variable. A flag deprecated on
// the CLI but absent from deprecatedCLIFlagNames is caught only by the source-table test below.
func TestScriptsDeprecatedCLIFlags_NoScriptUsesOne(t *testing.T) {
	cli := buildCLIForGuard(t)
	probe := newCLIProbe(t, cli)

	root := repoRoot(t)
	var hits []string
	scripts := filepath.Join(root, "scripts")
	err := filepath.WalkDir(scripts, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".sh") {
			return nil
		}
		data, err := os.ReadFile(p) // #nosec G304 -- walks the repo's own scripts/
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		for _, h := range scanScriptForDeprecatedFlags(string(data), probe) {
			hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, h.line, h.msg))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("scripts call a CLI flag the current CLI deprecates (it prints a deprecation line on every call); use the replacement named in the message:\n%s", strings.Join(hits, "\n"))
	}
}

// TestScriptsDeprecatedCLIFlags_RedAndGreen watches the scanner fail on a known-bad line and pass on
// known-good ones, against the real CLI: a guard nobody has seen go red is not a guard.
func TestScriptsDeprecatedCLIFlags_RedAndGreen(t *testing.T) {
	probe := newCLIProbe(t, buildCLIForGuard(t))
	cases := []struct {
		name, script string
		want         int
	}{
		{"deprecated --format on secret list", `cli "$n" "$p" secret list --project 1 --format json`, 1},
		{"deprecated --format on a continuation line", "keyorix secret list \\\n  --project 1 --format json", 1},
		{"deprecated --by on user suspend", `keyorix user suspend --id 3 --by admin`, 1},
		{"current --output on secret list", `cli "$n" "$p" secret list --project 1 --output json`, 0},
		{"live --format on secret export", `"$CLI_BIN" secret export --project 1 --env 1 --format json`, 0},
		{"server admin command is not the CLI", `keyorix-server admin backup --output ./b.tar.gz --format x`, 0},
		{"comment line is ignored", `# keyorix secret list --format json`, 0},
	}
	for _, c := range cases {
		got := scanScriptForDeprecatedFlags(c.script, probe)
		if len(got) != c.want {
			t.Errorf("%s: got %d hit(s) %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// TestScriptsDeprecatedCLIFlags_TableCoversCLISource fails when cli/cmd deprecates a flag name that
// deprecatedCLIFlagNames does not list, so a new deprecation cannot slip past the scan above.
func TestScriptsDeprecatedCLIFlags_TableCoversCLISource(t *testing.T) {
	re := regexp.MustCompile(`MarkDeprecated\("([a-z][a-z0-9-]*)"`)
	have := map[string]bool{}
	for _, n := range deprecatedCLIFlagNames {
		have[n] = true
	}
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "cli", "cmd", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot read cli/cmd: %v (%d files)", err, len(files))
	}
	var missing []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f) // #nosec G304 -- in-repo source
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if !have["--"+m[1]] {
				missing = append(missing, "--"+m[1]+" ("+filepath.Base(f)+")")
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("cli/cmd deprecates flag(s) missing from deprecatedCLIFlagNames: %s", strings.Join(missing, ", "))
	}
}

type guardHit struct {
	line int
	msg  string
}

// cliProbe runs the built CLI with --help and caches results.
type cliProbe struct {
	t     *testing.T
	bin   string
	top   map[string]bool
	cache map[string]string
}

func newCLIProbe(t *testing.T, bin string) *cliProbe {
	p := &cliProbe{t: t, bin: bin, top: map[string]bool{}, cache: map[string]string{}}
	stdout, _, err := p.run("--help")
	if err != nil {
		t.Fatalf("keyorix --help: %v", err)
	}
	in := false
	for l := range strings.SplitSeq(stdout, "\n") {
		switch {
		case strings.HasPrefix(l, "Available Commands:"):
			in = true
		case in && strings.HasPrefix(l, "  "):
			if f := strings.Fields(l); len(f) > 0 {
				p.top[f[0]] = true
			}
		case in:
			in = false
		}
	}
	if len(p.top) < 10 {
		t.Fatalf("parsed only %d top-level commands from `keyorix --help`; its layout changed", len(p.top))
	}
	return p
}

func (p *cliProbe) run(args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bin, args...) // #nosec G204 -- binary built by this test
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.Env = append(os.Environ(), "HOME="+p.t.TempDir(), "KEYORIX_SERVER=http://127.0.0.1:1")
	err = cmd.Run()
	return so.String(), se.String(), err
}

// resolves reports whether `<words> --help` is the help of exactly that command path.
func (p *cliProbe) resolves(words []string) bool {
	stdout, _, err := p.run(append(append([]string{}, words...), "--help")...)
	if err != nil {
		return false
	}
	ls := strings.Split(stdout, "\n")
	for i, l := range ls {
		if l == "Usage:" && i+1 < len(ls) {
			f := strings.Fields(ls[i+1])
			if len(f) < 1 || f[0] != "keyorix" {
				return false
			}
			path := []string{}
			for _, w := range f[1:] {
				if strings.HasPrefix(w, "[") || strings.HasPrefix(w, "<") {
					break
				}
				path = append(path, w)
			}
			return strings.Join(path, " ") == strings.Join(words, " ")
		}
	}
	return false
}

// deprecation returns the CLI's deprecation message for flag on path, or "".
func (p *cliProbe) deprecation(path []string, flag, value string) string {
	key := strings.Join(path, " ") + "|" + flag
	if v, ok := p.cache[key]; ok {
		return v
	}
	args := append([]string{}, path...)
	args = append(args, flag)
	if value != "" {
		args = append(args, value)
	}
	args = append(args, "--help")
	_, stderr, _ := p.run(args...)
	msg := ""
	for l := range strings.SplitSeq(stderr, "\n") {
		if strings.Contains(l, "has been deprecated") {
			msg = strings.TrimSpace(l)
			break
		}
	}
	p.cache[key] = msg
	return msg
}

var guardWordRE = regexp.MustCompile(`^[a-z][a-z-]*$`)

func scanScriptForDeprecatedFlags(script string, p *cliProbe) []guardHit {
	var hits []guardHit
	raw := strings.Split(script, "\n")
	for i := 0; i < len(raw); i++ {
		start := i + 1
		line := raw[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(raw) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + raw[i+1]
			i++
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		toks := strings.Fields(line)
		for j, tok := range toks {
			toks[j] = strings.Trim(tok, `"'`)
		}
		for _, flag := range deprecatedCLIFlagNames {
			fi := -1
			for j, tok := range toks {
				if tok == flag || strings.HasPrefix(tok, flag+"=") {
					fi = j
					break
				}
			}
			if fi < 0 {
				continue
			}
			// first top-level CLI command word before the flag, not the server's `admin` verbs
			ti := -1
			for j := 0; j < fi; j++ {
				if p.top[toks[j]] && !(j > 0 && toks[j-1] == "admin") && !strings.Contains(strings.Join(toks[:j], " "), "keyorix-server") {
					ti = j
					break
				}
			}
			if ti < 0 {
				continue
			}
			cands := []string{toks[ti]}
			for j := ti + 1; j < fi && len(cands) < 3 && guardWordRE.MatchString(toks[j]); j++ {
				cands = append(cands, toks[j])
			}
			var path []string
			for n := len(cands); n >= 1; n-- {
				if p.resolves(cands[:n]) {
					path = cands[:n]
					break
				}
			}
			if path == nil {
				continue
			}
			value := ""
			if strings.HasPrefix(toks[fi], flag+"=") {
				value = ""
			} else if fi+1 < len(toks) && !strings.HasPrefix(toks[fi+1], "-") {
				value = toks[fi+1]
			}
			if value == "$" || strings.ContainsAny(value, "$`(") {
				value = "x"
			}
			if msg := p.deprecation(path, flag, value); msg != "" {
				hits = append(hits, guardHit{start, fmt.Sprintf("`keyorix %s %s`: %s", strings.Join(path, " "), flag, msg)})
			}
		}
	}
	return hits
}

// buildCLIForGuard builds ./cli (a separate module, excluded from go.work) into a temp dir.
func buildCLIForGuard(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not on PATH, cannot build the CLI the guard probes: %v", err)
	}
	out := filepath.Join(t.TempDir(), "keyorix")
	cmd := exec.Command(goBin, "build", "-o", out, ".") // #nosec G204 -- fixed arguments
	cmd.Dir = filepath.Join(repoRoot(t), "cli")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the CLI for the guard: %v\n%s", err, b)
	}
	return out
}
