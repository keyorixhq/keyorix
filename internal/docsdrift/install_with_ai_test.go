package docsdrift

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// INSTALL-WITH-AI-1 item 3: INSTALL-WITH-AI.md is followed literally by an AI
// assistant, and everything the assistant runs or reads lands in its transcript.
// TestInstallWithAIIsSecretBlind checks the page's lines against the rules its own
// prompt states. Lines inside a blockquote (`> ...`) are HUMAN STEPs, run by the
// user in their own terminal; every other fenced shell line and inline code span
// is an assistant line.
//
//   - read: an assistant line does not read a secret file. A secret path (see
//     iwaSecretPath) is refused as the input redirection of a command, or as an
//     argument anywhere in a simple command that also names a reader
//     (iwaReaders: cat, grep, base64, cp, a hash, an editor, an interpreter, ...),
//     so `docker compose exec backend cat /run/secrets/x` and `$(cat x)` count.
//     Passing a path as KEYORIX_*_FILE=, `rm`, `chmod`, `chown` and output
//     redirection are not reads.
//   - print: an assistant line does not run a command that prints a secret by
//     design: `mfa enroll`, `mfa activate`, `recovery-key rotate` without
//     `--recipient`, `printenv`, a bare `env`, `set -x`, `docker inspect`, and
//     `printenv` / a trailing `env` / `set -x` run through docker or podman exec|run.
//     A password= or URL userinfo password inside a connection string is refused.
//   - value: no line (assistant or human) assigns a plain KEYORIX_* secret
//     variable (KEYORIX_ADMIN_PASSWORD=..., only the *_FILE form is allowed).
//     Secret flags with a value are TestDocsDoNotPutSecretsInFlags' job (this
//     page is in commandDocs) and cli's TestDocsShowNoLiteralSecretOnCommandLine.
//   - spelling: in fenced shell lines, the CLI is run as ./bin/keyorix and the
//     server as ./bin/keyorix-server (or inside `docker compose run|exec`), the
//     forms cli's TestInstallWithAICommandsExist and server/admin's
//     TestInstallWithAIAdminCommandsExist / TestDocsServerCommandsExist resolve
//     against the real command trees. A bare `keyorix ...` would be checked by
//     nothing.
//   - proof: each install path section ends its assistant-run `keyorix-server
//     admin` lines with `admin validate --posture`.
//   - prompt: the text block under "## The prompt" still states the rules.
//
// A script given to `sh|bash|zsh|dash -c` (also through docker compose exec) is
// read like the rest of the line (iwaShellCScript).
//
// What it does not check: prose that is not in a code span, fences whose info
// string is not a shell (the prompt is ```text) or that use ~~~ instead of
// backticks, the keyorix CLI credential file (~/.config/keyorix/credentials.json,
// not in iwaSecretPath), whether a reader not in iwaReaders can read a file, and
// whether the steps work (the transcript test in the page's maintainer notes,
// pending the e2e VM).

const iwaDoc = "INSTALL-WITH-AI.md"

// iwaPathSections are the "## " sections that each install end to end.
var iwaPathSections = []string{"Steps for the assistant", "Docker Compose with PostgreSQL"}

// iwaPromptRules must each appear in the prompt block.
var iwaPromptRules = []string{
	"SECRET-BLIND",
	"Never read, print, copy, encode, hash or search the contents",
	"Never ask me to paste or type a password, token, key, TOTP secret, MFA code or",
	"never put one in a command-line flag",
	"Pass\n   secrets only as KEYORIX_*_FILE=<path>",
	"HUMAN STEP",
	"admin validate --posture",
}

var (
	// iwaSecretPath matches a word naming a secret file or a whole secret
	// directory: secrets, keys and /run/secrets with or without a trailing slash
	// or a file below them (so `cp -r secrets x` and `tar czf x secrets keys`
	// count), and the known secret file names.
	iwaSecretPath = regexp.MustCompile(`(^|[/"'=:])(secrets|keys)(/|$)|/run/secrets(/|$)|server\.key|\.age$|keyorix\.db|(master|admin|db)_password|bootstrap_token|metrics_token`)
	iwaReaders    = []string{
		"cat", "tac", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag", "awk", "sed",
		"cut", "sort", "uniq", "xxd", "od", "hexdump", "base64", "base32", "strings", "cp", "scp", "rsync",
		"tar", "zip", "openssl", "gpg", "age", "diff", "cmp", "vi", "vim", "nano", "emacs", "source", ".",
		"python", "python3", "perl", "ruby", "node", "jq", "yq", "sqlite3", "psql", "echo", "printf",
		"sha256sum", "sha1sum", "sha512sum", "shasum", "md5sum", "b2sum", "cksum", "curl", "wget", "nc",
		"dd", "mv", "install", "ln",
	}
	// iwaDSNPassword matches a password inside a connection string: a password=
	// keyword or URL userinfo with a password.
	iwaDSNPassword    = regexp.MustCompile(`(?i)(^|[\s"'])password\s*=|://[^/\s:@]+:[^/\s@]+@`)
	iwaPlainSecretVar = regexp.MustCompile(`^KEYORIX_[A-Z0-9_]*(PASSWORD|PASSPHRASE|TOKEN|SECRET)=`)
	iwaAssign         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	iwaWrappers       = []string{"sudo", "nohup", "time", "exec", "env", "xargs"}
	iwaSeparators     = []string{"|", "||", "&&", ";", "&"}
	iwaInlineSpan     = regexp.MustCompile("`([^`\n]+)`")
)

// iwaLine is one command line of the page.
type iwaLine struct {
	Num     int    // 1-based line in the file
	Text    string // continuations joined
	Human   bool   // inside a blockquote: a HUMAN STEP
	Fenced  bool   // a shell fence line, not an inline span
	Section string // the enclosing "## " heading
}

// iwaParse returns the shell lines and inline code spans of the page, and the
// prompt block's text.
func iwaParse(doc string) (lines []iwaLine, prompt string) {
	section, inFence, shellFence, inPrompt := "", false, false, false
	var pending *iwaLine
	for i, raw := range strings.Split(doc, "\n") {
		trim := strings.TrimSpace(raw)
		quoted := strings.HasPrefix(trim, ">")
		body := strings.TrimSpace(strings.TrimPrefix(trim, ">"))
		if !inFence && strings.HasPrefix(trim, "## ") {
			section = strings.TrimPrefix(trim, "## ")
		}
		if info, ok := strings.CutPrefix(body, "```"); ok {
			if inFence {
				inFence, inPrompt = false, false
				continue
			}
			info = strings.TrimSpace(info)
			inFence = true
			shellFence = slices.Contains([]string{"", "bash", "sh", "shell", "console"}, info)
			inPrompt = section == "The prompt" && info == "text"
			continue
		}
		if inFence {
			if inPrompt {
				prompt += raw + "\n"
			}
			if !shellFence {
				continue
			}
			if pending != nil {
				pending.Text += " " + body
			} else {
				pending = &iwaLine{Num: i + 1, Text: body, Human: quoted, Fenced: true, Section: section}
			}
			if text, ok := strings.CutSuffix(pending.Text, "\\"); ok {
				pending.Text = text
				continue
			}
			lines = append(lines, *pending)
			pending = nil
			continue
		}
		for _, m := range iwaInlineSpan.FindAllStringSubmatch(raw, -1) {
			lines = append(lines, iwaLine{Num: i + 1, Text: m[1], Human: quoted, Section: section})
		}
	}
	return lines, prompt
}

// iwaWords splits a shell line into words, keeping quoted strings whole (quotes
// removed), splitting off ; | & < > ( ) as their own words, and dropping a
// comment.
func iwaWords(line string) []string {
	var words []string
	var cur strings.Builder
	has := false
	flush := func() {
		if has {
			words = append(words, cur.String())
		}
		cur.Reset()
		has = false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'' || c == '"':
			j := strings.IndexByte(line[i+1:], c)
			if j < 0 {
				j = len(line) - i - 1
			}
			if quoted := line[i+1 : i+1+j]; (c == '"' && strings.Contains(quoted, "$(")) || (!has && iwaShellCScript(words)) {
				flush() // "$(cat x)" and `sh -c '...'` run a command: split it like unquoted text
				words = append(words, iwaWords(quoted)...)
			} else {
				cur.WriteString(quoted)
				has = true
			}
			i += j + 1
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && !has:
			flush()
			return words
		case strings.IndexByte(";|&<>()", c) >= 0:
			flush()
			op := string(c)
			if i+1 < len(line) && (line[i+1] == c || (c == '&' && line[i+1] == '&')) && c != '(' && c != ')' {
				op += string(c)
				i++
			}
			words = append(words, op)
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	flush()
	return words
}

// iwaShells are the shells whose -c argument is a script iwaWords must read.
var iwaShells = []string{"sh", "bash", "zsh", "dash"}

// iwaShellCScript reports whether the next word, if quoted, is the script of a
// shell run with -c (or -lc, -ec, ...): the last word is such an option and a shell
// is named earlier on the line, as in `docker compose exec backend sh -c '...'`.
func iwaShellCScript(words []string) bool {
	if len(words) < 2 {
		return false
	}
	opt := words[len(words)-1]
	if len(opt) < 2 || opt[0] != '-' || opt[1] == '-' || !strings.HasSuffix(opt, "c") {
		return false
	}
	for _, w := range words[:len(words)-1] {
		if slices.Contains(iwaShells, path.Base(w)) {
			return true
		}
	}
	return false
}

// iwaCommands splits words into simple commands at | || && ; & ( ) and $( .
func iwaCommands(words []string) [][]string {
	var out [][]string
	var cur []string
	for _, w := range words {
		if slices.Contains(iwaSeparators, w) || w == "(" || w == ")" {
			if len(cur) > 0 {
				out = append(out, cur)
			}
			cur = nil
			continue
		}
		if w == "$" || w == "`" {
			continue
		}
		cur = append(cur, strings.Trim(w, "`"))
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// iwaCommandWord returns the index of the word that is the command: the first one
// that is not an assignment, a wrapper or a wrapper's option.
func iwaCommandWord(cmd []string) int {
	for i, w := range cmd {
		if iwaAssign.MatchString(w) || slices.Contains(iwaWrappers, w) || (i > 0 && slices.Contains(iwaWrappers, cmd[i-1]) && strings.HasPrefix(w, "-")) {
			continue
		}
		return i
	}
	return -1
}

func iwaFind(lines []iwaLine, prompt string) []secretFinding {
	var out []secretFinding
	add := func(l iwaLine, format string, args ...any) {
		out = append(out, secretFinding{iwaDoc, l.Num, fmt.Sprintf(format, args...)})
	}
	lastAdmin := map[string]iwaLine{}
	for _, l := range lines {
		for _, cmd := range iwaCommands(iwaWords(l.Text)) {
			for _, w := range cmd {
				if iwaPlainSecretVar.MatchString(w) && !strings.Contains(strings.SplitN(w, "=", 2)[0], "_FILE") {
					add(l, "a plain secret variable %s puts the value on the command line; use the *_FILE form", strings.SplitN(w, "=", 2)[0]+"=")
				}
			}
			ci := iwaCommandWord(cmd)
			if ci < 0 {
				continue
			}
			for j := ci; l.Fenced && j < len(cmd); j++ {
				b := path.Base(cmd[j])
				if b != "keyorix" && b != "keyorix-server" {
					continue
				}
				inContainer := cmd[ci] == "docker" || cmd[ci] == "podman"
				if (j == ci && cmd[j] != "./bin/"+b) || (inContainer && b == "keyorix") {
					add(l, "%s is spelled so no command-tree check sees it; run it as ./bin/%s", cmd[j], b)
				}
				if !l.Human && j+1 < len(cmd) && cmd[j+1] == "admin" && (j == ci || inContainer) {
					lastAdmin[l.Section] = l
				}
				break
			}
			if l.Human {
				continue
			}
			name := path.Base(cmd[ci])
			reader := ""
			for _, w := range cmd[ci:] {
				if slices.Contains(iwaReaders, path.Base(w)) {
					reader = path.Base(w)
					break
				}
			}
			for j := ci; j < len(cmd); j++ {
				w := cmd[j]
				// NAME=path is a pass-through only as a *_FILE variable; dd's
				// if=secrets/x is a read.
				if (iwaAssign.MatchString(w) && strings.HasSuffix(strings.SplitN(w, "=", 2)[0], "_FILE")) || !iwaSecretPath.MatchString(w) {
					continue
				}
				switch prev := cmd[max(j-1, 0)]; {
				case prev == ">" || prev == ">>":
				case prev == "<" || prev == "<<":
					add(l, "assistant line reads the secret file %s by input redirection", w)
				case reader != "" && name != "rm" && name != "chmod" && name != "chown":
					add(l, "assistant line reads the secret file %s with %s", w, reader)
				}
			}
			joined := " " + strings.Join(cmd, " ") + " "
			switch {
			case !l.Fenced: // a code span in prose names a command, it does not run it
			case iwaDSNPassword.MatchString(l.Text):
				add(l, "assistant line puts a password inside a connection string; the password goes in a *_FILE the user creates")
			case strings.Contains(joined, " mfa enroll ") || strings.Contains(joined, " mfa activate "):
				add(l, "assistant line runs %q, which prints a TOTP secret or recovery codes: make it a HUMAN STEP", strings.TrimSpace(joined))
			case strings.Contains(joined, " recovery-key rotate ") && !strings.Contains(joined, " --recipient"):
				add(l, "assistant line runs recovery-key rotate without --recipient, which prints the key: make it a HUMAN STEP")
			case name == "printenv" || (name == "env" && ci == len(cmd)-1) || (name == "set" && strings.Contains(joined, " -x ")) ||
				(name == "docker" && slices.Contains(cmd, "inspect")) ||
				// the same commands run inside a container: docker compose exec|run SERVICE printenv
				((name == "docker" || name == "podman") && (slices.Contains(cmd, "printenv") || cmd[len(cmd)-1] == "env" || strings.Contains(joined, " set -x "))):
				add(l, "assistant line runs %q, which can print secret values", strings.TrimSpace(joined))
			}
		}
	}
	for _, s := range iwaPathSections {
		last, ok := lastAdmin[s]
		if !ok || !strings.Contains(last.Text, "admin validate --posture") {
			out = append(out, secretFinding{iwaDoc, last.Num, fmt.Sprintf("section %q does not end its assistant-run admin commands with `admin validate --posture` (last: %q)", s, last.Text)})
		}
	}
	for _, r := range iwaPromptRules {
		if !strings.Contains(prompt, r) {
			out = append(out, secretFinding{iwaDoc, 0, fmt.Sprintf("the prompt block no longer states %q", r)})
		}
	}
	return out
}

func TestInstallWithAIIsSecretBlind(t *testing.T) {
	lines, prompt := iwaParse(readDoc(t, iwaDoc))
	human, assistant := 0, 0
	for _, l := range lines {
		if l.Fenced && l.Human {
			human++
		} else if l.Fenced {
			assistant++
		}
	}
	// Liveness: a parser that stopped seeing the steps would pass vacuously.
	if assistant < 25 || human < 8 || prompt == "" {
		t.Fatalf("parsed %d assistant and %d human fenced lines and a %d-byte prompt from %s; the parser has drifted", assistant, human, len(prompt), iwaDoc)
	}
	for _, f := range iwaFind(lines, prompt) {
		t.Errorf("%s:%d: %s", f.Doc, f.Line, f.What)
	}
}

// TestInstallWithAISecretBlindCatchesPlantedErrors is the red/green proof: each
// planted line in an otherwise passing page is reported, and the real page with
// one planted line goes red.
func TestInstallWithAISecretBlindCatchesPlantedErrors(t *testing.T) {
	prompt := "## The prompt\n\n```text\n" + strings.Join(iwaPromptRules, "\n") + "\n```\n\n"
	good := prompt + "## Steps for the assistant\n\n```bash\n" +
		"KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin migrate --config ./keyorix.yaml\n" +
		"KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin recovery-key rotate --recipient age1x --output ./recovery-key.age\n" +
		"rm -f secrets/bootstrap_token\n" +
		"sed -i.bak 's|^    # dsn: .*|    dsn: \"host=h\"|' keyorix.yaml\n" +
		"KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin validate --posture --config ./keyorix.yaml\n" +
		"KEYORIX_CONFIG_PATH=./keyorix.yaml nohup ./bin/keyorix-server > server.log 2>&1 &\n" +
		"```\n\n" +
		"> ```bash\n> ./bin/keyorix login --server https://localhost:8080 --username admin < secrets/admin_password\n" +
		"> ./bin/keyorix mfa enroll\n> (umask 077; cat > secrets/db_password)\n> ```\n\n" +
		"## Docker Compose with PostgreSQL\n\n```bash\n" +
		"sudo chown root:1000 secrets/*\n" +
		"docker compose run --rm backend ./keyorix-server admin validate --posture\n" +
		"docker compose start backend\n```\n"
	if f := iwaFind(iwaParse(good)); len(f) != 0 {
		t.Fatalf("passing page reported: %+v", f)
	}

	bad := []string{
		"cat secrets/master_password",
		"./bin/keyorix login --username admin < secrets/admin_password",
		"docker compose exec -T backend cat /run/secrets/master_password",
		"export X=\"$(base64 < keys/dek.key)\"",
		"export X=$(cat secrets/bootstrap_token)",
		"sha256sum certs/server.key",
		"KEYORIX_ADMIN_PASSWORD=hunter2 ./bin/keyorix system init",
		"./bin/keyorix mfa enroll",
		"./bin/keyorix-server admin recovery-key rotate --config ./keyorix.yaml",
		"printenv",
		"docker compose exec backend printenv",
		"docker compose exec backend env",
		"docker compose exec backend sh -c 'cat /run/secrets/master_password'",
		"bash -c \"cat secrets/master_password\"",
		"dd if=secrets/master_password of=/dev/stdout",
		"mv secrets/master_password ./leak",
		// whole-directory reads: a bare secrets/keys directory name, /run/secrets
		"cp -r secrets ./leak",
		"tar czf leak.tgz secrets keys",
		"docker compose cp backend:/run/secrets ./leak",
		"sed -i.bak 's|^    # dsn: .*|    dsn: \"host=h user=u password=hunter2\"|' keyorix.yaml",
		"sed -i.bak 's|^    # dsn: .*|    dsn: \"postgres://u:hunter2@h/db\"|' keyorix.yaml",
		"keyorix login --server https://localhost:8080",
		"docker compose run --rm backend keyorix whoami",
	}
	for _, line := range bad {
		doc := strings.Replace(good, "rm -f secrets/bootstrap_token\n", "rm -f secrets/bootstrap_token\n"+line+"\n", 1)
		if f := iwaFind(iwaParse(doc)); len(f) == 0 {
			t.Errorf("planted assistant line not reported: %s", line)
		}
	}
	// The same lines in a HUMAN STEP are the user's to run: only a plain secret
	// variable and a spelling no command-tree check sees are still reported.
	for _, line := range bad {
		doc := strings.Replace(good, "> ./bin/keyorix mfa enroll\n", "> ./bin/keyorix mfa enroll\n> "+line+"\n", 1)
		f := iwaFind(iwaParse(doc))
		want := strings.HasPrefix(line, "KEYORIX_ADMIN_PASSWORD=") || strings.HasPrefix(line, "keyorix ") || strings.HasSuffix(line, " keyorix whoami")
		if (len(f) != 0) != want {
			t.Errorf("human line %q: findings %+v, want reported=%v", line, f, want)
		}
	}
	// The posture proof must stay last, and the prompt must keep its rules.
	noProof := strings.Replace(good, "docker compose run --rm backend ./keyorix-server admin validate --posture\n",
		"docker compose run --rm backend ./keyorix-server admin validate --posture\ndocker compose run --rm backend ./keyorix-server admin migrate\n", 1)
	if f := iwaFind(iwaParse(noProof)); len(f) != 1 {
		t.Errorf("admin command after the posture proof: %d findings, want 1: %+v", len(f), f)
	}
	if f := iwaFind(iwaParse(strings.Replace(good, "HUMAN STEP", "", 1))); len(f) != 1 {
		t.Errorf("prompt without its HUMAN STEP rule: %d findings, want 1: %+v", len(f), f)
	}

	page := readDoc(t, iwaDoc)
	anchor := "rm -f secrets/bootstrap_token\n"
	if !strings.Contains(page, anchor) {
		t.Fatalf("%s no longer contains %q to plant after", iwaDoc, anchor)
	}
	if f := iwaFind(iwaParse(strings.Replace(page, anchor, anchor+"cat secrets/master_password\n", 1))); len(f) != 1 {
		t.Errorf("real page with a planted read: %d findings, want 1: %+v", len(f), f)
	}
}
