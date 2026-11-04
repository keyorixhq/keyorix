package docsdrift

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// INSTALL-WITH-AI-1 item 3: INSTALL-WITH-AI.md is followed literally by an AI
// assistant, and everything the assistant runs or reads lands in its transcript.
// TestInstallWithAIIsSecretBlind checks the page's lines against the rules its own
// prompt states. A fence opened inside a blockquote (`> ```bash`) holds HUMAN
// STEPs, run by the user in their own terminal; every other fenced shell line and
// inline code span is an assistant line.
//
//   - read: an assistant line does not read a secret file. A secret path (see
//     iwaSecretPath) is refused as the input redirection of a command, or as an
//     argument of ANY command that is not on the allowlist of non-reading
//     commands (iwaNonReaders: rm, chmod, chown, chgrp, shred, test, [, [[, ls,
//     stat, touch, mkdir, ./bin/keyorix, ./bin/keyorix-server), so `docker compose exec backend cat /run/secrets/x`,
//     `$(cat x)`, `eval "cat x"`, `nl x`, `awk 1 x` and `python -c` all count and
//     an unknown command fails closed. Passing a path as KEYORIX_*_FILE=, a bare
//     path in prose and output redirection are not reads.
//   - print: an assistant line does not run a command that prints a secret by
//     design: `mfa enroll`, `mfa activate`, `recovery-key rotate` without
//     `--recipient`, `printenv`, `env` with no command after it (`env`,
//     `sudo env`, `env | sort`), `set -x`, `docker inspect`, and
//     `printenv` / a trailing `env` / `set -x` run through docker or podman exec|run.
//     A password= or URL userinfo password inside a connection string is refused.
//   - value: no line (assistant or human) assigns a plain KEYORIX_* secret
//     variable (KEYORIX_ADMIN_PASSWORD=..., only the *_FILE form is allowed): every
//     name in config.SecretEnvVars, and any KEYORIX_* name ending in PASSWORD,
//     PASSPHRASE, TOKEN or SECRET.
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
// read like the rest of the line (iwaShellCScript), and a backtick span is split
// like `$(` (`X=`cat f``). Every fence is read as shell whatever its info string
// says, except ```text (the prompt block).
//
// What it does not check: prose that is not in a code span, fences that use ~~~
// instead of backticks, 4-space indented code blocks, the keyorix CLI credential file (~/.config/keyorix/credentials.json,
// not in iwaSecretPath), whether an allowlisted command can read a file
// (an input redirection, also 0< 3< and <>, is a read whatever the command),
// shell globs (`cat secre*/master*`) and variable indirection (`F=secrets/x` and
// `cat "$F"` on separate lines), which a word-level match cannot see, the
// environment-printing builtins `set`, `export`, `export -p`, `declare -p`,
// `command printenv` and `builtin set`, and whether the steps work (the
// transcript test in the page's maintainer notes, pending the e2e VM).

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
	iwaSecretPath = regexp.MustCompile(`(^|[/"'=:\s])(secrets|keys)(/|$)|/run/secrets(/|$)|server\.key|\.age$|keyorix\.db|(master|admin|db)_password|bootstrap_token|metrics_token`)
	// iwaNonReaders is the ALLOWLIST: the only commands that may have a secret path
	// among their words. None of them opens the file's contents (rm, chmod, chown,
	// chgrp and shred act on the file, test/[/[[ , ls and stat read metadata, touch
	// and mkdir create; the project's own binaries write files such as --output and
	// do not echo one, what they print is the print rules' job). Any other command word, known or not (cat, eval, nl, less,
	// awk, xxd, base64, python -c, a script of the page's own), is refused. Matched
	// against the whole command word: `/bin/cat`, `\rm` and `command rm` are not on it.
	iwaNonReaders = []string{"rm", "chmod", "chown", "chgrp", "shred", "test", "[", "[[", "ls", "stat", "touch", "mkdir", "./bin/keyorix", "./bin/keyorix-server"}
	// iwaProjectBinaries are the allowlisted commands that run or carry another
	// command: `./bin/keyorix run -- cat x` execs it. For them the allowlist is not
	// enough: a reader (iwaReaders) anywhere after the binary refuses the line, and
	// the word after a `--` must itself be on the allowlist.
	iwaProjectBinaries = []string{"./bin/keyorix", "./bin/keyorix-server"}
	// iwaReaders are the known reading commands, the denylist the allowlist replaced.
	// It is kept only for iwaProjectBinaries' arguments.
	iwaReaders = []string{
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
	// iwaRedirect matches a redirection word of the >& family: >&2 and 2>&1 carry
	// their target, a bare >& takes the next word as its file. iwaWords keeps a
	// digit run before > attached, so 2>&1 is one word.
	iwaRedirect = regexp.MustCompile(`^[0-9]*>&[0-9-]*$`)
	// iwaRedirectOp matches a redirection whose target is the next word.
	iwaRedirectOp = regexp.MustCompile(`^[0-9]*(>|>>|<)$`)
	// iwaInputOp matches an input redirection operator, with or without a
	// descriptor: <, <<, 0<, 3<.
	iwaInputOp    = regexp.MustCompile(`^[0-9]*<<?$`)
	iwaInlineSpan = regexp.MustCompile("`([^`\n]+)`")
)

// iwaIsPlainSecretVar reports whether name (the part of a word before its =) is a
// secret variable in its plain form: a name in config.SecretEnvVars, or one the
// suffix rule matches (operator-named ones such as KEYORIX_SSO_<P>_CLIENT_SECRET).
// The *_FILE form is the allowed one.
func iwaIsPlainSecretVar(name string) bool {
	if strings.Contains(name, "_FILE") {
		return false
	}
	return slices.Contains(config.SecretEnvVars, name) || iwaPlainSecretVar.MatchString(name+"=")
}

// iwaLine is one command line of the page.
type iwaLine struct {
	Num     int    // 1-based line in the file
	Text    string // continuations joined
	Human   bool   // inside a blockquote: a HUMAN STEP
	Fenced  bool   // a shell fence line, not an inline span
	Section string // the enclosing "## " heading
}

// iwaParse returns the shell lines and inline code spans of the page, and the
// prompt block's text. HUMAN is decided per fence, by whether the opening ```
// line is in a blockquote, not per line.
func iwaParse(doc string) (lines []iwaLine, prompt string) {
	section, inFence, shellFence, inPrompt, fenceQuoted := "", false, false, false, false
	var pending *iwaLine
	for i, raw := range strings.Split(doc, "\n") {
		trim := strings.TrimSpace(raw)
		quoted := strings.HasPrefix(trim, ">")
		// Inside a fence the fence decides: a leading > in a fence opened outside a
		// blockquote is shell text (`>&2 cat x`), not a blockquote marker, so it
		// stays an assistant line and keeps its >. In a fence opened in a blockquote a
		// line without > ends the blockquote, so it is not a HUMAN line (fail closed);
		// a closing ``` without > still closes the fence.
		if inFence {
			quoted = fenceQuoted && quoted
		}
		body := trim
		if quoted {
			body = strings.TrimSpace(strings.TrimPrefix(trim, ">"))
		}
		if !inFence && strings.HasPrefix(trim, "## ") {
			section = strings.TrimPrefix(trim, "## ")
		}
		if info, ok := strings.CutPrefix(body, "```"); ok {
			if inFence {
				inFence, inPrompt = false, false
				continue
			}
			info = strings.TrimSpace(info)
			inFence, fenceQuoted = true, quoted
			// Fail closed: any fence but ```text (the prompt) is read as shell, so a
			// zsh, Bash or shell-session info string cannot hide a read.
			shellFence = !strings.EqualFold(info, "text")
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
	inTick := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'' || c == '"':
			j := strings.IndexByte(line[i+1:], c)
			if j < 0 {
				j = len(line) - i - 1
			}
			if quoted := line[i+1 : i+1+j]; (c == '"' && (strings.Contains(quoted, "$(") || strings.Contains(quoted, "`"))) || (!has && iwaShellCScript(words)) {
				flush() // "$(cat x)", "`cat x`" and `sh -c '...'` run a command: split it like unquoted text
				words = append(words, iwaWords(quoted)...)
			} else {
				cur.WriteString(quoted)
				has = true
			}
			i += j + 1
		case c == '`':
			// `cmd` is command substitution like $(cmd): the span opens and closes a
			// command, so X=`cat f` reads f as the command word `cat`.
			flush()
			if inTick {
				words = append(words, ")")
			} else {
				words = append(words, "(")
			}
			inTick = !inTick
		case c == ' ' || c == '\t':
			flush()
		case c == '#' && !has:
			flush()
			return words
		case strings.IndexByte(";|&<>()", c) >= 0:
			// A digit run right before > or < is the descriptor of the redirection
			// (2>&1, 2>/dev/null): keep it attached, not a command word.
			fd := ""
			if (c == '>' || c == '<') && has && strings.Trim(cur.String(), "0123456789") == "" {
				fd = cur.String()
				cur.Reset()
				has = false
			}
			flush()
			op := string(c)
			if c == '>' && i+1 < len(line) && line[i+1] == '&' {
				// >&2 duplicates a descriptor: one word, not a background operator
				j := i + 2
				for j < len(line) && (line[j] >= '0' && line[j] <= '9' || line[j] == '-') {
					j++
				}
				words = append(words, fd+line[i:j])
				i = j - 1
				continue
			}
			if i+1 < len(line) && (line[i+1] == c || (c == '&' && line[i+1] == '&')) && c != '(' && c != ')' {
				op += string(c)
				i++
			}
			words = append(words, fd+op)
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
// that is not an assignment, a wrapper or a wrapper's option, or -1 when there is
// none (`< file` alone). `env` followed only by assignments and redirections
// (`env`, `sudo env`, `env X=1 >&2`) is the command itself; an option after it
// (`env -u X`) is read as a command, so env stays a wrapper there. A leading redirection and its target are
// skipped here; iwaFind still reads an input redirection's target.
func iwaCommandWord(cmd []string) int {
	for i := 0; i < len(cmd); i++ {
		w := cmd[i]
		// a leading redirection (`>&2 printenv`, `> file cat x`) is not the command
		if iwaRedirectOp.MatchString(w) || (strings.HasSuffix(w, ">&") && iwaRedirect.MatchString(w)) {
			i++ // its target: `> file`, `2>/dev/null`, `>& file`
			continue
		}
		if iwaRedirect.MatchString(w) {
			continue
		}
		if w == "env" && iwaCommandWord(cmd[i+1:]) < 0 {
			return i
		}
		if iwaAssign.MatchString(w) || slices.Contains(iwaWrappers, w) || (i > 0 && slices.Contains(iwaWrappers, cmd[i-1]) && strings.HasPrefix(w, "-")) {
			continue
		}
		return i
	}
	return -1
}

// iwaProjectBinaryArgsOK reports whether the words after an allowlisted project
// binary carry no command that could read a file: no reader among them, and the
// word after a `--` (keyorix run -- CMD) is itself on the allowlist.
func iwaProjectBinaryArgsOK(args []string) bool {
	for i, w := range args {
		if slices.Contains(iwaReaders, path.Base(w)) {
			return false
		}
		if w == "--" && (i+1 >= len(args) || !slices.Contains(iwaNonReaders, args[i+1])) {
			return false
		}
	}
	return true
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
				if name, _, ok := strings.Cut(w, "="); ok && iwaIsPlainSecretVar(name) {
					add(l, "a plain secret variable %s puts the value on the command line; use the *_FILE form", name+"=")
				}
			}
			ci := iwaCommandWord(cmd)
			for j := ci; ci >= 0 && l.Fenced && j < len(cmd); j++ {
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
			name, allowed := "", false
			if ci >= 0 {
				name = path.Base(cmd[ci])
				// a bare path (`secrets/x` in prose) is a noun, not a command that reads it;
				// in a fence every command word is a command
				allowed = slices.Contains(iwaNonReaders, cmd[ci]) || (!l.Fenced && iwaSecretPath.MatchString(cmd[ci]))
				if allowed && slices.Contains(iwaProjectBinaries, cmd[ci]) {
					allowed = iwaProjectBinaryArgsOK(cmd[ci+1:])
				}
			}
			// From the first word, not from ci: iwaCommandWord skips a leading
			// redirection and its target, but `< secrets/x cat` and $(< secrets/x)
			// still read the file.
			for j := range cmd {
				w := cmd[j]
				// NAME=path is a pass-through only as a *_FILE variable; dd's
				// if=secrets/x is a read.
				if (iwaAssign.MatchString(w) && strings.HasSuffix(strings.SplitN(w, "=", 2)[0], "_FILE")) || !iwaSecretPath.MatchString(w) {
					continue
				}
				prev := cmd[max(j-1, 0)]
				// <> (read-write) arrives as "<" then ">": the word before the ">" is the
				// input half.
				readWrite := prev == ">" && j >= 2 && iwaInputOp.MatchString(cmd[j-2])
				switch {
				case (prev == ">" && !readWrite) || prev == ">>":
				case readWrite || iwaInputOp.MatchString(prev):
					add(l, "assistant line reads the secret file %s by input redirection", w)
				case ci >= 0 && !allowed:
					add(l, "assistant line names the secret file %s in %q, which is not a non-reading command (iwaNonReaders)", w, cmd[ci])
				}
			}
			if ci < 0 {
				continue
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
			case name == "printenv" || name == "env" || (name == "set" && strings.Contains(joined, " -x ")) ||
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
		// backtick command substitution, the sibling of $( )
		"X=`cat secrets/master_password`",
		"export X=\"`cat secrets/bootstrap_token`\"",
		"sha256sum certs/server.key",
		"KEYORIX_ADMIN_PASSWORD=hunter2 ./bin/keyorix system init",
		// secrets whose name has no PASSWORD/PASSPHRASE/TOKEN/SECRET suffix but are in
		// config.SecretEnvVars
		"KEYORIX_API_KEY=hunter2 ./bin/keyorix secret list",
		"export KEYORIX_NOTIFY_SLACK_WEBHOOK=https://x",
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
		// a leading redirection in an unquoted fence is shell text, not a blockquote
		// marker: the line is still an assistant line
		">&2 cat secrets/master_password",
		">&2 printenv",
		"> /dev/stderr cat secrets/master_password",
		">&2 ./bin/keyorix mfa enroll",
		// a digit-prefixed or bare >& redirection is not the command word
		"2>&1 printenv",
		"2>/dev/null printenv",
		"2>/dev/null docker inspect backend",
		"2>/dev/null keyorix whoami",
		">& /dev/stderr printenv",
		// a leading input redirection is skipped as the command word but is still a
		// read, also when no command follows it (bash's $(< file))
		"X=$(< secrets/master_password)",
		"export X=\"$(<secrets/admin_password)\"",
		"< secrets/master_password cat",
		"<secrets/admin_password tr -d x",
		// a digit-prefixed input redirection (0<, 3<) or <> is a read too, also with
		// a command that is not in iwaReaders (read, mapfile, exec)
		"read -r X 0< secrets/master_password",
		"read -r X 0<secrets/master_password",
		"mapfile -t A 0< secrets/admin_password",
		"while read -r l; do :; done 0< secrets/master_password",
		"exec 3< secrets/master_password",
		"exec 3<> secrets/master_password",
		// env with no command after it prints the environment
		"env",
		"sudo env",
		"env | sort",
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
		want := strings.HasPrefix(line, "KEYORIX_ADMIN_PASSWORD=") || strings.HasPrefix(line, "KEYORIX_API_KEY=") ||
			strings.HasPrefix(line, "export KEYORIX_NOTIFY_SLACK_WEBHOOK=") || strings.HasPrefix(line, "keyorix ") || strings.HasSuffix(line, " keyorix whoami")
		if (len(f) != 0) != want {
			t.Errorf("human line %q: findings %+v, want reported=%v", line, f, want)
		}
	}
	// A line without a leading > inside a blockquoted fence ends the blockquote: it
	// is not part of the HUMAN STEP, so it is an assistant line. Forgetting the > on
	// one line must not exempt it.
	for _, line := range bad {
		if strings.HasPrefix(line, ">") {
			continue // a leading > is a blockquote marker inside a quoted fence
		}
		doc := strings.Replace(good, "> ./bin/keyorix mfa enroll\n", "> ./bin/keyorix mfa enroll\n"+line+"\n", 1)
		if f := iwaFind(iwaParse(doc)); len(f) == 0 {
			t.Errorf("planted line without > in a quoted fence not reported: %s", line)
		}
	}
	// A closing ``` without > still closes a quoted fence.
	closeNoQuote := strings.Replace(good, "> (umask 077; cat > secrets/db_password)\n> ```\n", "> (umask 077; cat > secrets/db_password)\n```\n", 1)
	if f := iwaFind(iwaParse(closeNoQuote)); len(f) != 0 {
		t.Errorf("a closing ``` without > must close the quoted fence: %+v", f)
	}
	// A fence is read as shell whatever its info string says, except ```text (the
	// prompt): a zsh, Bash or shell-session fence must not hide a read.
	for _, info := range []string{"zsh", "Bash", "shell-session", "BASH"} {
		doc := good + "\n```" + info + "\ncat secrets/master_password\n```\n"
		if f := iwaFind(iwaParse(doc)); len(f) == 0 {
			t.Errorf("read planted in a ```%s fence not reported", info)
		}
	}
	if f := iwaFind(iwaParse(good + "\n```text\ncat secrets/master_password\n```\n")); len(f) != 0 {
		t.Errorf("a ```text fence is not shell and must not be scanned: %+v", f)
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
