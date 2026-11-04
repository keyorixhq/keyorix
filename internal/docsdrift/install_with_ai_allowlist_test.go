package docsdrift

import (
	"strings"
	"testing"
)

// INSTALL-AI-TAILS-1 item 1: the secret-read rule of TestInstallWithAIIsSecretBlind
// is an allowlist of non-reading commands (iwaNonReaders), not a denylist of
// reading verbs. Each shape below names a secret path in a command that is not on
// the allowlist, so it must be reported; the allowlisted shapes must stay green.

const iwaAllowlistDoc = "## The prompt\n\n```text\nSECRET-BLIND\n```\n\n## Steps for the assistant\n\n```bash\n" +
	"rm -f secrets/bootstrap_token\n%s\n```\n"

func iwaAllowlistFindings(line string) []secretFinding {
	return iwaFind(iwaParse(strings.Replace(iwaAllowlistDoc, "%s", line, 1)))
}

// iwaOnlyAllowlistFindings drops the findings that are not about a secret path
// (the page skeleton above has no posture proof and an incomplete prompt).
func iwaOnlyAllowlistFindings(line string) []secretFinding {
	var out []secretFinding
	for _, f := range iwaAllowlistFindings(line) {
		if strings.Contains(f.What, "secret file") {
			out = append(out, f)
		}
	}
	return out
}

func TestInstallWithAIAllowlistRefusesEveryOtherCommand(t *testing.T) {
	for _, line := range []string{
		"eval \"cat secrets/master_password\"",
		"eval 'cat /run/secrets/master_password'",
		"nl secrets/master_password",
		"less secrets/master_password",
		"awk '1' secrets/master_password",
		"awk 1 secrets/master_password",
		"xxd secrets/master_password",
		"base64 secrets/master_password",
		"python3 -c \"print(open('secrets/master_password').read())\"",
		"frobnicate secrets/master_password",
		"/bin/cat secrets/master_password",
		"command cat secrets/master_password",
		"\\cat secrets/master_password",
		"find secrets -type f -exec cat {} +",
		// REVFIX-3951-1: the project binaries are allowlisted, but `keyorix run` runs
		// any command and a reader after the binary is still a reader.
		"./bin/keyorix run --env prod --var X=y -- cat secrets/master_password",
		"./bin/keyorix run --env prod --var X=y -- sh -c 'cat secrets/master_password'",
		"./bin/keyorix run -- nl secrets/master_password",
		"./bin/keyorix-server admin migrate cat secrets/master_password",
		// a command word that merely contains a secret path is not a bare noun in a fence
		"secrets/../../../bin/cat secrets/master_password",
	} {
		if len(iwaOnlyAllowlistFindings(line)) == 0 {
			t.Errorf("secret read not reported: %s", line)
		}
	}
}

func TestInstallWithAIAllowlistKeepsNonReadingCommandsGreen(t *testing.T) {
	for _, line := range []string{
		"test -f secrets/master_password",
		"[ -f secrets/master_password ]",
		"[[ -s secrets/master_password ]]",
		"ls -l secrets/master_password",
		"ls -l secrets/",
		"stat secrets/master_password",
		"stat -c %a secrets/master_password",
		"sudo chown root:1000 secrets/master_password",
		"chmod 600 secrets/master_password",
		"rm -f secrets/master_password",
		"shred -u secrets/admin_password",
		"touch secrets/db_password",
		"KEYORIX_MASTER_PASSWORD_FILE=secrets/master_password ./bin/keyorix-server admin migrate",
		"./bin/keyorix run --env prod -- ls -l secrets/master_password",
	} {
		if f := iwaOnlyAllowlistFindings(line); len(f) != 0 {
			t.Errorf("non-reading line reported: %s: %+v", line, f)
		}
	}
}
