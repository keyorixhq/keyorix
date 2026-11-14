// scripts_header_var_guard_test.go -- SCRIPTS-SECRETS-4. Calibration pair for
// scanShellForHeaderVars (see docs_no_literal_secrets_test.go): a credential header held in
// a shell variable and passed to curl as `-H "$NAME"` is red; the 0600 header file is green.
package cmd

import "testing"

func TestScriptsHeaderVarGuardCalibration(t *testing.T) {
	mustFlag := map[string]string{
		// The shape demo/vault-migration/run.sh carried.
		"bearer var":      "AUTH_HDR=\"Authorization: Bearer ${TOKEN}\"\ncurl -sf -H \"$AUTH_HDR\" \"$URL/api/v1/projects\"",
		"braced use":      "H=\"Authorization: Bearer $T\"\ncurl -sf -H \"${H}\" \"$URL\"",
		"vault token var": "VH='X-Vault-Token: abc'\ncurl -s --header \"$VH\" \"$A\"",
		"header equals":   "VH=\"X-Vault-Token: $T\"\ncurl -s --header=\"$VH\" \"$A\"",
		"attached quote":  "H=\"Cookie: s=$S\"\ncurl -s -H\"$H\" \"$A\"",
		"local var":       "f() {\n  local h=\"Authorization: Bearer $1\"\n  curl -s -H \"$h\" \"$URL\"\n}",
		"export var":      "export H=\"Proxy-Authorization: Basic $B\"\ncurl -x \"$P\" -H \"$H\" \"$URL\"",
		"use on cont":     "H=\"Authorization: Bearer $T\"\ncurl -sf \\\n  -H \"$H\" \\\n  \"$URL\"",
	}
	for name, sh := range mustFlag {
		if len(scanShellForSecrets(sh)) == 0 {
			t.Errorf("header-variable guard missed (%s): %q", name, sh)
		}
	}
	mustPass := map[string]string{
		"header file":        "printf 'Authorization: Bearer %s\\n' \"$T\" >\"$hdr\"\ncurl -sf -H @\"$hdr\" \"$URL\"",
		"content type var":   "CT=\"Content-Type: application/json\"\ncurl -sf -H \"$CT\" \"$URL\"",
		"cred var not used":  "H=\"Authorization: Bearer $T\"\necho ready",
		"other var as H":     "H=\"Authorization: Bearer $T\"\nOTHER='Accept: x'\ncurl -sf -H \"$OTHER\" \"$URL\"",
		"name prefix":        "H=\"Authorization: Bearer $T\"\ncurl -sf -H \"$H2\" \"$URL\"",
		"allow marker use":   "H=\"Authorization: Bearer fixed\"\ncurl -sf -H \"$H\" \"$URL\" # docs-secrets:allow (fixture on a throwaway server)",
		"allow marker def":   "H=\"Authorization: Bearer fixed\" # docs-secrets:allow (fixture)\ncurl -sf -H \"$H\" \"$URL\"",
		"read from stdin":    "IFS= read -r h\nexec wget -q --header=\"$h\" -O- \"$1\"",
		"comment only":       "# H=\"Authorization: Bearer $T\" then curl -H \"$H\"",
		"flag value not hdr": "H=\"Authorization: Bearer $T\"\ntar -H \"$X\" -cf a.tar .",
	}
	for name, sh := range mustPass {
		// "other var as H" and "name prefix" must be green; "allow marker def" drops the
		// definition line, so the use finds no credential assignment.
		if hits := scanShellForSecrets(sh); len(hits) != 0 {
			t.Errorf("header-variable guard false positive (%s): %q -> %+v", name, sh, hits)
		}
	}
}
