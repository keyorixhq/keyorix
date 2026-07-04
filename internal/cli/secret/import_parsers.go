// import_parsers.go — Format parsers: parseDotenv, parseVault, parseJSON, parseFile.
//
// Each parser reads a file and returns []secretEntry.
// The command, orchestration, and resolution helpers live in import.go.
package secret

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// maxImportFileBytes caps how much of an untrusted --file import we'll read into
// memory in one shot. parseVault and parseJSON both os.ReadFile the whole input
// (the dotenv parser is already bounded via bufio.Scanner's 64KiB line limit), so
// without a cap a booby-trapped multi-GB import file can OOM-kill the operator's
// own CLI process. This only protects the local session; there is no cross-tenant
// or server-side impact.
const maxImportFileBytes = 100 << 20 // 100 MiB

// checkImportFileSize stats path and rejects files over maxImportFileBytes before
// any parser reads the full contents into memory.
func checkImportFileSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxImportFileBytes {
		return fmt.Errorf("import file %q is %d bytes, which exceeds the %d byte limit", path, info.Size(), maxImportFileBytes)
	}
	return nil
}

// keyHasControlChars reports whether a parsed secret name contains any Unicode
// control character (C0/C1 controls, including the ESC byte that introduces an
// ANSI escape sequence). Unlike sanitizeForTerminal (import.go), which only
// scrubs bytes for terminal DISPLAY, this gates what is actually stored.
// Secret names are simple identifiers — see core.SecretNamePolicy, whose
// operator-configured pattern is exactly the kind of convention a name with
// raw control bytes would already violate — so there is no legitimate case for
// one to contain control characters. Reject rather than silently strip: a
// dropped byte could change which existing secret an import collides with.
func keyHasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// valueHasDangerousControlChars reports whether a parsed secret value contains
// a control character that could manipulate a terminal when the value is
// later echoed back (dry-run preview, "already exists" listings, an error
// quoting it) — ESC-introduced ANSI/C1 escape sequences and other
// non-printable control bytes. Plain \t, \n, and \r are tolerated because
// real credential material legitimately contains them (PEM-encoded private
// keys and certificates are multi-line, for example), and this codebase must
// not silently mangle the actual secret bytes it stores on an operator's
// behalf. Values that trip this check are rejected — never auto-stripped —
// so a suspicious import fails loudly instead of quietly corrupting
// credential material.
func valueHasDangerousControlChars(s string) bool {
	for _, r := range s {
		switch r {
		case '\t', '\n', '\r':
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// validateImportedEntry rejects a parsed key/value pair that contains raw
// control characters or ANSI escape sequences, naming the offending key so
// the operator can locate and fix (or knowingly re-export) the source record.
// See #295: previously only sanitizeForTerminal existed, and it cleaned
// display output only — the value actually sent to the server was untouched.
func validateImportedEntry(e secretEntry) error {
	if keyHasControlChars(e.Name) {
		return fmt.Errorf("secret name %q contains control characters or ANSI escape sequences; rejecting import", sanitizeForTerminal(e.Name))
	}
	if valueHasDangerousControlChars(e.Value) {
		return fmt.Errorf("value for secret %q contains control characters or ANSI escape sequences; rejecting import (if this is expected binary-ish data, re-export it without escape bytes)", sanitizeForTerminal(e.Name))
	}
	return nil
}

// parseFile dispatches to the correct parser based on format string.
func parseFile(path, format string) ([]secretEntry, error) {
	switch strings.ToLower(format) {
	case "dotenv", "env":
		return parseDotenv(path)
	case "vault":
		return parseVault(path)
	case "json": //nolint:goconst
		return parseJSON(path)
	default:
		return nil, fmt.Errorf("unknown format %q (supported: dotenv, vault, json)", format)
	}
}

// parseDotenv reads a standard .env file.
// Rules:
//   - Lines starting with # are comments — skipped.
//   - Blank lines are skipped.
//   - KEY=VALUE; value may be quoted with " or '.
//   - Keys with empty values are skipped.
func parseDotenv(path string) ([]secretEntry, error) {
	f, err := os.Open(path) // #nosec G304 — path already cleaned by caller
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var entries []secretEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key == "" || val == "" {
			continue
		}
		entry := secretEntry{Name: key, Value: val}
		if err := validateImportedEntry(entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// parseVault reads a Medusa/Vault YAML export in one of two formats.
//
// Format 1 — Keyorix export (single "value" key per path):
//
//	secret/production/database-password:
//	  value: supersecret123
//
// → secret named "database-password" with value "supersecret123".
//
// Format 2 — real Vault/Medusa export (multiple keys per path):
//
//	secret/production/database:
//	  password: REPLACE_WITH_YOUR_DB_PASSWORD
//	  username: app_user
//
// → secrets named "database-password" and "database-username".
//
// Detection: if the block has exactly one key named "value" → Format 1.
func parseVault(path string) ([]secretEntry, error) {
	if err := checkImportFileSize(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	var entries []secretEntry
	for pathKey, v := range raw {
		parts := strings.Split(strings.Trim(pathKey, "/"), "/")
		segment := parts[len(parts)-1]
		if segment == "" {
			continue
		}
		fields, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		if len(fields) == 1 {
			if fval, isFormat1 := fields["value"]; isFormat1 {
				val := fmt.Sprintf("%v", fval)
				if val != "" {
					entry := secretEntry{Name: segment, Value: val}
					if err := validateImportedEntry(entry); err != nil {
						return nil, err
					}
					entries = append(entries, entry)
				}
				continue
			}
		}
		for key, fval := range fields {
			val := fmt.Sprintf("%v", fval)
			if key == "" || val == "" {
				continue
			}
			entry := secretEntry{Name: segment + "-" + key, Value: val}
			if err := validateImportedEntry(entry); err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// parseJSON reads a flat key-value JSON object.
//
//	{"DB_PASSWORD": "supersecret123", "API_KEY": "sk_live_abc123"}
func parseJSON(path string) ([]secretEntry, error) {
	if err := checkImportFileSize(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var entries []secretEntry
	for k, v := range raw {
		val := fmt.Sprintf("%v", v)
		if k == "" || val == "" {
			continue
		}
		entry := secretEntry{Name: k, Value: val}
		if err := validateImportedEntry(entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
