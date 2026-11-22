// secret_import_parsers.go — format parsers for `secret import`: parseImportFile
// dispatches to parseDotenv/parseVault/parseJSON. Pure local file parsing, no REST calls.
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/cli/internal/cliout"
	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"github.com/keyorixhq/keyorix/internal/yamlsafe"
)

// maxImportFileBytes caps how much of an untrusted --file import gets read into memory
// in one shot. parseVault and parseJSON both read the whole file (the dotenv parser is
// already bounded via bufio.Scanner's line limit) — without a cap, a booby-trapped
// multi-GB import file can OOM-kill the operator's own CLI process.
const maxImportFileBytes = 100 << 20 // 100 MiB

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

// keyHasControlChars reports whether a parsed secret name contains any Unicode control
// character (C0/C1 controls, including the ESC byte that introduces an ANSI escape
// sequence). Secret names are simple identifiers, so there is no legitimate case for
// one to contain control characters — reject rather than silently strip: a dropped byte
// could change which existing secret an import collides with.
func keyHasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// valueHasDangerousControlChars reports whether a parsed secret value contains a
// control character that could manipulate a terminal when later echoed back (dry-run
// preview, error messages) — ESC-introduced ANSI/C1 escapes and other non-printable
// bytes. Plain \t/\n/\r are tolerated (real credential material, e.g. PEM keys, is
// legitimately multi-line) — the actual bytes are never silently mangled.
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

// validateImportedEntry rejects a parsed key/value pair containing raw control
// characters or ANSI escapes, naming the offending key so the operator can locate and
// fix (or knowingly re-export) the source record.
func validateImportedEntry(e secretEntry) error {
	if keyHasControlChars(e.Name) {
		return fmt.Errorf("secret name %q contains control characters or ANSI escape sequences; rejecting import", cliout.SanitizeForTerminal(e.Name))
	}
	if valueHasDangerousControlChars(e.Value) {
		return fmt.Errorf("value for secret %q contains control characters or ANSI escape sequences; rejecting import (if this is expected binary-ish data, re-export it without escape bytes)", cliout.SanitizeForTerminal(e.Name))
	}
	return nil
}

// parseImportFile dispatches to the correct parser based on format string.
func parseImportFile(path, format string) ([]secretEntry, error) {
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

// parseJSONBytes parses a flat key-value JSON object from already-read bytes (the
// encrypted-json import path, where the bytes have already been decrypted in memory).
func parseJSONBytes(data []byte) ([]secretEntry, error) {
	var raw map[string]any
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

// unquoteDotenvSingleQuoted reverses writeDotenv's exact escaping scheme for a
// single-quoted value: the outer quotes are stripped, then every occurrence of the
// close-escape-reopen sequence '\” is folded back to a literal '. A naive "just strip
// the first and last byte" (the previous implementation) leaves every embedded '\”
// artifact in the value, corrupting any value containing an apostrophe on reimport
// (FuzzDotenvRoundTrip, CLI-FUZZ target 3b).
func unquoteDotenvSingleQuoted(inner string) string {
	return strings.ReplaceAll(inner, `'\''`, `'`)
}

// parseDotenv reads a standard .env file: '#'-prefixed and blank lines are skipped;
// KEY=VALUE, value may be quoted with " or '; keys with empty values are skipped.
func parseDotenv(path string) ([]secretEntry, error) {
	f, _, err := regularfile.Open("import file", path)
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
			switch {
			case val[0] == '"' && val[len(val)-1] == '"':
				val = val[1 : len(val)-1]
			case val[0] == '\'' && val[len(val)-1] == '\'':
				val = unquoteDotenvSingleQuoted(val[1 : len(val)-1])
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
	data, err := regularfile.ReadFile("import file", path)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := yamlsafe.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	var entries []secretEntry
	for pathKey, v := range raw {
		parts := strings.Split(strings.Trim(pathKey, "/"), "/")
		segment := parts[len(parts)-1]
		if segment == "" {
			continue
		}
		if v == nil {
			return nil, fmt.Errorf("secret path %q has no value (null); rejecting import, nothing was imported", cliout.SanitizeForTerminal(pathKey))
		}
		fields, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if len(fields) == 1 {
			if fval, isFormat1 := fields["value"]; isFormat1 {
				if err := checkVaultScalar(pathKey, "value", fval); err != nil {
					return nil, err
				}
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
			if err := checkVaultScalar(pathKey, key, fval); err != nil {
				return nil, err
			}
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

// checkVaultScalar rejects a vault-format field whose decoded value is YAML null or a
// mapping/sequence. Formatting those with %v would store the text "<nil>" or Go map/slice
// text as the secret's value. The error names the path and field, never the value.
// parseVault returns the error before any entry reaches the caller, so a rejected file
// imports nothing (all-or-nothing, like validateImportedEntry).
func checkVaultScalar(pathKey, field string, v any) error {
	var kind string
	switch v.(type) {
	case nil:
		kind = "null"
	case map[string]any, map[any]any:
		kind = "a mapping"
	case []any:
		kind = "a sequence"
	default:
		return nil
	}
	return fmt.Errorf("secret path %q field %q is %s, not a scalar value; rejecting import, nothing was imported (quote the value if it is meant as literal text)",
		cliout.SanitizeForTerminal(pathKey), cliout.SanitizeForTerminal(field), kind)
}

// parseJSON reads a flat key-value JSON object: {"DB_PASSWORD": "supersecret123"}.
func parseJSON(path string) ([]secretEntry, error) {
	if err := checkImportFileSize(path); err != nil {
		return nil, err
	}
	data, err := regularfile.ReadFile("import file", path)
	if err != nil {
		return nil, err
	}
	return parseJSONBytes(data)
}
