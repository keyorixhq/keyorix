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

	"gopkg.in/yaml.v3"
)

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
		entries = append(entries, secretEntry{Name: key, Value: val})
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
					entries = append(entries, secretEntry{Name: segment, Value: val})
				}
				continue
			}
		}
		for key, fval := range fields {
			val := fmt.Sprintf("%v", fval)
			if key == "" || val == "" {
				continue
			}
			entries = append(entries, secretEntry{Name: segment + "-" + key, Value: val})
		}
	}
	return entries, nil
}

// parseJSON reads a flat key-value JSON object.
//
//	{"DB_PASSWORD": "supersecret123", "API_KEY": "sk_live_abc123"}
func parseJSON(path string) ([]secretEntry, error) {
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
		entries = append(entries, secretEntry{Name: k, Value: val})
	}
	return entries, nil
}
