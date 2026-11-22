package cmd

// Vault-format import must not turn a YAML null or a mapping/sequence into secret text.
// Before the fix `value: ~` was stored as the literal "<nil>" and a nested mapping as Go
// map text ("map[...]"). These cases were left out of the YAML v4 baseline goldens
// (secret_import_yaml_v4_baseline_test.go) on purpose so they would not pin the defect.
// Inputs are placeholders; assertions never print a value.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseVaultString(t *testing.T, content string) ([]secretEntry, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return parseVault(path)
}

func TestParseVault_RejectsNullAndNonScalar(t *testing.T) {
	const marker = "MARKER-NOT-A-SECRET"
	cases := []struct {
		name, input string
		wantInErr   []string // entry names the error must mention
	}{
		{"format1_unquoted_tilde", "secret/env-1/db:\n  value: ~\n", []string{"secret/env-1/db", "value", "null"}},
		{"format1_unquoted_null", "secret/env-1/db:\n  value: null\n", []string{"secret/env-1/db", "value", "null"}},
		{"format1_empty_value", "secret/env-1/db:\n  value:\n", []string{"secret/env-1/db", "value", "null"}},
		{"format2_null_field", "secret/env-1/db:\n  password: ~\n  username: app\n", []string{"secret/env-1/db", "password", "null"}},
		{"format1_nested_mapping", "secret/env-1/db:\n  value:\n    inner: " + marker + "\n", []string{"secret/env-1/db", "value", "mapping"}},
		{"format2_nested_mapping", "secret/env-1/db:\n  password:\n    inner: " + marker + "\n  username: app\n", []string{"secret/env-1/db", "password", "mapping"}},
		{"format1_sequence", "secret/env-1/db:\n  value: [" + marker + "]\n", []string{"secret/env-1/db", "value", "sequence"}},
		{"format2_sequence", "secret/env-1/db:\n  tags:\n    - " + marker + "\n  username: app\n", []string{"secret/env-1/db", "tags", "sequence"}},
		{"path_block_null", "secret/env-1/db: ~\n", []string{"secret/env-1/db", "null"}},
		{"path_block_empty", "secret/env-1/db:\n", []string{"secret/env-1/db", "null"}},
		{"alias_to_mapping_value", "base: &b\n  inner: " + marker + "\nsecret/env-1/db:\n  value: *b\n", []string{"secret/env-1/db", "value", "mapping"}},
		{"bad_entry_after_good_one_imports_nothing", "secret/env-1/ok:\n  value: PLACEHOLDER\nsecret/env-1/db:\n  value: ~\n", []string{"secret/env-1/db", "null"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := parseVaultString(t, tc.input)
			if err == nil {
				t.Fatalf("expected a rejection, got %d entries", len(entries))
			}
			if len(entries) != 0 {
				t.Fatalf("a rejected file must import nothing, got %d entries", len(entries))
			}
			msg := err.Error()
			for _, want := range tc.wantInErr {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
			for _, bad := range []string{marker, "<nil>", "map[", "PLACEHOLDER"} {
				if strings.Contains(msg, bad) {
					t.Errorf("error leaks value text %q: %q", bad, msg)
				}
			}
		})
	}
}

// TestParseVault_ScalarsKeepTheirText pins that strings, numbers and booleans are untouched
// by the null/non-scalar check, including quoted spellings of the YAML null tokens.
func TestParseVault_ScalarsKeepTheirText(t *testing.T) {
	cases := []struct {
		name, input, wantName, wantValue string
	}{
		{"string", "secret/env-1/db:\n  value: PLACEHOLDER\n", "db", "PLACEHOLDER"},
		{"quoted_tilde_is_literal", "secret/env-1/db:\n  value: \"~\"\n", "db", "~"},
		{"single_quoted_tilde_is_literal", "secret/env-1/db:\n  value: '~'\n", "db", "~"},
		{"quoted_null_is_literal", "secret/env-1/db:\n  value: \"null\"\n", "db", "null"},
		{"integer", "secret/env-1/db:\n  value: 12345\n", "db", "12345"},
		{"float", "secret/env-1/ratio:\n  value: 0.50\n", "ratio", "0.5"},
		{"bool", "secret/env-1/flags:\n  enabled: true\n", "flags-enabled", "true"},
		{"format2_quoted_null", "secret/env-1/db:\n  password: \"null\"\n  other: x\n", "db-password", "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := parseVaultString(t, tc.input)
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			found := false
			for _, e := range entries {
				if e.Name == tc.wantName {
					found = true
					if e.Value != tc.wantValue {
						t.Errorf("entry %q stored text changed (len %d, want len %d)", e.Name, len(e.Value), len(tc.wantValue))
					}
				}
			}
			if !found {
				t.Fatalf("entry %q missing from %d parsed entries", tc.wantName, len(entries))
			}
		})
	}
}
