package cmd

// v4-only baseline for the go.yaml.in/yaml/v4 paths `keyorix secret import --format vault`
// uses (#4574): typed decode into map[string]any through parseVault (yamlsafe.Unmarshal,
// first document only), every document of a `---` stream through the v4 Loader, and what
// strict KnownFields mode does on a map target.
//
// Expected outputs are committed goldens in testdata/yaml_v4_baseline, not a second
// parser. Regenerate after reviewing a go-yaml bump with
//
//	KEYORIX_UPDATE_GOLDEN=1 go test ./cmd -run 'TestYAMLV4Baseline'
//
// The goldens record entry names and value lengths, never values; inputs are placeholders.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

type v4bCase struct{ name, input string }

func v4bFirstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func v4bGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "yaml_v4_baseline", name+".golden")
	if os.Getenv("KEYORIX_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil { //nolint:gosec // golden test data, not a secret
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with KEYORIX_UPDATE_GOLDEN=1 after reviewing the output): %v", path, err)
	}
	if string(want) != got {
		t.Fatalf("golden %s differs: a go-yaml change altered v4 behaviour (review, then regenerate)\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

var v4bVaultCases = []v4bCase{
	{"format1_value_only", "secret/env-1/db:\n  value: PLACEHOLDER\n"},
	{"format2_fields", "secret/env-1/db:\n  password: PLACEHOLDER\n  username: app\n"},
	{"int_value_is_stringified", "secret/env-1/db:\n  value: 12345\n"},
	{"bool_value_is_stringified", "secret/env-1/flags:\n  enabled: true\n"},
	{"float_value_is_stringified", "secret/env-1/ratio:\n  value: 0.50\n"},
	{"empty_string_value_is_skipped", "secret/env-1/db:\n  value: \"\"\n"},
	{"non_mapping_entry_is_skipped", "secret/env-1/db: not-a-map\n"},
	{"trailing_slash_path", "secret/env-1/db/:\n  value: PLACEHOLDER\n"},
	{"anchor_and_alias", "base: &b\n  value: PLACEHOLDER\ncopy: *b\n"},
	{"merge_key", "base: &b\n  user: app\nderived:\n  <<: *b\n  extra: x\n"},
	{"duplicate_path_key", "a:\n  value: one\na:\n  value: two\n"},
	{"duplicate_field_key", "a:\n  value: one\n  value: two\n"},
	{"two_documents_first_wins", "first:\n  value: one\n---\nsecond:\n  value: two\n"},
	{"empty_file", ""},
	{"top_level_sequence", "- a\n- b\n"},
	{"top_level_scalar", "just a string\n"},
	{"unterminated_flow", "a: {value: x\n"},
}

func TestYAMLV4Baseline_VaultTypedDecode(t *testing.T) {
	var out strings.Builder
	dir := t.TempDir()
	for _, tc := range v4bVaultCases {
		path := filepath.Join(dir, "vault.yaml")
		if err := os.WriteFile(path, []byte(tc.input), 0o600); err != nil {
			t.Fatal(err)
		}
		entries, err := parseVault(path)
		if err != nil {
			fmt.Fprintf(&out, "%s: reject | %s\n", tc.name, v4bFirstLine(err.Error()))
			continue
		}
		lines := make([]string, 0, len(entries))
		for _, e := range entries {
			lines = append(lines, fmt.Sprintf("%s(len %d)", e.Name, len(e.Value)))
		}
		sort.Strings(lines) // parseVault walks a map: order is not part of the contract
		fmt.Fprintf(&out, "%s: accept | %d entr(ies) [%s]\n", tc.name, len(entries), strings.Join(lines, ", "))
	}
	v4bGolden(t, "vault_typed_decode", out.String())
}

// v4bStream loads every document with the v4 Loader into a fresh map.
func v4bStream(data string, opts ...yaml.Option) (docs []string, err error) {
	l, err := yaml.NewLoader(strings.NewReader(data), opts...)
	if err != nil {
		return nil, err
	}
	for range 64 {
		var m map[string]any
		err := l.Load(&m)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		docs = append(docs, "keys ["+strings.Join(keys, ", ")+"]")
	}
	return docs, errors.New("loader did not reach EOF within 64 documents")
}

var v4bMultiCases = []v4bCase{
	{"one_document", "a:\n  value: x\n"},
	{"two_documents", "a:\n  value: x\n---\nb:\n  value: y\n"},
	{"second_document_not_a_mapping", "a:\n  value: x\n---\n- b\n"},
	{"second_document_syntax_error", "a:\n  value: x\n---\nb: {value: y\n"},
	{"empty_second_document", "a:\n  value: x\n---\n"},
	{"anchor_does_not_cross_documents", "a: &x\n  value: y\n---\nb: *x\n"},
	{"empty_input", ""},
}

func TestYAMLV4Baseline_MultiDocumentStream(t *testing.T) {
	var out strings.Builder
	for _, tc := range v4bMultiCases {
		fmt.Fprintf(&out, "%s:\n", tc.name)
		docs, err := v4bStream(tc.input)
		for i, d := range docs {
			fmt.Fprintf(&out, "  doc %d: accept | %s\n", i+1, d)
		}
		if err != nil {
			fmt.Fprintf(&out, "  doc %d: reject | %s\n", len(docs)+1, v4bFirstLine(err.Error()))
		}
		fmt.Fprintf(&out, "  documents decoded: %d\n", len(docs))
	}
	v4bGolden(t, "vault_multi_document", out.String())
}

// TestYAMLV4Baseline_KnownFieldsOnAMapTarget pins that strict mode has nothing to reject
// when the target is a map: the import file's keys are data, not a closed field set, so an
// "unknown key" check cannot protect this path and none is expected from v4.
func TestYAMLV4Baseline_KnownFieldsOnAMapTarget(t *testing.T) {
	const in = "anything:\n  goes: here\nunknown_top_level: 1\n"
	plain, err := v4bStream(in)
	if err != nil || len(plain) != 1 {
		t.Fatalf("plain decode: docs=%v err=%v", plain, err)
	}
	strict, err := v4bStream(in, yaml.WithKnownFields())
	if err != nil || len(strict) != 1 {
		t.Fatalf("strict decode of a map target must accept the same input: docs=%v err=%v", strict, err)
	}
	if plain[0] != strict[0] {
		t.Fatalf("strict and plain decode of a map disagree: %v vs %v", plain, strict)
	}
}
