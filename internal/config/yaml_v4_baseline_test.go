package config

// v4-only baseline for the three go.yaml.in/yaml/v4 paths production uses that no other
// test pins since #4573 retired yaml.v3 and the v3-vs-v4 differential fuzz targets
// (#4574): (1) typed decode into Config, (2) every document of a `---` stream through the
// v4 Loader, (3) strict KnownFields mode.
//
// The expected outputs are committed goldens (testdata/yaml_v4_baseline/*.golden), not a
// second parser: a go-yaml bump that changes what v4 accepts, rejects or decodes shows up
// as a readable diff of those files. Regenerate after reviewing the change with
//
//	KEYORIX_UPDATE_GOLDEN=1 go test ./internal/config -run 'TestYAMLV4Baseline'
//
// The inputs hold placeholder values only; no real configuration or credentials.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	yaml "go.yaml.in/yaml/v4"
)

// baselineProjection is the slice of Config the goldens record: typed fields of several
// kinds (string, int, bool) from different nesting depths. A tag or type change on any of
// them changes the golden.
type baselineProjection struct {
	Environment       string `json:"environment"`
	StorageType       string `json:"storage_type"`
	NativeReadPoolMax int    `json:"native_read_pool_max"`
	RequireMFA        bool   `json:"require_mfa"`
	MinimumCLIVersion string `json:"minimum_cli_version"`
}

func project(c *Config) baselineProjection {
	return baselineProjection{
		Environment:       c.Environment,
		StorageType:       c.Storage.Type,
		NativeReadPoolMax: c.Storage.Database.NativeReadPoolMax,
		RequireMFA:        c.Security.RequireMFA,
		MinimumCLIVersion: c.MinimumCLIVersion,
	}
}

func projectJSON(t *testing.T, c *Config) string {
	t.Helper()
	b, err := json.Marshal(project(c))
	require.NoError(t, err)
	return string(b)
}

// firstLine keeps the golden free of multi-line error text while still naming the cause.
func firstLine(err error) string {
	return strings.SplitN(err.Error(), "\n", 2)[0]
}

// checkGolden compares got with testdata/yaml_v4_baseline/<name>.golden, or rewrites it
// when KEYORIX_UPDATE_GOLDEN=1.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "yaml_v4_baseline", name+".golden")
	if os.Getenv("KEYORIX_UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644)) //nolint:gosec // golden test data, not a secret
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden; run with KEYORIX_UPDATE_GOLDEN=1 after reviewing the output")
	require.Equal(t, string(want), got, "golden %s differs: a go-yaml change altered v4 behaviour (review, then regenerate)", path)
}

type baselineCase struct {
	name  string
	input string
}

// typedDecodeCases: the production path is Load(path) -> strict decode into Config.
var typedDecodeCases = []baselineCase{
	{"empty_file_is_all_defaults", ""},
	{"comments_only_is_all_defaults", "# nothing here\n"},
	{"minimal_scalars", "environment: staging\nminimum_cli_version: \"1.2.0\"\n"},
	{"nested_typed_int", "storage:\n  type: postgres\n  database:\n    native_read_pool_max: 12\n"},
	{"explicit_bool_false", "security:\n  require_mfa: false\n"},
	{"explicit_bool_true", "security:\n  require_mfa: true\n"},
	{"int_where_string_expected", "environment: 7\n"},
	{"string_where_int_expected", "storage:\n  database:\n    native_read_pool_max: many\n"},
	{"string_where_bool_expected", "security:\n  require_mfa: \"maybe\"\n"},
	{"mapping_where_scalar_expected", "environment:\n  nested: x\n"},
	{"sequence_where_mapping_expected", "storage:\n  - type\n"},
	{"null_value_keeps_zero", "environment: ~\nstorage:\n  type: null\n"},
	{"anchor_and_alias_scalar", "environment: &e production\nminimum_cli_version: *e\n"},
	{"duplicate_known_key", "environment: a\nenvironment: b\n"},
	{"unterminated_flow", "storage: {type: postgres\n"},
	{"tab_indentation", "storage:\n\ttype: postgres\n"},
	{"top_level_scalar", "just a string\n"},
	{"top_level_sequence", "- environment\n- storage\n"},
}

func TestYAMLV4Baseline_TypedDecode(t *testing.T) {
	var out strings.Builder
	for _, tc := range typedDecodeCases {
		path := filepath.Join(t.TempDir(), "keyorix.yaml")
		require.NoError(t, os.WriteFile(path, []byte(tc.input), 0o600))
		cfg, err := Load(path)
		if err != nil {
			fmt.Fprintf(&out, "%s: reject | %s\n", tc.name, firstLine(errorAfterPrefix(err)))
			continue
		}
		fmt.Fprintf(&out, "%s: accept | %s\n", tc.name, projectJSON(t, cfg))
	}
	checkGolden(t, "typed_decode", out.String())
}

// errorAfterPrefix drops the config file path (a per-run temp dir) from Load's error so
// the golden is stable.
func errorAfterPrefix(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "failed to unmarshal config: "); i >= 0 {
		return errors.New(strings.TrimPrefix(msg[i:], "failed to "))
	}
	return errors.New("other: " + firstLine(err))
}

// loadStream decodes every document of data through the v4 Loader into fresh Configs, the
// way a multi-document consumer must (a single Decode/Unmarshal sees only the first).
func loadStream(data string, opts ...yaml.Option) (docs []baselineProjection, err error) {
	l, err := yaml.NewLoader(strings.NewReader(data), opts...)
	if err != nil {
		return nil, err
	}
	for range 64 { // a Loader that never reaches EOF must fail the test, not hang it
		var c Config
		err := l.Load(&c)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, project(&c))
	}
	return docs, errors.New("loader did not reach EOF within 64 documents")
}

var multiDocCases = []baselineCase{
	{"one_document", "environment: a\n"},
	{"two_documents", "environment: a\n---\nenvironment: b\n"},
	{"leading_marker", "---\nenvironment: a\n---\nstorage:\n  type: postgres\n"},
	{"explicit_end_marker", "environment: a\n...\n---\nenvironment: b\n...\n"},
	{"empty_second_document", "environment: a\n---\n"},
	{"comment_only_second_document", "environment: a\n---\n# nothing\n"},
	{"second_document_wrong_type", "environment: a\n---\nstorage:\n  database:\n    native_read_pool_max: many\n"},
	{"second_document_syntax_error", "environment: a\n---\nstorage: {type: postgres\n"},
	{"anchor_does_not_cross_documents", "environment: &e a\n---\nminimum_cli_version: *e\n"},
	{"three_documents_last_differs", "environment: a\n---\nenvironment: b\n---\nsecurity:\n  require_mfa: true\n"},
	{"empty_input", ""},
}

func TestYAMLV4Baseline_MultiDocumentStream(t *testing.T) {
	var out strings.Builder
	for _, tc := range multiDocCases {
		fmt.Fprintf(&out, "%s:\n", tc.name)
		docs, err := loadStream(tc.input, yaml.WithKnownFields())
		for i, d := range docs {
			b, jerr := json.Marshal(d)
			require.NoError(t, jerr)
			fmt.Fprintf(&out, "  doc %d: accept | %s\n", i+1, b)
		}
		if err != nil {
			fmt.Fprintf(&out, "  doc %d: reject | %s\n", len(docs)+1, firstLine(err))
		}
		fmt.Fprintf(&out, "  documents decoded: %d\n", len(docs))
	}
	checkGolden(t, "multi_document", out.String())
}

// TestYAMLV4Baseline_PlainDecodeSeesOnlyTheFirstDocument pins the contrast the stream
// test relies on: Unmarshal and a single Decode stop after document one, so a consumer
// that needs every document has to loop the Loader.
func TestYAMLV4Baseline_PlainDecodeSeesOnlyTheFirstDocument(t *testing.T) {
	const stream = "environment: first\n---\nenvironment: second\n"
	var c Config
	require.NoError(t, yaml.NewDecoder(strings.NewReader(stream)).Decode(&c))
	require.Equal(t, "first", c.Environment)

	docs, err := loadStream(stream)
	require.NoError(t, err)
	require.Len(t, docs, 2)
	require.Equal(t, "second", docs[1].Environment)

	var all []Config
	require.NoError(t, yaml.Load([]byte(stream), &all, yaml.WithAllDocuments()))
	require.Len(t, all, 2)
	require.Equal(t, "second", all[1].Environment)
}

var knownFieldsCases = []baselineCase{
	{"all_keys_known", "environment: a\nstorage:\n  type: postgres\n"},
	{"unknown_top_level_key", "environment: a\nenvironmnt: typo\n"},
	{"unknown_nested_key", "storage:\n  type: postgres\n  databse: {}\n"},
	{"known_key_under_wrong_parent", "encryption:\n  enabled: true\n"},
	{"unknown_key_in_flow_mapping", "storage: {type: postgres, bogus: 1}\n"},
	{"unknown_key_with_null_value", "bogus: ~\n"},
	{"unknown_key_with_nested_value", "bogus:\n  a: [1, 2]\n"},
	{"unknown_key_in_second_document", "environment: a\n---\nbogus: 1\n"},
	{"case_differs_from_tag", "Environment: a\n"},
	{"several_unknown_keys", "one: 1\ntwo: 2\n"},
}

func TestYAMLV4Baseline_KnownFields(t *testing.T) {
	var out strings.Builder
	for _, tc := range knownFieldsCases {
		strict := strictVerdict(tc.input, true)
		plain := strictVerdict(tc.input, false)
		fmt.Fprintf(&out, "%s:\n  strict: %s\n  plain:  %s\n", tc.name, strict, plain)
	}
	checkGolden(t, "known_fields", out.String())
}

// strictVerdict decodes every document of data into Config with or without KnownFields.
func strictVerdict(data string, strict bool) string {
	var opts []yaml.Option
	if strict {
		opts = append(opts, yaml.WithKnownFields())
	}
	docs, err := loadStream(data, opts...)
	if err != nil {
		return "reject | " + strings.ReplaceAll(firstLine(err), "\n", " ")
	}
	return fmt.Sprintf("accept | %d document(s)", len(docs))
}

// TestYAMLV4Baseline_LoadRejectsUnknownKeyButDecodeAcceptsIt ties the table to the real
// entry point: Load must refuse what a plain decode of the same bytes accepts.
func TestYAMLV4Baseline_LoadRejectsUnknownKeyButDecodeAcceptsIt(t *testing.T) {
	data := []byte("environment: a\nenvironmnt: typo\n")
	var plain Config
	require.NoError(t, yaml.Unmarshal(data, &plain), "a plain decode drops the unknown key")

	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err := Load(path)
	require.Error(t, err, "Load is strict: an unknown key must fail at startup")
	require.True(t, bytes.Contains([]byte(err.Error()), []byte("environmnt")), "the error must name the unknown key: %v", err)
}
