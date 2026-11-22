package k8ssync

// v4-only baseline for the go.yaml.in/yaml/v4 paths the agent config uses (#4574): typed
// decode into Config through LoadConfig (yamlsafe.Unmarshal, first document only), every
// document of a `---` stream through the v4 Loader, and strict KnownFields mode.
//
// Expected outputs are committed goldens in testdata/yaml_v4_baseline, not a second
// parser. Regenerate after reviewing a go-yaml bump with
//
//	KEYORIX_UPDATE_GOLDEN=1 go test ./internal/k8ssync -run 'TestYAMLV4Baseline'
//
// Inputs hold placeholder values only.

import (
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

const v4bValidHead = "keyorix_url: https://keyorix.example.test\nproject_id: 7\n"
const v4bValidMapping = "mappings:\n  - ref: production/db-password\n    namespace: apps\n    name: db\n    key: password\n"

type v4bCase struct{ name, input string }

func v4bFirstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func v4bGolden(t *testing.T, name, got string) {
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

// v4bView is what the goldens record of a decoded Config.
func v4bView(c *Config) string {
	prune := "unset"
	if c.PruneOnRevoke != nil {
		prune = fmt.Sprintf("%t", *c.PruneOnRevoke)
	}
	b, _ := json.Marshal(struct {
		URL      string `json:"keyorix_url"`
		Project  uint   `json:"project_id"`
		Interval string `json:"interval"`
		Port     int    `json:"health_port"`
		Cleanup  bool   `json:"cleanup"`
		Prune    string `json:"prune_on_revoke"`
		Suspend  string `json:"on_suspend"`
		Mappings int    `json:"mappings"`
		FirstKey string `json:"first_mapping_key"`
	}{c.KeyorixURL, c.ProjectID, c.Interval, c.HealthPort, c.Cleanup, prune, c.OnSuspend, len(c.Mappings), firstKey(c)})
	return string(b)
}

func firstKey(c *Config) string {
	if len(c.Mappings) == 0 {
		return ""
	}
	return c.Mappings[0].Key
}

var v4bTypedCases = []v4bCase{
	{"minimal_valid", v4bValidHead + v4bValidMapping},
	{"all_scalar_kinds", v4bValidHead + "interval: 30s\nhealth_port: 9090\ncleanup: true\nprune_on_revoke: false\non_suspend: clear\n" + v4bValidMapping},
	{"tristate_prune_unset", v4bValidHead + v4bValidMapping},
	{"tristate_prune_explicit_true", v4bValidHead + "prune_on_revoke: true\n" + v4bValidMapping},
	{"project_id_string_number", "keyorix_url: https://keyorix.example.test\nproject_id: \"8\"\n" + v4bValidMapping},
	{"project_id_negative", "keyorix_url: https://keyorix.example.test\nproject_id: -1\n" + v4bValidMapping},
	{"project_id_not_a_number", "keyorix_url: https://keyorix.example.test\nproject_id: seven\n" + v4bValidMapping},
	{"health_port_float", v4bValidHead + "health_port: 80.5\n" + v4bValidMapping},
	{"cleanup_yes_decodes_as_bool_true", v4bValidHead + "cleanup: yes\n" + v4bValidMapping},
	{"mappings_not_a_sequence", v4bValidHead + "mappings: nope\n"},
	{"mapping_entry_not_a_mapping", v4bValidHead + "mappings:\n  - just-a-string\n"},
	{"duplicate_key", v4bValidHead + "project_id: 9\n" + v4bValidMapping},
	{"anchor_reused_in_mappings", v4bValidHead + "mappings:\n  - &m {ref: production/a, namespace: apps, name: a, key: k}\n  - *m\n"},
	{"merge_key_in_mapping", v4bValidHead + "mappings:\n  - <<: {ref: production/a, namespace: apps}\n    name: a\n    key: k\n"},
	{"empty_file", ""},
	{"unterminated_flow", "keyorix_url: [https://keyorix.example.test\n"},
	{"unknown_key_is_ignored", v4bValidHead + "unknown_setting: 1\n" + v4bValidMapping},
}

func TestYAMLV4Baseline_TypedDecode(t *testing.T) {
	var out strings.Builder
	dir := t.TempDir()
	for _, tc := range v4bTypedCases {
		path := filepath.Join(dir, "agent.yaml")
		require.NoError(t, os.WriteFile(path, []byte(tc.input), 0o600))
		c, err := LoadConfig(path)
		if err != nil {
			fmt.Fprintf(&out, "%s: reject | %s\n", tc.name, v4bFirstLine(strings.ReplaceAll(err.Error(), dir, "<dir>")))
			continue
		}
		fmt.Fprintf(&out, "%s: accept | %s\n", tc.name, v4bView(c))
	}
	v4bGolden(t, "typed_decode", out.String())
}

// v4bStream loads every document with the v4 Loader into a fresh Config.
func v4bStream(data string, opts ...yaml.Option) (docs []string, err error) {
	l, err := yaml.NewLoader(strings.NewReader(data), opts...)
	if err != nil {
		return nil, err
	}
	for range 64 {
		var c Config
		err := l.Load(&c)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, v4bView(&c))
	}
	return docs, errors.New("loader did not reach EOF within 64 documents")
}

var v4bMultiCases = []v4bCase{
	{"one_document", v4bValidHead + v4bValidMapping},
	{"two_documents", "keyorix_url: https://a.example.test\nproject_id: 1\n---\nkeyorix_url: https://b.example.test\nproject_id: 2\n"},
	{"second_document_wrong_type", "project_id: 1\n---\nproject_id: seven\n"},
	{"second_document_syntax_error", "project_id: 1\n---\nmappings: [\n"},
	{"empty_second_document", "project_id: 1\n---\n"},
	{"anchor_does_not_cross_documents", "keyorix_url: &u https://a.example.test\n---\nkeyorix_url: *u\n"},
	{"empty_input", ""},
}

func TestYAMLV4Baseline_MultiDocumentStream(t *testing.T) {
	var out strings.Builder
	for _, tc := range v4bMultiCases {
		fmt.Fprintf(&out, "%s:\n", tc.name)
		docs, err := v4bStream(tc.input, yaml.WithKnownFields())
		for i, d := range docs {
			fmt.Fprintf(&out, "  doc %d: accept | %s\n", i+1, d)
		}
		if err != nil {
			fmt.Fprintf(&out, "  doc %d: reject | %s\n", len(docs)+1, v4bFirstLine(err.Error()))
		}
		fmt.Fprintf(&out, "  documents decoded: %d\n", len(docs))
	}
	v4bGolden(t, "multi_document", out.String())
}

// TestYAMLV4Baseline_LoadConfigReadsOnlyTheFirstDocument pins what production does today:
// LoadConfig (yamlsafe.Unmarshal) decodes document one and ignores the rest, while a Loader
// walk sees both. A change to either shows here.
func TestYAMLV4Baseline_LoadConfigReadsOnlyTheFirstDocument(t *testing.T) {
	stream := v4bValidHead + v4bValidMapping + "---\nproject_id: 99\n"
	path := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(stream), 0o600))
	c, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, uint(7), c.ProjectID)

	docs, err := v4bStream(stream)
	require.NoError(t, err)
	require.Len(t, docs, 2)
	require.Contains(t, docs[1], `"project_id":99`)
}

var v4bKnownFieldsCases = []v4bCase{
	{"all_keys_known", v4bValidHead + v4bValidMapping},
	{"unknown_top_level_key", v4bValidHead + "prune_on_revok: true\n"},
	{"unknown_key_in_mapping_entry", "mappings:\n  - ref: production/a\n    namespce: apps\n"},
	{"unknown_key_null_value", "bogus: ~\n"},
	{"unexported_field_name_is_unknown", "massPruneAckTime: 2026-01-01T00:00:00Z\n"},
	{"unknown_key_in_second_document", "project_id: 1\n---\nbogus: 1\n"},
}

func TestYAMLV4Baseline_KnownFields(t *testing.T) {
	verdict := func(in string, strict bool) string {
		var opts []yaml.Option
		if strict {
			opts = append(opts, yaml.WithKnownFields())
		}
		docs, err := v4bStream(in, opts...)
		if err != nil {
			return "reject | " + v4bFirstLine(err.Error())
		}
		return fmt.Sprintf("accept | %d document(s)", len(docs))
	}
	var out strings.Builder
	for _, tc := range v4bKnownFieldsCases {
		fmt.Fprintf(&out, "%s:\n  strict: %s\n  plain:  %s\n", tc.name, verdict(tc.input, true), verdict(tc.input, false))
	}
	v4bGolden(t, "known_fields", out.String())
}
