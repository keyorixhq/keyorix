package credstore

// v4-only baseline for the go.yaml.in/yaml/v4 paths the CLI credential store uses (#4574):
// typed decode into Credentials through FileStore.Load (Decoder.Decode, first document
// only), every document of a `---` stream through the v4 Loader, and strict KnownFields mode.
//
// Expected outputs are committed goldens in testdata/yaml_v4_baseline, not a second
// parser. Regenerate after reviewing a go-yaml bump with
//
//	KEYORIX_UPDATE_GOLDEN=1 go test ./internal/credstore -run 'TestYAMLV4Baseline'
//
// The goldens record whether a token is present, never its value; inputs hold placeholders.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v4"
)

type v4bCase struct{ name, input string }

// The cli module does not depend on testify; these stop the test on failure like require.
func v4bNoErr(t *testing.T, err error, msg ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v %v", err, msg)
	}
}

func v4bEqual[T comparable](t *testing.T, want, got T, msg ...any) {
	t.Helper()
	if want != got {
		t.Fatalf("not equal\n want: %v\n  got: %v\n  %v", want, got, msg)
	}
}

func v4bContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("%q does not contain %q", s, sub)
	}
}

func v4bFirstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func v4bGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "yaml_v4_baseline", name+".golden")
	if os.Getenv("KEYORIX_UPDATE_GOLDEN") == "1" {
		v4bNoErr(t, os.MkdirAll(filepath.Dir(path), 0o755))
		v4bNoErr(t, os.WriteFile(path, []byte(got), 0o644)) //nolint:gosec // golden test data, not a secret
		return
	}
	want, err := os.ReadFile(path)
	v4bNoErr(t, err, "missing golden; run with KEYORIX_UPDATE_GOLDEN=1 after reviewing the output")
	v4bEqual(t, string(want), got, "golden %s differs: a go-yaml change altered v4 behaviour (review, then regenerate)", path)
}

// v4bView is what the goldens record of decoded Credentials: the token is reduced to
// "set or not" so no credential-shaped value is ever committed.
func v4bView(c Credentials) string {
	b, _ := json.Marshal(struct {
		ServerURL     string `json:"server_url"`
		TokenSet      bool   `json:"token_set"`
		ActiveProject string `json:"active_project"`
		CAFile        string `json:"ca_file"`
	}{c.ServerURL, c.Token != "", c.ActiveProject, c.CAFile})
	return string(b)
}

var v4bTypedCases = []v4bCase{
	{"all_fields", "server_url: https://keyorix.example.test\ntoken: PLACEHOLDER\nactive_project: \"7\"\nca_file: /etc/keyorix/ca.pem\n"},
	{"server_url_only", "server_url: https://keyorix.example.test\n"},
	{"active_project_unquoted_int", "active_project: 7\n"},
	{"active_project_float", "active_project: 7.5\n"},
	{"token_int_is_stringified", "token: 12345\n"},
	{"token_mapping", "token:\n  nested: x\n"},
	{"token_null", "token: ~\n"},
	{"server_url_sequence", "server_url:\n  - a\n"},
	{"duplicate_key", "server_url: https://a.example.test\nserver_url: https://b.example.test\n"},
	{"anchor_and_alias", "server_url: &u https://keyorix.example.test\nca_file: *u\n"},
	{"unknown_key_is_ignored", "server_url: https://keyorix.example.test\nrefresh_token: PLACEHOLDER\n"},
	{"two_documents_first_wins", "server_url: https://first.example.test\n---\nserver_url: https://second.example.test\n"},
	{"empty_file", ""},
	{"comments_only", "# nothing\n"},
	{"document_marker_only", "---\n"},
	{"top_level_scalar", "just a string\n"},
	{"top_level_sequence", "- server_url\n"},
	{"unterminated_flow", "server_url: [https://a.example.test\n"},
}

func TestYAMLV4Baseline_TypedDecode(t *testing.T) {
	var out strings.Builder
	dir := t.TempDir()
	for _, tc := range v4bTypedCases {
		path := filepath.Join(dir, "credentials.yaml")
		v4bNoErr(t, os.WriteFile(path, []byte(tc.input), 0o600))
		v4bNoErr(t, os.Chmod(path, 0o600))
		c, err := NewFileStore(path).Load()
		if err != nil {
			fmt.Fprintf(&out, "%s: reject | %s\n", tc.name, v4bFirstLine(err.Error()))
			continue
		}
		fmt.Fprintf(&out, "%s: accept | %s\n", tc.name, v4bView(c))
	}
	v4bGolden(t, "typed_decode", out.String())
}

// v4bStream loads every document with the v4 Loader into a fresh Credentials.
func v4bStream(data string, opts ...yaml.Option) (docs []string, err error) {
	l, err := yaml.NewLoader(strings.NewReader(data), opts...)
	if err != nil {
		return nil, err
	}
	for range 64 {
		var c Credentials
		err := l.Load(&c)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, v4bView(c))
	}
	return docs, errors.New("loader did not reach EOF within 64 documents")
}

var v4bMultiCases = []v4bCase{
	{"one_document", "server_url: https://a.example.test\n"},
	{"two_documents", "server_url: https://a.example.test\n---\nserver_url: https://b.example.test\n"},
	{"second_document_wrong_type", "server_url: https://a.example.test\n---\nserver_url: [x]\n"},
	{"second_document_syntax_error", "server_url: https://a.example.test\n---\nserver_url: [x\n"},
	{"empty_second_document", "server_url: https://a.example.test\n---\n"},
	{"anchor_does_not_cross_documents", "server_url: &u https://a.example.test\n---\nca_file: *u\n"},
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

var v4bKnownFieldsCases = []v4bCase{
	{"all_keys_known", "server_url: https://a.example.test\nactive_project: \"1\"\n"},
	{"unknown_top_level_key", "server_url: https://a.example.test\nserver_ulr: typo\n"},
	{"unknown_key_null_value", "bogus: ~\n"},
	{"unknown_key_nested_value", "bogus:\n  a: [1, 2]\n"},
	{"key_differs_by_case", "Server_URL: https://a.example.test\n"},
	{"omitempty_tag_name_is_the_key", "token,omitempty: PLACEHOLDER\n"},
	{"unknown_key_in_second_document", "server_url: https://a.example.test\n---\nbogus: 1\n"},
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

// TestYAMLV4Baseline_SaveLoadRoundTrip: what Save writes, Load reads back unchanged, so the
// v4 encoder and decoder keep agreeing on the Credentials tags (omitempty, key names).
func TestYAMLV4Baseline_SaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix", "credentials.yaml")
	want := Credentials{ServerURL: "https://keyorix.example.test", Token: "PLACEHOLDER", ActiveProject: "7", CAFile: "/etc/keyorix/ca.pem"}
	s := NewFileStore(path)
	v4bNoErr(t, s.Save(want))
	got, err := s.Load()
	v4bNoErr(t, err)
	v4bEqual(t, want, got)

	raw, err := os.ReadFile(path)
	v4bNoErr(t, err)
	for _, key := range []string{"server_url:", "token:", "active_project:", "ca_file:"} {
		v4bContains(t, string(raw), key)
	}
}
