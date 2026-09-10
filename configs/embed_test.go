package configs

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDefaultConfigTemplate_NonEmptyAndValidYAML guards the vacuity failure
// mode for a go:embed directive: a typo'd or removed keyorix.yaml.tpl
// silently resolves to zero embedded bytes at compile time -- no build
// error, no test failure, just an empty config written to every new user's
// disk. Parsing as YAML additionally catches a truncated or corrupted embed
// that happens to be non-empty.
func TestDefaultConfigTemplate_NonEmptyAndValidYAML(t *testing.T) {
	if len(DefaultConfigTemplate) == 0 {
		t.Fatal("DefaultConfigTemplate is empty -- the go:embed directive resolved to zero bytes " +
			"(keyorix.yaml.tpl missing, renamed, or emptied); every `keyorix system init` would " +
			"write an empty config file")
	}

	var doc map[string]any
	if err := yaml.Unmarshal(DefaultConfigTemplate, &doc); err != nil {
		t.Fatalf("DefaultConfigTemplate does not parse as YAML: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("DefaultConfigTemplate parses as YAML but yields an empty document -- not the " +
			"real shipped template")
	}
}
