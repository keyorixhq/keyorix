package contracttest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const invalidYAMLSpec = "openapi: [this is not valid YAML for an OpenAPI doc\n"

const failsValidationSpec = `
openapi: 3.0.3
info:
  title: missing required fields
paths: {}
`

func writeTempSpec(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp spec: %v", err)
	}
	return path
}

func TestLoadSpecFrom(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		_, _, err := loadSpecFrom(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		if err == nil {
			t.Fatal("expected an error for a nonexistent spec file")
		}
		if !strings.Contains(err.Error(), "loading") {
			t.Errorf("expected a loading error, got: %v", err)
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		path := writeTempSpec(t, invalidYAMLSpec)
		_, _, err := loadSpecFrom(path)
		if err == nil {
			t.Fatal("expected an error for malformed YAML")
		}
	})

	t.Run("valid YAML that fails OpenAPI validation", func(t *testing.T) {
		path := writeTempSpec(t, failsValidationSpec)
		_, _, err := loadSpecFrom(path)
		if err == nil {
			t.Fatal("expected an error for a spec missing required fields (info.version)")
		}
		if !strings.Contains(err.Error(), "OpenAPI validation") {
			t.Errorf("expected an OpenAPI validation error, got: %v", err)
		}
	})

	t.Run("the real spec loads clean", func(t *testing.T) {
		doc, r, err := loadSpecFrom(specPath)
		if err != nil {
			t.Fatalf("expected the real spec to load without error, got: %v", err)
		}
		if doc == nil || r == nil {
			t.Fatal("expected a non-nil doc and router")
		}
	})
}
