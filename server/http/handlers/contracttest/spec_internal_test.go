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

// badServerURLSpec parses and passes OpenAPI validation cleanly (server URLs
// aren't checked for validity by doc.Validate()), but its server URL's
// invalid percent-encoding ("%zz" is not a valid URL escape) makes
// gorillamux.NewRouter fail when it parses the URL to build the mux route --
// the one loadSpecFrom error branch a malformed-YAML or failed-validation
// spec can't reach.
const badServerURLSpec = `
openapi: 3.0.3
info:
  title: bad server url
  version: "1.0"
servers:
  - url: "http://example.com/%zz"
paths:
  /foo:
    get:
      operationId: foo
      responses:
        '200':
          description: ok
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

	t.Run("valid spec whose router fails to build", func(t *testing.T) {
		path := writeTempSpec(t, badServerURLSpec)
		_, _, err := loadSpecFrom(path)
		if err == nil {
			t.Fatal("expected an error when gorillamux.NewRouter cannot build a router from the doc")
		}
		if !strings.Contains(err.Error(), "building operation router") {
			t.Errorf("expected a router-build error, got: %v", err)
		}
	})
}
