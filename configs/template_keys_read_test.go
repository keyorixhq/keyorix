package configs

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/config"
)

// yamlFieldIndex maps every yaml leaf path of config.Config to the Go field name that
// carries it.
func yamlFieldIndex(t reflect.Type, prefix string, out map[string]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for f := range t.Fields() {
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "-" || !f.IsExported() {
			continue
		}
		if tag == "" { // inline / untagged embedded struct
			yamlFieldIndex(f.Type, prefix, out)
			continue
		}
		p := tag
		if prefix != "" {
			p = prefix + "." + tag
		}
		out[p] = f.Name
		yamlFieldIndex(f.Type, p, out)
	}
}

func yamlLeaves(prefix string, v any, out map[string]bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		out[prefix] = true
		return
	}
	for k, c := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		yamlLeaves(p, c, out)
	}
}

// TestShippedConfigKeysAreRead fails when a shipped config (the admin-init template,
// dev.yaml, test.yaml) sets a key whose Go field is never read: no selector .Field
// appears in any non-test Go file of the module. Such a key promises a control that
// does not exist; secrets.limits.max_secrets_per_user ("Maximum number of secrets per
// user", 1000) and secrets.chunking.* were shipped like that.
//
// Limits, stated: a field read only through reflection or a struct copy counts as
// unread (none today), and a generic field name (Enabled, Path) is "read" if any
// struct's field of that name is, so this catches only distinctively named dead keys.
func TestShippedConfigKeysAreRead(t *testing.T) {
	fields := map[string]string{}
	yamlFieldIndex(reflect.TypeFor[config.Config](), "", fields)

	selectors := map[string]bool{}
	sel := regexp.MustCompile(`\.([A-Z][A-Za-z0-9_]*)`)
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != ".." && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "testdata" || name == "web" || name == "cli" || name == "operator") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range sel.FindAllSubmatch(src, -1) {
			selectors[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{"keyorix.yaml.tpl", DefaultConfigTemplate},
		{"dev.yaml", mustRead(t, "dev.yaml")},
		{"test.yaml", mustRead(t, "test.yaml")},
	} {
		var doc any
		if err := yaml.Unmarshal(file.raw, &doc); err != nil {
			t.Fatalf("%s: %v", file.name, err)
		}
		leaves := map[string]bool{}
		yamlLeaves("", doc, leaves)
		var unread []string
		for leaf := range leaves {
			field, ok := fields[leaf]
			if !ok {
				unread = append(unread, leaf+" (not a config.Config key)")
				continue
			}
			if !selectors[field] {
				unread = append(unread, leaf+" (field "+field+" is never read)")
			}
		}
		sort.Strings(unread)
		for _, u := range unread {
			t.Errorf("%s sets %s", file.name, u)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
