// registry_exhaustiveness_test.go -- Group 3 guard: a future KeyProviderConfig
// provider type that writes new key material to disk must fail this test the
// moment it's added without also being wired into Registry, rather than
// silently shipping with no checker coverage (exactly how WrappedKeyPath was
// missed across all four hand-copied FilePermSpec lists this package
// replaces).
//
// TestSourceScan_WriteCapableProviderTypesMatchRegistry re-derives, from the
// actual source tree at test time, which KeyProviderConfig.Type values
// dispatch (in internal/encryption/service.go's buildSingleProvider) to a
// provider constructor whose file (in internal/crypto) calls
// SecureWriteFileSync/SecureWriteFile -- then asserts that set is exactly
// writeCapableProviderTypes. This is a genuine cross-check against the
// source, not a mirror of the constant: it goes red if a new crypto provider
// file starts writing without a matching registry.go entry, AND if
// writeCapableProviderTypes grows a stale entry that no longer corresponds to
// a real writer.
package keyfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// repoRoot locates the repository root from this test file's own path, so the
// source scan below works regardless of the working directory a test runner
// uses.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to resolve this test file's path")
	}
	// this file lives at <root>/internal/keyfiles/registry_exhaustiveness_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

var constructorFuncRe = regexp.MustCompile(`(?m)^func (New\w+)\(`)

// writerConstructors scans every non-test .go file directly under
// internal/crypto for a call to SecureWriteFileSync/SecureWriteFile, and
// returns the set of "New*" constructor function names DEFINED IN THAT SAME
// FILE (internal/crypto's one-constructor-per-provider-file layout makes this
// a reliable proxy for "this provider's constructor returns a value that
// writes key material").
func writerConstructors(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "internal", "crypto")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	result := make(map[string]bool)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed repo-relative test-only path
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(data)
		if !strings.Contains(src, "SecureWriteFileSync(") && !strings.Contains(src, "SecureWriteFile(") {
			continue
		}
		for _, m := range constructorFuncRe.FindAllStringSubmatch(src, -1) {
			result[m[1]] = true
		}
	}
	return result
}

// buildSingleProviderCaseDispatch parses internal/encryption/service.go's
// buildSingleProvider switch and returns, for every `case "type", "type2":`
// (or `case "":`) clause, the set of constructor function names
// (crypto.New\w+) called anywhere in that case's body.
func buildSingleProviderCaseDispatch(t *testing.T) map[string]map[string]bool {
	t.Helper()
	path := filepath.Join(repoRoot(t), "internal", "encryption", "service.go")
	data, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative test-only path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)

	start := strings.Index(src, "func buildSingleProvider(")
	if start < 0 {
		t.Fatal("buildSingleProvider not found in internal/encryption/service.go -- has it been renamed/moved? update this test's assumptions")
	}
	// The function body runs from its opening brace to the matching closing
	// brace at column 0 (the next top-level "}\n" -- buildSingleProvider is
	// the last case in this switch-only function, followed by the next
	// top-level func).
	rest := src[start:]
	nextFunc := regexp.MustCompile(`(?m)^func `).FindStringIndex(rest[1:])
	body := rest
	if nextFunc != nil {
		body = rest[:nextFunc[0]+1]
	}

	caseRe := regexp.MustCompile(`(?m)^\tcase ([^:]+):`)
	caseIdx := caseRe.FindAllStringSubmatchIndex(body, -1)
	if len(caseIdx) == 0 {
		t.Fatal("no `case` clauses found while parsing buildSingleProvider -- source shape changed, update this test")
	}
	constructorRe := regexp.MustCompile(`crypto\.(New\w+)\(`)

	result := make(map[string]map[string]bool)
	for i, idx := range caseIdx {
		caseLabels := body[idx[2]:idx[3]]
		bodyStart := idx[1]
		bodyEnd := len(body)
		if i+1 < len(caseIdx) {
			bodyEnd = caseIdx[i+1][0]
		}
		caseBody := body[bodyStart:bodyEnd]

		constructors := make(map[string]bool)
		for _, m := range constructorRe.FindAllStringSubmatch(caseBody, -1) {
			constructors[m[1]] = true
		}

		for _, label := range strings.Split(caseLabels, ",") {
			label = strings.TrimSpace(label)
			label = strings.Trim(label, `"`)
			result[label] = constructors
		}
	}
	return result
}

func TestSourceScan_WriteCapableProviderTypesMatchRegistry(t *testing.T) {
	writers := writerConstructors(t)
	if len(writers) == 0 {
		t.Fatal("source scan found zero writer constructors in internal/crypto -- the scan itself is broken (password/tpm/kms providers are known writers), not that none exist")
	}

	dispatch := buildSingleProviderCaseDispatch(t)
	if len(dispatch) == 0 {
		t.Fatal("source scan found zero case clauses in buildSingleProvider -- the parser is broken")
	}

	derived := make(map[string]bool)
	for typeName, constructors := range dispatch {
		for c := range constructors {
			if writers[c] {
				derived[typeName] = true
			}
		}
	}

	// "" and "password" both dispatch to NewPasswordKeyProvider, which writes
	// EncryptionConfig.SaltPath directly -- not a KeyProviderConfig field, so
	// it's handled unconditionally in Registry rather than through
	// writeCapableProviderTypes. Exclude both from the derived set before
	// comparing: they are confirmed writers, but of a path this package
	// already covers by a different, unconditional code path.
	delete(derived, "")
	delete(derived, "password")

	var derivedList, wantList []string
	for typeName := range derived {
		derivedList = append(derivedList, typeName)
	}
	for typeName := range writeCapableProviderTypes {
		wantList = append(wantList, typeName)
	}
	sort.Strings(derivedList)
	sort.Strings(wantList)

	if fmt.Sprint(derivedList) != fmt.Sprint(wantList) {
		t.Fatalf("writeCapableProviderTypes (registry.go) = %v, but the source scan derived %v from internal/crypto + buildSingleProvider's dispatch -- a provider type's write-capability changed without registry.go being updated to match", wantList, derivedList)
	}
}

// TestRegistry_IncludesWrappedKeyPathForEveryWriteCapableType is the positive
// half of the guard: for every type this package believes is write-capable,
// Registry must actually surface its configured WrappedKeyPath. Deleting a
// case from Registry's switch (without touching
// writeCapableProviderTypes) makes THIS test catch it, even though the
// source-scan test above only catches writeCapableProviderTypes itself
// drifting from the true writer set.
func TestRegistry_IncludesWrappedKeyPathForEveryWriteCapableType(t *testing.T) {
	for providerType := range writeCapableProviderTypes {
		t.Run(providerType, func(t *testing.T) {
			dir := t.TempDir()
			enc := &config.EncryptionConfig{
				Enabled: true,
				KeyProvider: config.KeyProviderConfig{
					Type:           providerType,
					WrappedKeyPath: "wrapped.key",
				},
			}
			// A required entry doesn't need to exist on disk for Registry to
			// list it (existence is enforced downstream by FixFilePerms) --
			// but SaltPath/DEKPath are unset here (KeyProvider.Type isn't
			// "password"), so isolate to just the KeyProvider-driven path by
			// leaving them empty; Registry must skip empty paths, not error.
			specs, err := Registry(enc, dir)
			if err != nil {
				t.Fatalf("Registry: %v", err)
			}
			want := filepath.Join(dir, "wrapped.key")
			found := false
			for _, s := range specs {
				if s.Path == want {
					found = true
					if s.Mode != 0600 {
						t.Errorf("wrapped-key spec mode = %o, want 0600", s.Mode)
					}
				}
			}
			if !found {
				t.Fatalf("Registry(%q) did not include the wrapped-key path %s; got %+v", providerType, want, specs)
			}
		})
	}
}
