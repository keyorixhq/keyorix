package secretenv

// FuzzLookupPrecedenceFailClosed drives Lookup, the resolver that turns a secret
// reference (the env var NAME, or the file named by NAME_FILE) into a value. The
// env value and the file content are both untrusted operator/orchestrator input.
// The governing rule (DEPLOY-2 decision 1, secretenv.go doc): NAME and NAME_FILE
// both set is an error -- "No silent precedence: an operator who set both has a
// deployment in an unknown state" -- and no error ever carries the secret value
// or the file content.
//
// ORACLE (fail-closed, canary-tagged -- cannot false-positive):
//
//	The direct value always carries envCanary; the file content always carries
//	fileCanary; the two canaries are distinct and appear nowhere else.
//	  - AMBIGUOUS (both NAME and NAME_FILE set): Lookup MUST return err != nil,
//	    found == false and value == "" -- it must not silently resolve to either
//	    scope -- and err.Error() must contain NEITHER canary (no secret / no file
//	    content in the message).
//	  - DIRECT-ONLY (only NAME set): Lookup resolves to EXACTLY the direct value;
//	    the result must not contain fileCanary (it cannot leak a scope that is not
//	    even present, but the check pins "resolves from the selected scope only").
//
// Every assertion is either "an error/empty is required" or "a canary from the
// non-selected scope must be absent", so it can only fire on a real
// silent-precedence or cross-scope leak; it never fires on a safe refusal.
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not exercise the file-permission / owner judgement (LookupChecked);
//     that is the classifier fuzzer's and the permission matrix's job. Here the
//     file is written 0600 self-owned so Lookup's own precedence logic is what is
//     under test, not checkInfo.
//   - It does not cover the file-unreadable branch's exact error text beyond the
//     no-canary-leak property.
//   - The direct-only resolved value is pinned to equal the env value verbatim;
//     the file-only round-trip (value == trimOneTerminator(content)) is left to
//     the existing secretenv_test.go cases, to keep this target focused on the
//     ambiguity rule.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzLookupPrecedenceFailClosed(f *testing.F) {
	const envCanary = "ENVSCOPE_canary_e5c1"
	const fileCanary = "FILESCOPE_canary_f9d2"

	// seeds: (directTail, fileTail, makeFile)
	f.Add("db-password", "file-secret", true)
	f.Add("", "", true)
	f.Add("value", "", false)
	f.Add("a\nb", "c\r\nd", true)

	f.Fuzz(func(t *testing.T, directTail, fileTail string, makeFile bool) {
		directVal := directTail + envCanary // always non-empty => NAME is always "set"
		// A real environment variable value cannot hold a NUL byte (execve/setenv
		// reject it); that is an OS limit on the fixture, not a property of Lookup.
		if strings.ContainsRune(directVal, 0) {
			t.Skip()
		}

		path := ""
		if makeFile {
			path = filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte(fileTail+fileCanary), 0o600); err != nil {
				t.Skipf("write fixture: %v", err)
			}
		}

		t.Setenv(testVar, directVal)
		t.Setenv(testVar+FileSuffix, path) // "" when !makeFile == unset

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Lookup panicked (direct=%q makeFile=%v): %v", directVal, makeFile, r)
			}
		}()

		v, found, err := Lookup(testVar)

		if makeFile {
			// Both NAME and NAME_FILE set => ambiguous => hard error, no value.
			if err == nil {
				t.Fatalf("both NAME and NAME_FILE set but Lookup returned no error (value=%q found=%v)", v, found)
			}
			if found || v != "" {
				t.Fatalf("ambiguous config resolved to a value: found=%v value=%q", found, v)
			}
			if strings.Contains(err.Error(), envCanary) {
				t.Fatalf("error leaked the env secret: %q", err.Error())
			}
			if strings.Contains(err.Error(), fileCanary) {
				t.Fatalf("error leaked the file content: %q", err.Error())
			}
			return
		}

		// Only NAME set => resolves to exactly the direct value, selected scope only.
		if err != nil || !found {
			t.Fatalf("direct-only lookup failed: found=%v err=%v", found, err)
		}
		if v != directVal {
			t.Fatalf("direct-only lookup returned %q, want the env value %q", v, directVal)
		}
		if strings.Contains(v, fileCanary) {
			t.Fatalf("direct-only lookup leaked the file scope: %q", v)
		}
	})
}
