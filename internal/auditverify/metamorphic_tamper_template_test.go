package auditverify_test

import (
	"os"
	"testing"
)

// TestAuditChainTemplates_Guard pins what makes sharing a built chain across
// FuzzAuditChainMetamorphicTamper inputs sound.
//
// Green: two inputs for the same n get different files with identical chain
// content, and damaging the first (the thing every fuzz mutation does) leaves
// the second, and the template, untouched, so one input's tamper can never
// reach the next. Red: a template file that no longer has the bytes it was
// built with is refused instead of being copied.
func TestAuditChainTemplates_Guard(t *testing.T) {
	templates := newAuditChainTemplates(t.TempDir())

	a := templates.fixtureFor(t, 6)
	b := templates.fixtureFor(t, 6)
	if a.path == b.path {
		t.Fatalf("two inputs share one file: %s", a.path)
	}
	want := fingerprintChain(a)
	if want == "" || fingerprintChain(b) != want {
		t.Fatal("two copies of one template differ before any mutation")
	}

	a.exec("UPDATE audit_events SET description = 'tampered' WHERE id = (SELECT min(id) FROM audit_events)")
	a.exec("DELETE FROM audit_events WHERE id = (SELECT max(id) FROM audit_events)")
	if fingerprintChain(a) == want {
		t.Fatal("precondition: the mutation did not change the first copy")
	}
	if fingerprintChain(b) != want {
		t.Fatal("a mutation of one input's copy leaked into another's")
	}
	if c := templates.fixtureFor(t, 6); fingerprintChain(c) != want {
		t.Fatal("a mutation of one input's copy leaked into the template")
	}

	t.Run("red/template file changed since built", func(t *testing.T) {
		tmpl := templates.byN[6]
		raw, err := os.ReadFile(tmpl.path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)/2] ^= 0xff
		if err := os.WriteFile(tmpl.path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := tmpl.open(t); err == nil {
			t.Fatal("a template whose bytes changed was copied without complaint")
		}
	})
}
