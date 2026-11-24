package identity

import (
	"strings"
	"testing"
)

// The rejected name is caller input and must not be quoted back in the error
// (request-echo canary, fuzz-corpus#186); the position of the first bad rune is.
func TestInvalidNameErrorDoesNotEchoInput(t *testing.T) {
	const canary = "kxfM-ah914g"
	raw := "ab" + "\x00" + canary
	for name, fn := range map[string]func(string) error{
		"folded":  func(s string) error { _, err := NewFoldedName(s); return err },
		"address": func(s string) error { _, err := NewAddressName(s); return err },
	} {
		err := fn(raw)
		if err == nil {
			t.Fatalf("%s: NUL accepted", name)
		}
		msg := err.Error()
		if strings.Contains(msg, canary) || strings.Contains(msg, "ab") || strings.Contains(msg, "\x00") {
			t.Errorf("%s: error echoes the input: %q", name, msg)
		}
		if !strings.Contains(msg, "position 2") {
			t.Errorf("%s: error does not locate the bad rune: %q", name, msg)
		}
	}
}
