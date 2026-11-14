package admin

import "testing"

// TestReadStdinLine_SharedWithRecoveryKeyPrompt: the lock-holder test hook and the
// recovery-key prompt read through the same reader, so a line consumed by one is not
// seen again by the other and nothing the first buffered is lost.
func TestReadStdinLine_SharedWithRecoveryKeyPrompt(t *testing.T) {
	withStdin(t, "go\nthe-key\n")
	if line, err := readStdinLine(); err != nil || line != "go\n" {
		t.Fatalf("readStdinLine = %q, %v; want \"go\\n\", nil", line, err)
	}
	got, err := readRecoveryKeyFromStdin()
	if err != nil || got != "the-key" {
		t.Fatalf("readRecoveryKeyFromStdin = %q, %v; want \"the-key\", nil", got, err)
	}
}
