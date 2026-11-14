package admin

import (
	"bufio"
	"os"
	"testing"
)

// TestDirectReaderLosesSecondPrompt is the bug class stdin_bufio_guard_test.go exists for,
// shown on the same piped input twice: a bufio reader built per prompt over os.Stdin reads
// ahead past the first line, so the second prompt sees end of input; readStdinLine returns
// both lines. The first half documents why the guard bans the direct reader (it fails if
// that stops being true), the second is the fix every site now uses.
func TestDirectReaderLosesSecondPrompt(t *testing.T) {
	const input = "first\nsecond\n"

	withStdin(t, input)
	if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("direct prompt 1 = %q, %v; want \"first\\n\", nil", line, err)
	}
	if line, err := bufio.NewReader(os.Stdin).ReadString('\n'); err == nil {
		t.Fatalf("direct prompt 2 = %q, nil: the direct reader no longer loses buffered input, so the premise of the guard changed", line)
	}

	withStdin(t, input)
	for i, want := range []string{"first\n", "second\n"} {
		if line, err := readStdinLine(); err != nil || line != want {
			t.Fatalf("shared prompt %d = %q, %v; want %q, nil", i+1, line, err, want)
		}
	}
}

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
