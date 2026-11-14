package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// withStdin points os.Stdin at a file holding content for the duration of the test,
// the same thing a shell pipe or redirect gives the process: all the input is
// already there when the first read happens.
func withStdin(t *testing.T, content string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = old
		_ = f.Close()
	})
}

// TestReadRecoveryKeyFromStdin_SeveralReadsOverPipedInput: with piped input a reader
// built per call reads ahead and drops the following lines, so the second prompt saw
// end of input (#3448, #4126, #4179). Successive reads must see successive lines.
func TestReadRecoveryKeyFromStdin_SeveralReadsOverPipedInput(t *testing.T) {
	withStdin(t, "first-key\r\nsecond-key\nthird-key")
	for i, want := range []string{"first-key", "second-key", "third-key"} {
		got, err := readRecoveryKeyFromStdin()
		if err != nil {
			t.Fatalf("read %d: %v", i+1, err)
		}
		if got != want {
			t.Fatalf("read %d: got %q, want %q", i+1, got, want)
		}
	}
	if _, err := readRecoveryKeyFromStdin(); err == nil {
		t.Fatal("a read past the end of input succeeded")
	}
}
