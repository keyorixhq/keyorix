package cmd

// CLI-PROMPT-READER-1 item 2: every other reader of stdin in cli/cmd uses the same shared
// reader, so a confirmation that follows a prompt (or another confirmation) on a pipe sees
// its own line. Each test pipes lines that a per-call bufio.NewReader(os.Stdin) would lose.

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestConfirmYesNo_TwoBackToBackOnPipedStdin(t *testing.T) {
	pipeStdin(t, "yes\nyes\n")
	if !confirmYesNo("first?") {
		t.Fatal("first confirmation not accepted")
	}
	if !confirmYesNo("second?") {
		t.Fatal("second confirmation lost its input line to the first reader's buffer")
	}
}

func TestConfirmSecretFolderDeletion_TwoBackToBackOnPipedStdin(t *testing.T) {
	pipeStdin(t, "y\ny\n")
	if !confirmSecretFolderDeletion("first?") {
		t.Fatal("first confirmation not accepted")
	}
	if !confirmSecretFolderDeletion("second?") {
		t.Fatal("second confirmation lost its input line to the first reader's buffer")
	}
}

func TestConfirmSecretDeletion_ThenAnotherPromptOnPipedStdin(t *testing.T) {
	pipeStdin(t, "db-pass\nyes\nnext-line\n")
	if !confirmSecretDeletion("db-pass") {
		t.Fatal("secret deletion not confirmed")
	}
	got, err := promptLine("")
	if err != nil || got != "next-line" {
		t.Fatalf("line after the confirmation: got %q, %v; want next-line", got, err)
	}
}

func TestSecretValueStdin_SeesBytesAnEarlierPromptBuffered(t *testing.T) {
	pipeStdin(t, "first\nthe-secret-value\n")
	if got, err := promptLine(""); err != nil || got != "first" {
		t.Fatalf("prompt: got %q, %v; want first", got, err)
	}
	data, err := readSecretValueFromStdin(secretValueStdin)
	if err != nil || string(data) != "the-secret-value" {
		t.Fatalf("whole-stdin read after a prompt: got %q, %v; want the-secret-value", data, err)
	}
}

func TestPromptInput_UsesSharedReaderOnlyForProcessStdin(t *testing.T) {
	pipeStdin(t, "from-stdin\n")
	if promptInput(os.Stdin) != stdinReader() {
		t.Fatal("promptInput(os.Stdin) is not the shared reader")
	}
	r := promptInput(strings.NewReader("injected\n"))
	if r == stdinReader() {
		t.Fatal("promptInput over an injected reader returned the shared stdin reader")
	}
	if line, _ := r.ReadString('\n'); line != "injected\n" {
		t.Fatalf("injected reader line = %q", line)
	}
	// The injected read must not have consumed anything from the real stdin.
	rest, err := io.ReadAll(sharedStdin{})
	if err != nil || string(rest) != "from-stdin\n" {
		t.Fatalf("stdin after an injected read: %q, %v", rest, err)
	}
}
