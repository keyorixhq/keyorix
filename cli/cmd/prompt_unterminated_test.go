package cmd

// `printf %s pw | keyorix login` ends the pipe without a newline. bufio's ReadString returns
// the bytes it read together with io.EOF in that case; promptLine used to drop them and
// report EOF, so the last (often the only) piped value was lost. EOF is right only when
// nothing at all was read.

import (
	"errors"
	"io"
	"testing"
)

type promptFn struct {
	name string
	call func() (string, error)
}

// both prompt shapes read a piped value through the same shared reader: promptLine for
// echoed input, promptPassword for the secret prompt (a pipe is not a terminal, so there is
// no no-echo path to take and it falls back to promptLine).
var promptFns = []promptFn{
	{"promptLine", func() (string, error) { return promptLine("") }},
	{"promptPassword", func() (string, error) { return promptPassword("") }},
}

func TestPrompt_FinalLineWithoutNewline(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{"unterminated last line", "hunter2", "hunter2", nil},
		{"terminated line", "hunter2\n", "hunter2", nil},
		{"CRLF line", "hunter2\r\n", "hunter2", nil},
		{"unterminated line ending in CR", "hunter2\r", "hunter2", nil},
		{"empty terminated line is a value, not EOF", "\n", "", nil},
		{"empty input", "", "", io.EOF},
	}
	for _, p := range promptFns {
		for _, c := range cases {
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				pipeStdin(t, c.input)
				got, err := p.call()
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				if got != c.want {
					t.Errorf("got %q, want %q", got, c.want)
				}
			})
		}
	}
}

// The unterminated line is the last one: the lines before it are read as before, and the
// prompt after it reports EOF (the value is consumed once, not replayed).
func TestPrompt_UnterminatedLastLineAfterTerminatedOnes(t *testing.T) {
	for _, p := range promptFns {
		t.Run(p.name, func(t *testing.T) {
			pipeStdin(t, "alice\r\nhunter2")
			user, err := promptLine("")
			if err != nil || user != "alice" {
				t.Fatalf("line 1: %q, %v; want alice", user, err)
			}
			got, err := p.call()
			if err != nil || got != "hunter2" {
				t.Fatalf("line 2: %q, %v; want hunter2 (no trailing newline)", got, err)
			}
			if got, err := p.call(); !errors.Is(err, io.EOF) || got != "" {
				t.Fatalf("line 3: %q, %v; want \"\" and io.EOF", got, err)
			}
		})
	}
}
