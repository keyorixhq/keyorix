package cmd

// One buffered reader over stdin, shared by every prompt in the process (#3448).
//
// A bufio.Reader reads ahead: its first fill takes whatever the pipe holds, so a prompt that
// builds its own reader throws away every line after the one it returned. With
// `printf 'user\npass\n123456\n' | keyorix login` the second and third prompts then saw EOF.
// Every prompt, confirmation and whole-stdin read goes through stdinReader() instead, so
// the read-ahead of one is the input of the next.
//
// Reading a password from a terminal (term.ReadPassword on the file descriptor, no echo) is
// unchanged: it never goes through this reader.

import (
	"bufio"
	"io"
	"os"
	"sync"
)

var stdinShared struct {
	mu  sync.Mutex
	src *os.File
	r   *bufio.Reader
}

// stdinReader returns the process-wide reader over os.Stdin, creating it on first use. It
// is rebuilt if os.Stdin was replaced since (tests swap it for a pipe), so a stale reader
// can never keep serving an old stdin.
func stdinReader() *bufio.Reader {
	stdinShared.mu.Lock()
	defer stdinShared.mu.Unlock()
	if stdinShared.r == nil || stdinShared.src != os.Stdin {
		stdinShared.src = os.Stdin
		stdinShared.r = bufio.NewReader(os.Stdin)
	}
	return stdinShared.r
}

// resetStdinReader drops the shared reader and whatever it had buffered. Tests call it
// after swapping os.Stdin.
func resetStdinReader() {
	stdinShared.mu.Lock()
	defer stdinShared.mu.Unlock()
	stdinShared.src, stdinShared.r = nil, nil
}

// sharedStdin is an io.Reader over the shared stdin reader, for code that reads all of
// stdin (a template, a secret value) and must still see bytes an earlier prompt buffered.
type sharedStdin struct{}

func (sharedStdin) Read(p []byte) (int, error) { return stdinReader().Read(p) }

var _ io.Reader = sharedStdin{}

// promptInput returns the reader a prompt should use for in: the shared stdin reader when in
// is the process stdin (the normal case, cobra's InOrStdin default), else a reader over in
// (a test that called cmd.SetIn).
func promptInput(in io.Reader) *bufio.Reader {
	if f, ok := in.(*os.File); ok && f == os.Stdin {
		return stdinReader()
	}
	return bufio.NewReader(in)
}
