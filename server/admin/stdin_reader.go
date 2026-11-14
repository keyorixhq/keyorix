package admin

import (
	"bufio"
	"os"
	"sync"
)

// One buffered reader per process over os.Stdin. A bufio reader reads ahead, so a
// reader built per prompt loses whatever the previous one buffered when input is
// piped and several prompts read in turn (#3448, #4126, #4179). Every stdin read in
// this package goes through readStdinLine; stdin_bufio_guard_test.go fails on a
// direct bufio reader over os.Stdin in the files it lists.
var (
	stdinMu  sync.Mutex
	stdinSrc *os.File
	stdinRd  *bufio.Reader
)

// readStdinLine reads up to and including the next newline from the process's
// shared stdin reader, with the semantics of bufio.Reader.ReadString('\n'): at end
// of input it returns the partial line (possibly empty) and the error.
//
// The reader is rebuilt when os.Stdin is a different file than the one it was built
// over (tests swap os.Stdin for a pipe or a file); in production os.Stdin never
// changes, so there is exactly one reader.
func readStdinLine() (string, error) {
	stdinMu.Lock()
	defer stdinMu.Unlock()
	if stdinRd == nil || stdinSrc != os.Stdin {
		stdinSrc, stdinRd = os.Stdin, bufio.NewReader(os.Stdin)
	}
	return stdinRd.ReadString('\n')
}
