//go:build !windows

package encryption_test

// process_crash_recovery_pg_child_test.go is the subprocess half of
// FuzzProcessCrashRecoveryPG. It starts the wire seam (see
// process_crash_recovery_pg_proxy_test.go), points this run's keyorix.yaml at
// it, and performs one action. The parent restores keyorix.yaml afterwards, so a
// killed child's rewritten address never reaches a reopen.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/server/admin"
)

const (
	envPCrashPGChild  = "KEYORIX_PCRASH_PG_CHILD"  // action; unset in a normal test run
	envPCrashPGKillAt = "KEYORIX_PCRASH_PG_KILLAT" // 1-based seam to act on; 0 never
	envPCrashPGMode   = "KEYORIX_PCRASH_PG_MODE"   // pcrashPGModeKill or pcrashPGModeCut
	envPCrashPGTarget = "KEYORIX_PCRASH_PG_TARGET" // host:port of the real server
	envPCrashPGResult = "KEYORIX_PCRASH_PG_RESULT"
	envPCrashPGArgs   = "KEYORIX_PCRASH_PG_ARGS"
	envPCrashPGTrace  = "KEYORIX_PCRASH_PG_TRACE" // non-empty: report every seam label
	envPCrashPGSplit  = "KEYORIX_PCRASH_PG_SPLIT" // "commit" or "nocommit": red-proof split
)

// pcrashPGChildResult is what the child reports; a killed child reports only its seam.
type pcrashPGChildResult struct {
	Seams int64    `json:"seams"`
	Label string   `json:"label,omitempty"`
	Cut   bool     `json:"cut,omitempty"`
	Trace []string `json:"trace,omitempty"`
}

func writePCrashPGResult(path string, r pcrashPGChildResult) {
	if path == "" {
		return
	}
	if b, err := json.Marshal(r); err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

// pcrashPGSeam is the seam counter shared by the proxy and the key-file hooks.
type pcrashPGSeam struct {
	killAt int64
	mode   string
	result string
	trace  bool

	count atomic.Int64
	mu    sync.Mutex
	last  string
	cut   atomic.Bool
	log   []string
}

// tick counts one seam. In kill mode the process dies here; in cut mode it
// returns true for a SQL seam, meaning the caller must cut its connection. A
// file seam cannot be cut, so in cut mode it only counts.
func (s *pcrashPGSeam) tick(label string) bool {
	n := s.count.Add(1)
	if s.trace {
		s.mu.Lock()
		s.log = append(s.log, label)
		s.mu.Unlock()
	}
	if n != s.killAt {
		return false
	}
	if s.mode == pcrashPGModeKill {
		writePCrashPGResult(s.result, pcrashPGChildResult{Seams: n, Label: label})
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		select {} // the signal is already on its way
	}
	if !strings.HasPrefix(label, "sql:") {
		return false
	}
	s.mu.Lock()
	s.last = label
	s.mu.Unlock()
	s.cut.Store(true)
	return true
}

// report writes the final result of a child that was not killed.
func (s *pcrashPGSeam) report() {
	s.mu.Lock()
	defer s.mu.Unlock()
	writePCrashPGResult(s.result, pcrashPGChildResult{Seams: s.count.Load(), Label: s.last, Cut: s.cut.Load(), Trace: s.log})
}

// TestProcessCrashPGChild is not a test in a normal run.
func TestProcessCrashPGChild(t *testing.T) {
	action := os.Getenv(envPCrashPGChild)
	if action == "" {
		t.Skip("only runs as a FuzzProcessCrashRecoveryPG child process")
	}
	killAt, err := strconv.ParseInt(os.Getenv(envPCrashPGKillAt), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad %s: %v\n", envPCrashPGKillAt, err)
		os.Exit(pcrashExitHarness)
	}
	seam := &pcrashPGSeam{
		killAt: killAt,
		mode:   os.Getenv(envPCrashPGMode),
		result: os.Getenv(envPCrashPGResult),
		trace:  os.Getenv(envPCrashPGTrace) != "",
	}
	target := os.Getenv(envPCrashPGTarget)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "proxy listen:", err)
		os.Exit(pcrashExitHarness)
	}
	proxy := &pcrashPGProxy{target: target, tick: seam.tick}
	if v := os.Getenv(envPCrashPGSplit); v != "" {
		proxy.split = &pcrashPGSplit{commit: v == "commit", die: func() {
			writePCrashPGResult(seam.result, pcrashPGChildResult{Seams: seam.count.Load(), Label: "split"})
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
			select {}
		}}
	}
	go proxy.serve(listener)
	if err := pcrashPGPointConfigAt(target, listener.Addr().String()); err != nil {
		fmt.Fprintln(os.Stderr, "rewrite config:", err)
		os.Exit(pcrashExitHarness)
	}
	encryption.SetProcessCrashSeamForTest(func(label string) { seam.tick(label) })

	code := pcrashExitHarness
	if action == "admin" {
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv(envPCrashPGArgs)), &args); err != nil {
			fmt.Fprintf(os.Stderr, "bad %s: %v\n", envPCrashPGArgs, err)
		} else {
			code = admin.Execute(args)
		}
	} else {
		code = runPCrashCoreAction(context.Background(), action)
	}
	seam.report()
	os.Exit(code)
}

// pcrashPGPointConfigAt swaps the real server's address for the proxy's in the
// working directory's keyorix.yaml. The DSN starts with the address it was
// written with (pcrashPGDSN), so an absent address is a harness error.
func pcrashPGPointConfigAt(target, proxyAddr string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	pHost, pPort, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return err
	}
	b, err := os.ReadFile("keyorix.yaml")
	if err != nil {
		return err
	}
	from := "host=" + host + " port=" + port + " "
	if !strings.Contains(string(b), from) {
		return fmt.Errorf("keyorix.yaml does not contain the real server address")
	}
	return os.WriteFile("keyorix.yaml", []byte(strings.Replace(string(b), from, "host="+pHost+" port="+pPort+" ", 1)), 0o600)
}
