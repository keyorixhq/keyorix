//go:build !windows

package encryption_test

// process_crash_recovery_child_test.go is the subprocess half of
// FuzzProcessCrashRecovery: the test binary re-execs itself to run one
// operation and SIGKILLs itself at the Nth write seam.
//
// The seam counts three kinds of event, in order, with no production change:
//   - every row a SQLite statement changes (the driver's pre-update hook);
//   - every SQLite commit, just before it happens (the driver's commit hook);
//   - every key-file durability step (encryption.SetProcessCrashSeamForTest).
//
// It does NOT see file writes outside internal/encryption's durable helpers:
// the backup archive, the restore journal and the staging directory are only
// interrupted at the database events around them.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"

	sqlite "modernc.org/sqlite"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/server/admin"
)

const (
	envPCrashChild  = "KEYORIX_PCRASH_CHILD"   // the action to run; unset in a normal test run
	envPCrashKillAt = "KEYORIX_PCRASH_KILL_AT" // 1-based seam number to die at; 0 never
	envPCrashResult = "KEYORIX_PCRASH_RESULT"  // file the child reports its seam count to
	envPCrashArgs   = "KEYORIX_PCRASH_ARGS"    // JSON argument list of an admin action
	envPCrashPass   = "KEYORIX_MASTER_PASSWORD"
)

// pcrashChildResult is what a child that was not killed reports. A killed child
// reports only the seam label it died at.
type pcrashChildResult struct {
	Seams int64  `json:"seams"`
	Label string `json:"label,omitempty"`
}

var pcrashSeams atomic.Int64

// installPCrashSeam makes this process SIGKILL itself at seam killAt.
func installPCrashSeam(killAt int64, resultPath string) {
	tick := func(label string) {
		if pcrashSeams.Add(1) != killAt {
			return
		}
		writePCrashResult(resultPath, pcrashChildResult{Seams: killAt, Label: label})
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		select {} // the signal is already on its way; nothing may run after this point
	}
	sqlite.RegisterConnectionHook(func(c sqlite.ExecQuerierContext, _ string) error {
		h, ok := c.(sqlite.HookRegisterer)
		if !ok {
			return fmt.Errorf("sqlite connection %T has no write hooks: the crash seam would be blind", c)
		}
		h.RegisterPreUpdateHook(func(sqlite.SQLitePreUpdateData) { tick("sql:row") })
		h.RegisterCommitHook(func() int32 {
			tick("sql:commit")
			return 0
		})
		return nil
	})
	encryption.SetProcessCrashSeamForTest(tick)
}

func writePCrashResult(path string, r pcrashChildResult) {
	if path == "" {
		return
	}
	b, err := json.Marshal(r)
	if err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

// TestProcessCrashChild is not a test in a normal run. Re-executed with
// envPCrashChild set, it performs one action in the working directory and exits.
func TestProcessCrashChild(t *testing.T) {
	action := os.Getenv(envPCrashChild)
	if action == "" {
		t.Skip("only runs as a FuzzProcessCrashRecovery child process")
	}
	killAt, err := strconv.ParseInt(os.Getenv(envPCrashKillAt), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad %s: %v\n", envPCrashKillAt, err)
		os.Exit(pcrashExitHarness)
	}
	resultPath := os.Getenv(envPCrashResult)
	installPCrashSeam(killAt, resultPath)

	code := pcrashExitHarness
	switch action {
	case "admin":
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv(envPCrashArgs)), &args); err != nil {
			fmt.Fprintf(os.Stderr, "bad %s: %v\n", envPCrashArgs, err)
			break
		}
		code = admin.Execute(args)
	case "rotate-dek-split", "rotate-dek-nosplit":
		code = runPCrashSplitAction(action)
	default:
		code = runPCrashCoreAction(context.Background(), action)
	}
	writePCrashResult(resultPath, pcrashChildResult{Seams: pcrashSeams.Load()})
	os.Exit(code)
}
