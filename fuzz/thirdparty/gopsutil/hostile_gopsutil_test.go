// Hostile-/proc fuzz harness for shirou/gopsutil/v4's Linux parsers.
//
// gopsutil parses kernel pseudo-files (/proc/stat, /proc/meminfo) into structs.
// This target feeds those parsers attacker-chosen file CONTENT via gopsutil's
// own public per-call env injection (common.EnvMap{HostProcEnvKey: ...} on the
// context), writing the fuzzed bytes into a fake HOST_PROC root and calling the
// exact public functions Keyorix's call path reaches (cpu.Times/Percent read
// /proc/stat; mem is the adjacent host-stats parser).
//
// load.Avg is excluded: a known-open upstream robustness defect, recorded
// privately. The loadavg parser is therefore NOT fuzzed by this committed target
// (it would red CI); Keyorix does not call load.Avg anyway.
//
// REACHABILITY NOTE (recorded, does not gate a library finding): Keyorix only
// calls cpu.Percent and disk.Usage against the LOCAL host's real /proc, which is
// trusted — an attacker controlling /proc already owns the host. So Keyorix has
// NO untrusted-input exposure here; this target probes gopsutil's parser
// robustness as a library (relevant to every consumer that runs it inside a
// container, on an exotic kernel, or over a HOST_PROC pointed at caller data).
//
// Oracle (crash-only parser — gopsutil has no serialiser for these):
//   - no panic inside the parser for any file content.
//   - bounded work: a parse of a <=64KiB fake file returns within a generous
//     wall budget; a timeout is a hang/CPU-DoS finding.
//
// What this oracle does NOT verify: that parsed values are correct, allocation
// ceilings (relies on the go fuzzer's OOM detection), any non-Linux code path,
// or multi-file consistency (only one pseudo-file is populated per exec).
package gopsutilhostile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/common"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

// One fake HOST_PROC dir per worker PROCESS (go fuzz workers are separate
// processes, each running inputs serially), so there is never a concurrent write
// and no per-exec mkdir/rm churn on the shared host.
var procDir = func() string {
	d := filepath.Join(os.TempDir(), fmt.Sprintf("gopsutil-fuzz-%d", os.Getpid()))
	_ = os.MkdirAll(d, 0o755)
	return d
}()

// TestMain removes this process's fake HOST_PROC dir on exit so workers do not
// leak one directory per run.
func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.RemoveAll(procDir)
	os.Exit(code)
}

func ctxWithProc() context.Context {
	return context.WithValue(context.Background(), common.EnvKey,
		common.EnvMap{common.HostProcEnvKey: procDir})
}

func FuzzGopsutilProc(f *testing.F) {
	f.Add(uint8(0), []byte("cpu  100 0 200 300 0 0 0 0 0 0\ncpu0 50 0 100 150 0 0 0 0 0 0\n"))
	f.Add(uint8(0), []byte("cpu 1\n"))
	f.Add(uint8(1), []byte("MemTotal: 2048 kB\nMemFree: 1024 kB\nMemAvailable: 1500 kB\n"))
	f.Add(uint8(1), []byte("MemTotal:\n"))
	f.Add(uint8(0), []byte("cpu x y z\n"))
	f.Add(uint8(1), []byte("MemFree 1 2 3\n"))

	// load.Avg deliberately excluded (see header).
	f.Fuzz(func(t *testing.T, sel uint8, data []byte) {
		// On non-Linux hosts cpu/mem ignore HOST_PROC and read the real host, so
		// the target would exercise nothing and still report green.
		if runtime.GOOS != "linux" {
			t.Skip("gopsutil HOST_PROC injection only applies on linux")
		}
		if len(data) > 64*1024 {
			return
		}
		files := []string{"stat", "meminfo"}
		which := int(sel) % len(files)
		fpath := filepath.Join(procDir, files[which])
		if err := os.WriteFile(fpath, data, 0o644); err != nil {
			t.Skipf("write fake proc file: %v", err)
		}
		ctx := ctxWithProc()
		done := make(chan struct{})
		go func() {
			defer close(done)
			switch which {
			case 0:
				_, _ = cpu.TimesWithContext(ctx, true)
				_, _ = cpu.TimesWithContext(ctx, false)
			case 1:
				_, _ = mem.VirtualMemoryWithContext(ctx)
			}
		}()
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Fatalf("bounded-work: gopsutil parse of %s did not return in 12s for %d-byte input", files[which], len(data))
		}
	})
}
