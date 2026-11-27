package soak

// sampler_test.go takes one point of every resource series the soak watches.
//
// Series sampled, and how each is measured:
//
//	goroutines     runtime.NumGoroutine, plus the goroutine profile (debug=1)
//	               grouped by stack, so a leak names the function that leaks
//	heap_inuse     runtime.MemStats.HeapInuse after two runtime.GC calls
//	heap_objects   runtime.MemStats.HeapObjects after the same GCs
//	fds            entries of /proc/self/fd (Linux) or /dev/fd (macOS); when
//	               neither exists the series is SKIPPED with an explicit line
//	db_open/in_use/idle/wait   database/sql DBStats of the soak's pool
//	temp_files     entries under the soak-owned TMPDIR
//	rows_<table>   COUNT(*) of the bookkeeping tables that exist
//
// A sample deliberately perturbs the system as little as it can (one COUNT per
// table, taken AFTER DBStats), but it does run runtime.GC, so do not sample
// faster than every second or so.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"time"
)

// bookkeepingTables are the tables whose row count says something about
// unbounded growth. A table that does not exist on the backend is skipped, and
// the skip is printed (sampleRows), never silent.
var bookkeepingTables = []string{
	"sessions", "rate_limits", "login_attempts", "audit_events",
	"secret_access_logs", "notifications", "password_histories",
}

// sample is one point of every series.
type sample struct {
	Seq      int
	At       time.Duration // since the run started
	Requests int64         // requests completed so far

	Goroutines  int
	Stacks      map[string]stackGroup // by signature
	HeapInuse   uint64
	HeapObjects uint64
	FDs         int // -1: unavailable on this platform
	DBOpen      int
	DBInUse     int
	DBIdle      int
	DBWaitCount int64
	TempFiles   int
	TempNames   []string
	Rows        map[string]int64
}

// stackGroup is the set of goroutines sharing one stack.
type stackGroup struct {
	Sig   string // function names top to bottom, "<"-joined, no offsets
	Top   string // first frame outside the runtime: the name a report uses
	Count int
	Full  string // the debug=1 text of the group, for failure messages
}

// takeSample measures every series now. keepStacks keeps the grouped goroutine
// profile (the baseline and the final sample need it; an in-load sample does
// not), and keepFull additionally keeps each group's stack text (only the final
// sample prints it). Retaining profile text in every sample would itself show
// up as heap growth in the series being measured.
func takeSample(e *soakEnv, seq int, started time.Time, requests int64, keepStacks, keepFull bool) sample {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st := e.sqlDB.Stats()
	s := sample{
		Seq: seq, At: time.Since(started), Requests: requests,
		Goroutines: runtime.NumGoroutine(),
		HeapInuse:  ms.HeapInuse, HeapObjects: ms.HeapObjects,
		FDs:    countFDs(),
		DBOpen: st.OpenConnections, DBInUse: st.InUse, DBIdle: st.Idle, DBWaitCount: st.WaitCount,
	}
	s.TempFiles, s.TempNames = listTemp(e.tmpDir)
	s.Rows = sampleRows(e)
	if keepStacks {
		s.Stacks = goroutineGroups()
		if !keepFull {
			for sig, g := range s.Stacks {
				g.Full = ""
				s.Stacks[sig] = g
			}
		}
	}
	return s
}

// goroutineGroups parses the debug=1 goroutine profile.
//
//	3 @ 0x... 0x...
//	#	0x...	pkg.fn+0x1c	/path/file.go:12
func goroutineGroups() map[string]stackGroup {
	var buf bytes.Buffer
	if p := pprof.Lookup("goroutine"); p != nil {
		_ = p.WriteTo(&buf, 1)
	}
	return parseGoroutineProfile(buf.String())
}

func parseGoroutineProfile(text string) map[string]stackGroup {
	out := map[string]stackGroup{}
	var cur *stackGroup
	var funcs []string
	var raw strings.Builder
	flush := func() {
		if cur == nil {
			return
		}
		cur.Sig = strings.Join(funcs, " < ")
		cur.Full = raw.String()
		cur.Top = topFrame(funcs)
		g := out[cur.Sig]
		g.Sig, g.Top, g.Full = cur.Sig, cur.Top, cur.Full
		g.Count += cur.Count
		out[cur.Sig] = g
		cur = nil
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "goroutine profile:"):
		case len(line) > 0 && line[0] >= '0' && line[0] <= '9' && strings.Contains(line, " @ "):
			flush()
			var n int
			_, _ = fmt.Sscanf(line, "%d @", &n)
			cur, funcs = &stackGroup{Count: n}, nil
			raw.Reset()
			raw.WriteString(line + "\n")
		case strings.HasPrefix(line, "#\t0x"):
			if cur == nil {
				continue
			}
			raw.WriteString(line + "\n")
			f := strings.Split(line, "\t")
			if len(f) >= 3 {
				name := f[2]
				if i := strings.LastIndex(name, "+0x"); i > 0 {
					name = name[:i]
				}
				funcs = append(funcs, name)
			}
		case strings.HasPrefix(line, "#"):
			if cur != nil {
				raw.WriteString(line + "\n")
			}
		}
	}
	flush()
	return out
}

// topFrame is the first frame that is not scheduler/runtime plumbing.
func topFrame(funcs []string) string {
	for _, f := range funcs {
		if strings.HasPrefix(f, "runtime.") || strings.HasPrefix(f, "internal/poll.") ||
			strings.HasPrefix(f, "sync.") || strings.HasPrefix(f, "internal/sync.") {
			continue
		}
		return f
	}
	if len(funcs) > 0 {
		return funcs[0]
	}
	return "?"
}

// countFDs counts this process's open descriptors, or -1 when the platform
// offers no cheap way (the caller prints the SKIP).
func countFDs() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		ents, err := os.ReadDir(dir)
		if err == nil {
			return len(ents)
		}
	}
	return -1
}

// listTemp returns the number of entries (files and directories, recursive)
// under dir, and up to 20 names for a failure message.
func listTemp(dir string) (int, []string) {
	n := 0
	var names []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		n++
		if len(names) < 20 {
			rel, _ := filepath.Rel(dir, p)
			names = append(names, rel)
		}
		return nil
	})
	sort.Strings(names)
	return n, names
}

// sampleRows counts the bookkeeping tables that exist.
func sampleRows(e *soakEnv) map[string]int64 {
	rows := map[string]int64{}
	for _, t := range bookkeepingTables {
		if !e.db.Migrator().HasTable(t) {
			continue
		}
		var n int64
		if err := e.db.Table(t).Count(&n).Error; err == nil {
			rows[t] = n
		}
	}
	return rows
}
