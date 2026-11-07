// Command powercut measures and crash-tests the SQLite backend's commit path
// with database.fdatasync off or on.
//
//	powercut bench  -db PATH [-fdatasync] [-n N] [-workers W]
//	powercut write  -db PATH -acks FILE [-fdatasync] [-n N] [-workers W]
//	powercut verify -db PATH -acks FILE [-cutoff-ns UNIX_NS]
//
// bench times N audit-event commits (LogAuditEvent, the production audit path:
// hash chain, group commit, WAL, synchronous=FULL) and prints p50/p99/rps.
//
// write commits audit events whose Description is "pc-<i>" and, only after
// LogAuditEvent returned nil (the commit was acknowledged), appends "<i>" to
// the acks file and syncs it. PATH must live on the filesystem under test
// (the dm-flakey device); FILE must live on a different, healthy one, so the
// acknowledgement record survives the simulated power cut.
//
// verify opens the database after the device was remounted, runs
// PRAGMA integrity_check, checks the audit hash chain, and checks that every
// acknowledged index is present. It exits non-zero on any failure.
//
// scripts/powercut/run-dmflakey.sh drives these three around a dm-flakey device.
//
// What this does NOT show: durability on hardware with a volatile write cache
// that lies about flushes (dm-flakey drops writes after the flush barrier
// semantics are honoured, it does not model a lying disk), and nothing about
// filesystems other than the one the script was pointed at.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	msqlite "modernc.org/sqlite"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: powercut bench|write|verify [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	db := fs.String("db", "", "SQLite database path")
	acks := fs.String("acks", "", "acknowledgement file (write, verify)")
	fdatasync := fs.Bool("fdatasync", false, "set storage.database.fdatasync")
	n := fs.Int("n", 2000, "number of commits")
	workers := fs.Int("workers", 1, "concurrent committers")
	cutoff := fs.Int64("cutoff-ns", 0, "verify: only acks timestamped before this Unix ns are required (0 = all)")
	_ = fs.Parse(args)
	if *db == "" {
		fatalf("-db is required")
	}
	switch cmd {
	case "bench":
		runBench(*db, *fdatasync, *n, *workers)
	case "write":
		if *acks == "" {
			fatalf("-acks is required")
		}
		runWrite(*db, *acks, *fdatasync, *n, *workers)
	case "verify":
		if *acks == "" {
			fatalf("-acks is required")
		}
		runVerify(*db, *acks, *cutoff)
	default:
		fatalf("unknown command %q", cmd)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

func openStorage(path string, fdatasync bool) corestorage.Storage {
	if err := i18n.InitializeForTesting(); err != nil {
		fatalf("i18n: %v", err)
	}
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = path
	cfg.Storage.Database.Fdatasync = fdatasync
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	if err != nil {
		fatalf("open storage: %v", err)
	}
	return st
}

func event(i int) *models.AuditEvent {
	return &models.AuditEvent{
		EventType:   "powercut.commit",
		IPAddress:   "127.0.0.1",
		Description: "pc-" + strconv.Itoa(i),
		EventTime:   time.Now().UTC(),
	}
}

// commitAll runs commit(i) for i in [0,n) across workers; the callback runs
// only for acknowledged commits.
func commitAll(st corestorage.Storage, n, workers int, acked func(i int, d time.Duration)) {
	ctx := context.Background()
	work := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range work {
				t0 := time.Now()
				if err := st.LogAuditEvent(ctx, event(i)); err != nil {
					// A failed commit is not acknowledged; the power cut makes these expected.
					continue
				}
				acked(i, time.Since(t0))
			}
		})
	}
	for i := range n {
		work <- i
	}
	close(work)
	wg.Wait()
}

func runBench(path string, fdatasync bool, n, workers int) {
	log.SetOutput(os.Stderr)
	st := openStorage(path, fdatasync)
	// Warm-up: the first commits create WAL/shm and fill caches.
	commitAll(st, 200, workers, func(int, time.Duration) {})

	var mu sync.Mutex
	lat := make([]time.Duration, 0, n)
	t0 := time.Now()
	commitAll(st, n, workers, func(_ int, d time.Duration) {
		mu.Lock()
		lat = append(lat, d)
		mu.Unlock()
	})
	elapsed := time.Since(t0)
	slices.Sort(lat)
	pct := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }
	fmt.Printf("fdatasync_requested=%v fdatasync_effective=%v workers=%d n=%d ok=%d p50=%.3fms p99=%.3fms rps=%.1f\n",
		fdatasync, msqlite.FdatasyncEnabled(), workers, n, len(lat),
		ms(pct(0.50)), ms(pct(0.99)), float64(len(lat))/elapsed.Seconds())
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func runWrite(path, acksPath string, fdatasync bool, n, workers int) {
	log.SetOutput(os.Stderr)
	st := openStorage(path, fdatasync)
	fmt.Printf("fdatasync_requested=%v fdatasync_effective=%v\n", fdatasync, msqlite.FdatasyncEnabled())
	f, err := os.OpenFile(filepath.Clean(acksPath), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fatalf("acks: %v", err)
	}
	defer func() { _ = f.Close() }()
	var mu sync.Mutex
	commitAll(st, n, workers, func(i int, _ time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		// Record the acknowledgement durably, on the healthy filesystem.
		if _, err := fmt.Fprintf(f, "%d %d\n", i, time.Now().UnixNano()); err != nil {
			fatalf("acks write: %v", err)
		}
		if err := f.Sync(); err != nil {
			fatalf("acks sync: %v", err)
		}
	})
}

// readAcks returns the indexes acknowledged strictly before cutoffNanos (a Unix
// nanosecond timestamp; 0 means no cutoff) and the number of lines at or after
// it. After the device starts dropping writes, a commit still "succeeds" (the
// drop is silent), so acknowledgements from then on promise nothing and are
// excluded by the caller passing the moment the cut began.
func readAcks(path string, cutoffNanos int64) (required []int, ignored int, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			// A torn last line from the writer being killed mid-append: that
			// index was never fully acknowledged, so it is not required.
			continue
		}
		i, errI := strconv.Atoi(fields[0])
		ts, errT := strconv.ParseInt(fields[1], 10, 64)
		if errI != nil || errT != nil {
			continue
		}
		if cutoffNanos != 0 && ts >= cutoffNanos {
			ignored++
			continue
		}
		required = append(required, i)
	}
	return required, ignored, sc.Err()
}

func runVerify(path, acksPath string, cutoffNanos int64) {
	acks, ignored, err := readAcks(acksPath, cutoffNanos)
	if err != nil {
		fatalf("acks: %v", err)
	}
	failed := false

	// Open through the production factory (the write-gate guard forbids a raw
	// open). Its start-up migration runs first, which is a no-op on a schema that
	// survived the cut; integrity_check below still covers the whole file.
	st := openStorage(path, false)
	ls, ok := st.(*store.LocalStorage)
	if !ok {
		fatalf("unexpected storage type %T", st)
	}
	db := ls.DB()
	var integrity string
	if err := db.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil {
		fatalf("integrity_check: %v", err)
	}
	fmt.Printf("integrity_check=%s\n", integrity)
	if integrity != "ok" {
		failed = true
	}
	present := map[int]bool{}
	var descs []string
	if err := db.Raw("SELECT description FROM audit_events WHERE event_type = 'powercut.commit'").Scan(&descs).Error; err != nil {
		fatalf("select: %v", err)
	}
	for _, d := range descs {
		if i, err := strconv.Atoi(strings.TrimPrefix(d, "pc-")); err == nil {
			present[i] = true
		}
	}

	missing := 0
	for _, i := range acks {
		if !present[i] {
			missing++
			if missing <= 10 {
				fmt.Printf("MISSING acknowledged commit %d\n", i)
			}
		}
	}
	fmt.Printf("acknowledged_before_cut=%d acknowledged_after_cut_ignored=%d present=%d missing_acknowledged=%d\n",
		len(acks), ignored, len(present), missing)
	if len(acks) == 0 {
		// A run that required nothing proves nothing.
		fmt.Println("no acknowledged commit preceded the cut; nothing was verified")
		failed = true
	}
	if missing > 0 {
		failed = true
	}

	res, err := st.VerifyAuditChain(context.Background(), nil)
	switch {
	case err != nil:
		fmt.Printf("audit_chain_verify_error=%v\n", err)
		failed = true
	case res == nil || !res.Valid:
		fmt.Printf("audit_chain_valid=false result=%+v\n", res)
		failed = true
	default:
		fmt.Printf("audit_chain_valid=true\n")
	}

	if failed {
		fmt.Println("RESULT=FAIL")
		os.Exit(1)
	}
	fmt.Println("RESULT=PASS")
}
