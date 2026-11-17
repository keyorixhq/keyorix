// Command powercut-pg is the PostgreSQL twin of scripts/powercut: it crash-tests
// the Postgres storage backend's commit durability across a dm-flakey power cut.
//
//	powercut-pg write  -dsn DSN -acks FILE [-n N] [-workers W] [-durability strict|standard]
//	powercut-pg verify -dsn DSN -acks FILE [-cutoff-ns UNIX_NS]
//
// It is the exact counterpart of scripts/powercut/main.go, re-expressed against
// Postgres and driven by scripts/powercut-pg/run-dmflakey-pg.sh around a
// dm-flakey device and a throwaway `initdb`'d cluster. The differences from the
// SQLite tool, and why they exist:
//
//   - The database is a SEPARATE server process (`postgres`) whose data
//     directory lives on the dm-flakey filesystem; this tool only CONNECTS to
//     it over the DSN. The power cut therefore has to be re-expressed against
//     Postgres's own crash-recovery path (WAL replay on restart), which the
//     shell driver checks in the server log — the SQLite tool has no equivalent
//     because SQLite is in-process.
//
//   - Durability. On Postgres the DEFAULT audit durability is `standard`
//     (ADR-112 Amendment 3): the audit commit issues `SET LOCAL
//     synchronous_commit = off`, so a returned LogAuditEvent does NOT promise
//     the row's WAL record was fsync'd. Treating an acknowledgement as a
//     durability promise under `standard` is therefore UNSOUND — an
//     acknowledged-then-lost commit there is by design, not a defect. `write`
//     defaults to `-durability strict` so an acknowledgement means the WAL
//     record was fsync'd before COMMIT returned, exactly mirroring the SQLite
//     tool's synchronous=FULL. The shell driver also runs a `standard` shape as
//     a documented NEGATIVE control: there, acknowledged commits MAY be lost and
//     that is not failed.
//
// write commits audit events whose Description is "pc-<i>" and, only after
// LogAuditEvent returned nil (the commit was acknowledged), appends "<i>
// <unix-ns>" to the acks file and fsyncs it. The DSN must point at a cluster
// whose data directory is on the filesystem under test; FILE must live on a
// different, healthy one, so the acknowledgement record survives the cut.
//
// verify opens the database after the device was remounted and the server
// recovered, then checks: every index acknowledged before the cut is present,
// the audit hash chain verifies (VerifyAuditChain — the Postgres analog of the
// SQLite tool's PRAGMA integrity_check + hash-chain pair; a torn/partial audit
// row cannot be committed on Postgres given full_page_writes, and pg_amcheck in
// the shell driver covers heap/index structural tearing across every table). It
// exits non-zero on any failure.
//
// What this does NOT show (same caveats as scripts/powercut): durability on
// hardware with a volatile write cache that lies about flushes (dm-flakey
// honours flushes issued before the switch and drops whole bios after it, it
// does not model a lying disk), and nothing about filesystems other than the
// ext4 the driver builds.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: powercut-pg write|verify [flags]")
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dsn := fs.String("dsn", "", "PostgreSQL DSN (libpq keyword form)")
	acks := fs.String("acks", "", "acknowledgement file (write, verify)")
	durability := fs.String("durability", "strict", "audit durability: strict (acknowledged => fsync'd) or standard (PG default, acknowledged promises nothing)")
	n := fs.Int("n", 20000, "number of commits")
	workers := fs.Int("workers", 4, "concurrent committers")
	cutoff := fs.Int64("cutoff-ns", 0, "verify: only acks timestamped before this Unix ns are required (0 = all)")
	_ = fs.Parse(args)
	if *dsn == "" {
		fatalf("-dsn is required")
	}
	switch cmd {
	case "write":
		if *acks == "" {
			fatalf("-acks is required")
		}
		runWrite(*dsn, *acks, *durability, *n, *workers)
	case "verify":
		if *acks == "" {
			fatalf("-acks is required")
		}
		runVerify(*dsn, *acks, *cutoff)
	default:
		fatalf("unknown command %q", cmd)
	}
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

// openStorage opens the Postgres backend through the PRODUCTION storage factory
// (never a raw gorm.Open — the same discipline scripts/powercut keeps), so the
// real start-up migration runs and the real audit-commit path is exercised.
// durability picks the audit commit's synchronous_commit behaviour (see the
// package doc); "" and "strict" both mean strict.
func openStorage(dsn, durability string) corestorage.Storage {
	if err := i18n.InitializeForTesting(); err != nil {
		fatalf("i18n: %v", err)
	}
	if durability == "" {
		durability = string(config.AuditDurabilityStrict)
	}
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	// Built as one literal (not a field assignment): TestAuditDurability_
	// NoWriteAssignment forbids assigning the durability field outside
	// internal/config. This tool is a standalone harness, not a request path.
	// A small pool: this tool opens one cluster on a loopback port and a
	// handful of workers; the factory additionally opens the lock pools.
	cfg.Storage.Database = config.DatabaseConfig{
		DSN:             dsn,
		AuditDurability: durability,
		MaxOpenConns:    16,
		MaxIdleConns:    4,
	}
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

// commitAll runs LogAuditEvent for i in [0,n) across workers; acked runs only
// for acknowledged commits. Identical shape to scripts/powercut's commitAll.
func commitAll(st corestorage.Storage, n, workers int, acked func(i int)) {
	ctx := context.Background()
	work := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range work {
				// audit-direct-ok: this is the dm-flakey power-cut tool, a
				// standalone dev/test binary never linked into the server. It
				// writes only fixed powercut.commit events with no ActorType,
				// UserID or MachineIdentityID, so it can never emit a
				// machine-identity-typed event that needs the emitAudit stamp;
				// the rows only exist to be counted and hash-chain-verified
				// after the cut.
				if err := st.LogAuditEvent(ctx, event(i)); err != nil {
					// A failed commit is not acknowledged; the cut makes these expected.
					continue
				}
				acked(i)
			}
		})
	}
	for i := range n {
		work <- i
	}
	close(work)
	wg.Wait()
}

func runWrite(dsn, acksPath, durability string, n, workers int) {
	st := openStorage(dsn, durability)
	dbCfg := config.DatabaseConfig{AuditDurability: durability}
	eff := dbCfg.EffectiveAuditDurability("postgres")
	fmt.Printf("durability_requested=%s durability_effective=%s\n", durability, eff.Level)
	f, err := os.OpenFile(filepath.Clean(acksPath), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G703 -- acksPath is the operator's own flag to this hand-run power-cut tool, no remote input
	if err != nil {
		fatalf("acks: %v", err)
	}
	defer func() { _ = f.Close() }()
	var mu sync.Mutex
	commitAll(st, n, workers, func(i int) {
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

// readAcks returns the indexes acknowledged strictly before cutoffNanos (0 =
// no cutoff) and the number at or after it. Identical to scripts/powercut's.
func readAcks(path string, cutoffNanos int64) (required []int, ignored int, err error) {
	f, err := os.Open(filepath.Clean(path)) // #nosec G703 -- path is the operator's own flag to this hand-run power-cut tool, no remote input
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

func runVerify(dsn, acksPath string, cutoffNanos int64) {
	acks, ignored, err := readAcks(acksPath, cutoffNanos)
	if err != nil {
		fatalf("acks: %v", err)
	}
	failed := false

	// Open through the production factory (the write-gate guard forbids a raw
	// open). Its start-up migration runs first, a no-op on a schema that
	// survived the cut. Durability is irrelevant for a read-only verify.
	st := openStorage(dsn, "strict")
	ls, ok := st.(*store.LocalStorage)
	if !ok {
		fatalf("unexpected storage type %T", st)
	}
	db := ls.DB()

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
