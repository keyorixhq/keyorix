package mysqlhostile

// resguard_mysql_test.go — PK1 port of the go-sql-driver/mysql hostile-server
// targets onto the shared resguard resource layer. Same design as the pgx port
// (resguard_pgx package): the pre-existing no-panic/bounded-time/LOCAL-INFILE
// oracles are UNCHANGED (they live in the driveMySQL* functions); a resguard.Probe
// is wrapped around each input to meter alloc_bytes/mallocs (the RAM-spike signal)
// and process CPU (advisory), checked against a per-target calibrated budget.
//
// Budget model: AbsMax for the fixed-shape Handshake greeting, per-byte slope for
// the Query/Prepared response parsers. live_heap is dropped (whole-process). No
// network/sleep meters: the harness dials its own loopback server, not a connector.
//
// What this oracle does NOT verify: correctness (only alloc proportion); alloc is
// sampled (1-in-32 + slow inputs); CPU is a process-wide getrusage delta (advisory,
// never fatal); the meter cannot separate the test server's allocation from the
// driver's (both run inside the measured call, alloc is a process-wide delta).

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const (
	mysqlBudgetHandshake = "testdata/resguard-mysql-handshake.json"
	mysqlBudgetQuery     = "testdata/resguard-mysql-query.json"
	mysqlBudgetPrepared  = "testdata/resguard-mysql-prepared.json"
)

func mysqlResguardProbe(f *testing.F, budgetPath string) (*resguard.Probe, resguard.Budget, bool) {
	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	b, err := resguard.LoadBudget(budgetPath)
	if err != nil {
		f.Logf("resguard: no budget at %s (%v); metering without a ceiling [%s]", budgetPath, err, resguard.Platform())
	}
	return probe, b, err == nil
}

func measureMySQL(t *testing.T, probe *resguard.Probe, budget resguard.Budget, haveBudget bool, resp []byte, drive func(*testing.T, []byte)) {
	cost := probe.Measure(len(resp), func() { drive(t, resp) })
	resguard.FeedCoverage(cost)
	if haveBudget {
		budget.Check(t.Fatalf, cost)
	}
}

// mysqlMemMeters: see pgxMemMeters — same reasoning (alloc per-input attributable,
// live_heap dropped as whole-process, cpu advisory).
var mysqlMemMeters = []string{"alloc_bytes", "mallocs", "cpu_ns"}

// benignQueryResultSet is a legitimate 1-column, one-row text result set, used as a
// larger-but-benign calibration sample so the slope's per-byte term reflects a real
// result set, not only a bare OK packet.
func benignQueryResultSet() []byte {
	colDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, 'c', 0, 1, 'c', 0, 0x0c, 0x2d, 0, 4, 0, 0, 0, 0xfd, 0, 0, 0, 0})
	rs := append(frame(1, []byte{0x01}), colDef...)
	rs = append(rs, frame(3, []byte{0xfe, 0, 0, 0x02, 0})...)
	rs = append(rs, frame(4, []byte{2, 'h', 'i'})...)
	rs = append(rs, frame(5, []byte{0xfe, 0, 0, 0x02, 0})...)
	return rs
}

func mysqlBenignHandshake() [][]byte {
	return [][]byte{
		greeting(),
		append(greeting(), okPacket(2)...),
		errPacket(0, 1045, "Access denied"),
	}
}

func mysqlBenignQuery() [][]byte {
	return [][]byte{
		okPacket(1),
		errPacket(1, 1064, "You have an error"),
		benignQueryResultSet(),
	}
}

func mysqlBenignPrepared() [][]byte {
	prepOK := frame(1, []byte{0x00, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0})
	paramDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 0, 0, 0, 0x0c, 0x3f, 0, 0, 0, 0, 0, 0xfd, 0x80, 0, 0, 0})
	eof := frame(3, []byte{0xfe, 0, 0, 0x02, 0})
	full := append(append(prepOK, paramDef...), eof...)
	return [][]byte{full, errPacket(1, 1146, "Table doesn't exist")}
}

func calibrateMySQL(t testing.TB, name string, corpus [][]byte, drive func(*testing.T, []byte), absolute bool) resguard.Budget {
	t.Helper()
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	tt := t.(*testing.T)
	var costs []resguard.Cost
	for range 3 {
		for _, seed := range corpus {
			costs = append(costs, probe.Measure(len(seed), func() { drive(tt, seed) }))
		}
	}
	b := resguard.Calibrate(name, costs, resguard.DefaultFactor)
	b.KeepOnly(mysqlMemMeters...)
	if absolute {
		b.UseAbsolute(mysqlMemMeters...)
	}
	return b
}

type mysqlCalTarget struct {
	name     string
	path     string
	corpus   [][]byte
	drive    func(*testing.T, []byte)
	absolute bool
}

func mysqlCalTargets() []mysqlCalTarget {
	return []mysqlCalTarget{
		{"mysql_handshake", mysqlBudgetHandshake, mysqlBenignHandshake(), driveMySQLHandshake, true},
		{"mysql_query", mysqlBudgetQuery, mysqlBenignQuery(), driveMySQLQuery, false},
		{"mysql_prepared", mysqlBudgetPrepared, mysqlBenignPrepared(), driveMySQLPrepared, false},
	}
}

func TestResguardMySQLCalibrate(t *testing.T) {
	for _, tgt := range mysqlCalTargets() {
		b := calibrateMySQL(t, tgt.name, tgt.corpus, tgt.drive, tgt.absolute)
		if len(b.Meters) == 0 {
			t.Fatalf("%s: no memory meter calibrated; %s", tgt.name, b.Summary())
		}
		if os.Getenv("RESGUARD_CALIBRATE") == "1" {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := b.WriteJSON(tgt.path); err != nil {
				t.Fatalf("%s: write budget: %v", tgt.name, err)
			}
			t.Logf("wrote %s: %s", tgt.path, b.Summary())
		}
	}
}

// TestResguardMySQLRedGreen — committed red/green for the mysql memory oracle. Same
// shape as the pgx proof: benign measured reply passes; a synthesized alloc
// amplification of the same input trips the budget naming alloc_bytes. (The driver
// does not amplify on any seed; the fuzz run exercises real hostile inputs.)
func TestResguardMySQLRedGreen(t *testing.T) {
	b := calibrateMySQL(t, "mysql_query", mysqlBenignQuery(), driveMySQLQuery, false)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("no alloc_bytes budget calibrated; %s", b.Summary())
	}
	probe := resguard.New(t, resguard.Options{SampleEvery: 1})
	seed := benignQueryResultSet()
	green := probe.Measure(len(seed), func() { driveMySQLQuery(t, seed) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign result set (alloc=%d) must pass the budget", green.AllocBytes)
	}
	red := green
	red.Sampled = true
	red.AllocBytes = green.AllocBytes*1000 + 1<<30
	red.Mallocs = green.Mallocs*1000 + 1
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("RED: a 1000x alloc amplification must trip the budget")
	}
	if !strings.Contains(msg, "alloc_bytes") {
		t.Fatalf("RED: failure message should name alloc_bytes: %q", msg)
	}
	t.Logf("GREEN alloc=%d passes; RED alloc=%d fires: %s", green.AllocBytes, red.AllocBytes, msg)
}
