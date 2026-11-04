package admin

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
)

// fakeLoader plays the loader's notification sequence against a reporter with
// a clock the test advances by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestRestoreProgress_HeartbeatsAndTableBoundaries(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	var buf bytes.Buffer
	cb := newRestoreProgress(&buf, true, clk.now, 10*time.Second).callback()

	cb(backupfmt.LoadProgress{Table: "secrets", TableTotal: 1000, TablesTotal: 2, Start: true})
	clk.t = clk.t.Add(3 * time.Second)
	cb(backupfmt.LoadProgress{Table: "secrets", TableRows: 200, TableTotal: 1000, TablesTotal: 2}) // inside interval: silent
	clk.t = clk.t.Add(8 * time.Second)
	cb(backupfmt.LoadProgress{Table: "secrets", TableRows: 600, TableTotal: 1000, TablesTotal: 2}) // 11s since last line: heartbeat
	clk.t = clk.t.Add(1 * time.Second)
	cb(backupfmt.LoadProgress{Table: "secrets", TableRows: 1000, TableTotal: 1000, TablesTotal: 2, Finished: true})
	cb(backupfmt.LoadProgress{Table: "users", TableTotal: 5, TablesDone: 1, TablesTotal: 2, Start: true})

	want := []string{
		"restore progress: table=secrets (1/2) start rows=0/1000 elapsed=0s",
		"restore progress: table=secrets (1/2) loading rows=600/1000 elapsed=11s",
		"restore progress: table=secrets (1/2) done rows=1000/1000 elapsed=12s",
		"restore progress: table=users (2/2) start rows=0/5 elapsed=12s",
	}
	got := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), buf.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got  %q\n want %q", i, got[i], want[i])
		}
	}
}

func TestRestoreProgress_DisabledIsSilent(t *testing.T) {
	var buf bytes.Buffer
	p := newRestoreProgress(&buf, false, time.Now, time.Second)
	if p != nil || p.callback() != nil {
		t.Fatal("disabled reporter must be nil with a nil callback")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected output %q", buf.String())
	}
}

func TestRestoreProgressEnabled_VerboseForcesOn(t *testing.T) {
	if !restoreProgressEnabled(true) {
		t.Fatal("--verbose must enable progress even when stderr is not a terminal")
	}
}

func TestRestoreProgress_LineCarriesNoSecretMaterial(t *testing.T) {
	var buf bytes.Buffer
	cb := newRestoreProgress(&buf, true, time.Now, time.Second).callback()
	cb(backupfmt.LoadProgress{Table: "secrets", TableRows: 1, TableTotal: 1, TablesTotal: 1, Finished: true})
	line := buf.String()
	for _, bad := range []string{"passphrase", "key=", "value="} {
		if strings.Contains(line, bad) {
			t.Errorf("progress line contains %q: %q", bad, line)
		}
	}
}
