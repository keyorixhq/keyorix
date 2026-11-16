package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// FuzzAuthBudgetLedger is an op-sequence fuzzer over the cluster-wide per-IP
// attempt budgets (rate_limit.go / auth_budget.go, ADR-040): failed-login,
// password-reset and SSO-begin attempts counted per canonical source inside a
// sliding window, the releasable reservations, the relayed attempts and the
// prune sweep, all under a fake clock the program moves, including to the exact
// instant an attempt leaves the window.
//
// The oracle is a ledger of {budget, canonical source, time, released} rows. Its
// rules (stated here, not copied from the code):
//
//   - the same source spelled differently (port suffix, bracketed or compressed
//     IPv6, IPv4-mapped IPv6) is ONE bucket; a non-IP source string is its own
//     bucket spelled as is; an empty source is never counted and never limited;
//   - a source is limited iff the attempts of that budget inside the window,
//     strictly newer than now-window, number at least the budget's limit
//     (login 10, password reset 5, SSO 20; every window 15 min);
//   - the three budgets are separate namespaces over the same table;
//   - a released reservation stops counting, once; releasing it again is a no-op;
//   - a relayed attempt is refused when its key is not an IP (after at most one
//     known namespace prefix) or when its time is in the future, and then stores
//     nothing;
//   - prune removes rows strictly older than min(now-window, before) and never
//     rows newer than now-window.
//
// After EVERY op: every source's three limited verdicts, the number of stored
// rows, and the set of stored keys (all canonical, none with a port) equal the
// ledger's.
//
// Program encoding (op numbers are corpus encoding: APPEND ONLY, never renumber).
// Bytes are (op, arg) pairs, at most authBudgetMaxOps of them; the source is
// authBudgetSources[arg%len], x = arg/len:
//
//	0 record failed login          3 reserve login slot
//	1 record password reset        4 release the x-th unreleased slot
//	2 record SSO begin             5 advance by steps[x%len]
//	6 advance to the instant the oldest counted attempt leaves the window
//	7 advance 1us past that instant
//	8 prune with a zero before     9 prune with before = one of 4 offsets (x%4)
//	10 relay: key = relayKeys[x%len], at = now / now-5m / now+1s by (x/len)%3
//	11 check only
//
// No bcrypt / KDF; the world is one in-memory SQLite per process, emptied per
// input. Not covered: the in-memory fallback used while storage is failing
// (account_lockout_*fallback* tests), concurrent callers, Postgres.
func FuzzAuthBudgetLedger(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0}) // 10 failures: limited
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 11, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 11, 0, 7, 0, 11, 0})
	f.Add([]byte{0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 11, 0}) // spellings collapse
	f.Add([]byte{1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 11, 0, 2, 0, 11, 0})                  // pwreset budget of 5
	f.Add([]byte{3, 0, 3, 0, 3, 0, 4, 0, 4, 0, 4, 0, 11, 0})                         // reserve / double release
	f.Add([]byte{0, 0, 0, 0, 5, 7, 8, 0, 11, 0, 9, 3, 11, 0})                        // prune
	f.Add([]byte{10, 0, 10, 4, 10, 8, 10, 12, 10, 20, 10, 24, 11, 0})                // relay variants

	w := authBudgetWorldInit(f)
	f.Fuzz(func(t *testing.T, prog []byte) { authBudgetProgram(t, w, prog) })
}

const authBudgetMaxOps = 64

// sources: text -> canonical bucket id ("" = not counted at all). Spellings of the
// same address share a bucket id; the id is only a label, chosen independently of
// CanonicalIP.
var authBudgetSources = []struct{ text, bucket string }{
	{"10.0.0.1", "A"}, {"10.0.0.1:5555", "A"}, {"::ffff:10.0.0.1", "A"}, {"[::ffff:10.0.0.1]:443", "A"},
	{"::1", "B"}, {"[::1]:80", "B"}, {"0:0:0:0:0:0:0:1", "B"}, {"[0:0:0:0:0:0:0:1]:9", "B"},
	{"192.168.1.1", "C"}, {"192.168.1.1:22", "C"},
	{"evil-host", "E"}, {"evil-host:80", "E"},
	{"", ""},
}

// relay keys: a known namespace prefix plus an IP spelling, or garbage. bucket ""
// = must be refused as a non-IP key.
var authBudgetRelayKeys = []struct{ key, budget, bucket string }{
	{"10.0.0.1", "login", "A"}, {"pwreset:10.0.0.1", "pwreset", "A"}, {"sso:[::1]:80", "sso", "B"},
	{"sso:0:0:0:0:0:0:0:1", "sso", "B"}, {"192.168.1.1:22", "login", "C"},
	{"bogus", "", ""}, {"pwreset:bogus", "", ""}, {"pwreset:pwreset:10.0.0.1", "", ""}, {"sso:", "", ""}, {"", "", ""},
}

var authBudgetSteps = []time.Duration{
	time.Microsecond, time.Second, time.Minute, 5 * time.Minute, 14 * time.Minute, 15 * time.Minute, 16 * time.Minute, time.Hour,
}

type authBudgetParams struct {
	prefix string
	limit  int
}

var authBudgets = map[string]authBudgetParams{
	"login": {"", 10}, "pwreset": {"pwreset:", 5}, "sso": {"sso:", 20},
}

type authBudgetRow struct {
	budget, bucket string
	at             time.Time
	handle         int // 0 = plain record; >0 = reservation number
	released       bool
}

type authBudgetWorldT struct{ db *gorm.DB }

var (
	authBudgetWorldOnce sync.Once
	authBudgetWorldV    *authBudgetWorldT
	authBudgetWorldErr  error
)

func authBudgetWorldInit(tb testing.TB) *authBudgetWorldT {
	authBudgetWorldOnce.Do(func() {
		db, err := gorm.Open(sqlitedialect.Open(":memory:"), &gorm.Config{})
		if err != nil {
			authBudgetWorldErr = err
			return
		}
		sqlDB, err := db.DB()
		if err != nil {
			authBudgetWorldErr = err
			return
		}
		sqlDB.SetMaxOpenConns(1)
		authBudgetWorldErr = db.AutoMigrate(&models.LoginAttempt{}, &models.AuditEvent{})
		authBudgetWorldV = &authBudgetWorldT{db: db}
	})
	if authBudgetWorldErr != nil {
		tb.Fatalf("auth budget world: %v", authBudgetWorldErr)
	}
	return authBudgetWorldV
}

func authBudgetProgram(t *testing.T, w *authBudgetWorldT, prog []byte) {
	t.Helper()
	for _, tbl := range []string{"login_attempts", "audit_events"} {
		if err := w.db.Exec("DELETE FROM " + tbl).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- hardcoded literals
			t.Fatalf("reset %s: %v", tbl, err)
		}
	}
	ctx := context.Background()
	clock := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{
		storage:        store.NewLocalStorage(w.db),
		now:            func() time.Time { return clock },
		passwordPolicy: DefaultPasswordPolicy(),
	}
	const window = 15 * time.Minute

	var (
		rows    []*authBudgetRow
		handles []*authBudgetRow // reservations by number-1, login budget only
		ids     = map[*authBudgetRow]uint{}
	)
	counted := func(r *authBudgetRow, now time.Time) bool { return !r.released && r.at.After(now.Add(-window)) }
	limited := func(budget, bucket string) bool {
		n := 0
		for _, r := range rows {
			if r.budget == budget && r.bucket == bucket && counted(r, clock) {
				n++
			}
		}
		return n >= authBudgets[budget].limit
	}
	add := func(budget, bucket string, at time.Time) *authBudgetRow {
		r := &authBudgetRow{budget: budget, bucket: bucket, at: at}
		rows = append(rows, r)
		return r
	}
	oldestCounted := func() *authBudgetRow {
		var best *authBudgetRow
		for _, r := range rows {
			if counted(r, clock) && (best == nil || r.at.Before(best.at)) {
				best = r
			}
		}
		return best
	}
	prune := func(before time.Time) {
		cutoff := clock.Add(-window)
		if !before.IsZero() && before.Before(cutoff) {
			cutoff = before
		}
		keep := rows[:0]
		for _, r := range rows {
			if !r.released && r.at.Before(cutoff) {
				continue
			}
			keep = append(keep, r)
		}
		rows = keep
	}

	check := func(step int, what string) {
		t.Helper()
		// Every bucket is asked every step, through one spelling that rotates with
		// the step (so each spelling is exercised without asking all of them each time).
		seen := map[string]int{}
		for _, src := range authBudgetSources {
			seen[src.bucket]++
		}
		turn := map[string]int{}
		for _, src := range authBudgetSources {
			if k := turn[src.bucket]; src.bucket != "" && k != step%seen[src.bucket] {
				turn[src.bucket]++
				continue
			}
			turn[src.bucket]++
			for _, b := range []struct {
				name string
				is   func(context.Context, string) bool
			}{{"login", c.IsLoginRateLimited}, {"pwreset", c.IsPasswordResetRateLimited}, {"sso", c.IsSSOBeginRateLimited}} {
				want := src.bucket != "" && limited(b.name, src.bucket)
				if got := b.is(ctx, src.text); got != want {
					t.Fatalf("step %d (%s): %s limited(%q)=%v, ledger=%v (now %s)", step, what, b.name, src.text, got, want, clock.Format(time.RFC3339Nano))
				}
			}
		}
		var stored []struct{ IP string }
		if err := w.db.Raw("SELECT ip FROM login_attempts").Scan(&stored).Error; err != nil {
			t.Fatalf("read login_attempts: %v", err)
		}
		alive := 0
		for _, r := range rows {
			if !r.released {
				alive++
			}
		}
		if len(stored) != alive {
			t.Fatalf("step %d (%s): %d rows stored, ledger has %d", step, what, len(stored), alive)
		}
		want := map[string]int{}
		for _, r := range rows {
			if r.released {
				continue
			}
			want[authBudgets[r.budget].prefix+authBudgetCanon(r.bucket)]++
		}
		for _, s := range stored {
			want[s.IP]--
		}
		for k, n := range want {
			if n != 0 {
				t.Fatalf("step %d (%s): stored keys differ from ledger at %q (ledger-stored=%d)", step, what, k, n)
			}
		}
	}

	for i := 0; i+1 < len(prog) && i/2 < authBudgetMaxOps; i += 2 {
		op, arg := prog[i]%12, int(prog[i+1])
		src := authBudgetSources[arg%len(authBudgetSources)]
		x := arg / len(authBudgetSources)
		step := i / 2
		what := fmt.Sprintf("op %d src %q x %d", op, src.text, x)
		switch op {
		case 0:
			c.RecordFailedLogin(ctx, src.text)
			if src.bucket != "" {
				add("login", src.bucket, clock)
			}
		case 1:
			c.RecordPasswordResetAttempt(ctx, src.text)
			if src.bucket != "" {
				add("pwreset", src.bucket, clock)
			}
		case 2:
			c.RecordSSOBeginAttempt(ctx, src.text)
			if src.bucket != "" {
				add("sso", src.bucket, clock)
			}
		case 3:
			id, ok := c.ReserveLoginAttempt(ctx, src.text)
			if ok != (src.bucket != "") {
				t.Fatalf("step %d (%s): reserve ok=%v for source %q", step, what, ok, src.text)
			}
			if ok {
				if id == 0 {
					t.Fatalf("step %d (%s): reserve returned a zero handle", step, what)
				}
				r := add("login", src.bucket, clock)
				r.handle = len(handles) + 1
				handles = append(handles, r)
				ids[r] = id
			}
		case 4:
			var open []*authBudgetRow
			for _, r := range handles {
				if !r.released {
					open = append(open, r)
				}
			}
			if len(open) == 0 {
				break
			}
			r := open[x%len(open)]
			c.ReleaseLoginAttempt(ctx, ids[r])
			r.released = true
		case 5:
			clock = clock.Add(authBudgetSteps[x%len(authBudgetSteps)])
		case 6, 7:
			if r := oldestCounted(); r != nil {
				target := r.at.Add(window)
				if op == 7 {
					target = target.Add(time.Microsecond)
				}
				if target.After(clock) {
					clock = target
				}
			}
		case 8:
			if _, err := c.PruneLoginAttempts(ctx, time.Time{}, 0); err != nil {
				t.Fatalf("step %d: prune: %v", step, err)
			}
			prune(time.Time{})
		case 9:
			before := [...]time.Time{clock.Add(time.Hour), clock.Add(-window), clock.Add(-30 * time.Minute), clock.Add(-5 * time.Minute)}[x%4]
			if _, err := c.PruneLoginAttempts(ctx, before, 0); err != nil {
				t.Fatalf("step %d: prune(before): %v", step, err)
			}
			prune(before)
		case 10:
			rk := authBudgetRelayKeys[x%len(authBudgetRelayKeys)]
			at := [...]time.Time{clock, clock.Add(-5 * time.Minute), clock.Add(time.Second)}[(x/len(authBudgetRelayKeys))%3]
			err := c.RecordLoginAttemptRelay(ctx, rk.key, at)
			future := at.After(clock)
			switch {
			case rk.bucket == "":
				if err == nil {
					t.Fatalf("step %d (%s): relay key %q accepted, want ErrInvalidLoginAttemptKey", step, what, rk.key)
				}
			case future:
				if err == nil {
					t.Fatalf("step %d (%s): relay with a future time accepted", step, what)
				}
			default:
				if err != nil {
					t.Fatalf("step %d (%s): relay of %q refused: %v", step, what, rk.key, err)
				}
				add(rk.budget, rk.bucket, at)
			}
		case 11:
		}
		check(step, what)
	}
}

// authBudgetCanon is the stored spelling of a bucket label: written out here, not
// derived from CanonicalIP.
func authBudgetCanon(bucket string) string {
	switch bucket {
	case "A":
		return "10.0.0.1"
	case "B":
		return "::1"
	case "C":
		return "192.168.1.1"
	case "E":
		return "evil-host"
	}
	return strings.ToLower(bucket)
}
