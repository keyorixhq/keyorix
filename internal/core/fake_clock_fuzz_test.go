package core

// fake_clock_fuzz_test.go -- extreme-instant fake-clock fuzzing.
// Scope, oracles (O1-O6), planted mutants (R1) and the finding rules (R3) are
// pre-registered in FAKE_CLOCK_FUZZ.md (same directory). No production code is
// changed: this drives the existing KeyorixCore.SetClockForTesting seam.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // real zone rules regardless of the host's tzdata

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/gorm"
)

// ---- special instants and TTLs ----------------------------------------------

// fakeClockInstants are the clock program's jump targets and the base instants of a
// mint. Year 0 and the last three entries never mint (see fkcMint); they stay in the
// table as jump targets, and appending or reordering changes the fuzz input encoding.
var fakeClockInstants = []time.Time{
	{}, // zero time, 0001-01-01
	time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
	time.Unix(0, 0).UTC(),
	time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
	time.Date(2000, 2, 29, 12, 0, 0, 0, time.UTC),
	time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC), // last leap-second day
	time.Date(2024, 2, 29, 23, 59, 59, 999999999, time.UTC),
	time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC),  // US spring forward (02:00 EST)
	time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), // EU spring forward
	time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC), // US fall back
	time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC),
	time.Date(2038, 1, 19, 3, 14, 7, 0, time.UTC),   // int32 time_t last second
	time.Date(2100, 2, 28, 23, 59, 59, 0, time.UTC), // 2100 is not a leap year
	time.Date(2106, 2, 7, 6, 28, 15, 0, time.UTC),   // uint32 time_t last second
	time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
	time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	time.Date(292277026596, 12, 4, 15, 30, 7, 0, time.UTC), // near Time's max
}

var fakeClockTTLs = []time.Duration{
	time.Second, 59 * time.Second, 60 * time.Second, time.Hour, 24 * time.Hour,
	30 * 24 * time.Hour, 365 * 24 * time.Hour, 100 * 365 * 24 * time.Hour,
}

// ---- oracle driver (pure; used on the real core AND on planted mutants) ----

type fkcCred interface {
	// Check reports whether the credential is accepted at the clock's current value.
	Check() bool
	// Expiry is the credential's CURRENT expiry (a lease renewal moves it).
	Expiry() time.Time
	// Strict reports whether "not past expiry and not previously observed
	// expired => accepted" (O3) can be asserted (false for leases).
	Strict() bool
	// RollbackTolerance is how far a backward step is allowed to go without
	// the anti-rollback guard engaging (0 for session/PAT; 30s for leases).
	RollbackTolerance() time.Duration
}

type fkcStep struct {
	kind  uint8
	delta int64
}

// fkcResolve turns a step into the next clock value.
func fkcResolve(st fkcStep, cur, issue, expiry time.Time) time.Time {
	small := time.Duration(st.delta%int64(2*time.Hour)) - time.Hour
	switch st.kind % 9 {
	case 0:
		return expiry.Add(small)
	case 1:
		return expiry.Add(-1)
	case 2:
		return expiry
	case 3:
		return expiry.Add(1)
	case 4:
		return fakeClockInstants[int(uint64(st.delta)%uint64(len(fakeClockInstants)))]
	case 5:
		return cur.Add(clampNanos(st.delta))
	case 6:
		return time.Time{}
	case 7:
		return expiry.Add(small).Round(0).In(time.FixedZone("x", int(st.delta%86400)))
	default:
		return issue.Add(small)
	}
}

// fkcRun executes the clock program and returns the O1-O3 violations.
func fkcRun(c fkcCred, set func(time.Time), issue, _ time.Time, steps []fkcStep) []string {
	var v []string
	sticky := false
	maxSeen := issue
	cur := issue
	for i, st := range steps {
		expiry := c.Expiry()
		T := fkcResolve(st, cur, issue, expiry)
		cur = T
		set(T)
		acc := c.Check()
		past := T.After(expiry) // judged against the expiry in force BEFORE this check
		// An accepted check at T <= expiry is fine; a lease may now have moved its expiry.
		regress := maxSeen.Sub(T)
		if T.After(maxSeen) {
			maxSeen = T
		}
		observedExpired := sticky
		if c.RollbackTolerance() > 0 {
			// lease: guard only engages for regressions beyond the tolerance
			observedExpired = sticky && regress > c.RollbackTolerance()+time.Second
		}
		if acc && past {
			v = append(v, fmt.Sprintf("step %d: O1 accepted at %v which is after expiry %v", i, T, expiry))
		}
		if acc && observedExpired {
			v = append(v, fmt.Sprintf("step %d: O2 accepted at %v after having been observed expired (max seen %v, expiry %v)", i, T, maxSeen, expiry))
		}
		if !acc && c.Strict() && !past && !sticky && !T.Before(issue) {
			v = append(v, fmt.Sprintf("step %d: O3 refused at %v which is not past expiry %v", i, T, expiry))
		}
		if past {
			sticky = true
		}
	}
	return v
}

// ---- real core world ---------------------------------------------------------

type fkcWorld struct {
	core   *KeyorixCore
	clock  *clockBox
	userID uint
	boot   *BootstrapResult
}

func buildFkcWorld(t testing.TB, start time.Time) *fkcWorld {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n.InitializeForTesting: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	clock := &clockBox{t: start}
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetClockForTesting(clock.now)
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	if err := enc.Initialize("fake-clock-fuzz-passphrase"); err != nil {
		t.Fatalf("encryption.Initialize: %v", err)
	}
	c.SetAuthEncryptor(enc)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	c.SetBootstrapToken("fc-bootstrap")
	boot, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "fcadmin", Email: "fcadmin@example.com", Password: "FakeClockAdmin123!", Token: "fc-bootstrap"})
	if err != nil {
		t.Fatalf("BootstrapSystem at %v: %v", start, err)
	}
	return &fkcWorld{core: c, clock: clock, userID: boot.User.ID, boot: boot}
}

type fkcSession struct {
	w      *fkcWorld
	token  string
	expiry time.Time
}

func (s *fkcSession) Expiry() time.Time { return s.expiry }

func (s *fkcSession) Check() bool {
	_, _, err := s.w.core.ValidateSessionToken(context.Background(), s.token)
	return err == nil
}
func (s *fkcSession) Strict() bool                     { return true }
func (s *fkcSession) RollbackTolerance() time.Duration { return 0 }

type fkcPAT struct {
	w      *fkcWorld
	token  string
	expiry time.Time
}

func (p *fkcPAT) Expiry() time.Time { return p.expiry }

func (p *fkcPAT) Check() bool {
	_, _, _, _, err := p.w.core.ValidatePATToken(context.Background(), p.token)
	return err == nil
}
func (p *fkcPAT) Strict() bool                     { return true }
func (p *fkcPAT) RollbackTolerance() time.Duration { return 0 }

type fkcLease struct {
	w      *fkcWorld
	id     string
	ttl    int
	expiry time.Time
}

func (l *fkcLease) Expiry() time.Time { return l.expiry }

func (l *fkcLease) Check() bool {
	exp, err := l.w.core.RenewLease(context.Background(), l.id, l.ttl, l.w.userID)
	if err == nil {
		l.expiry = exp
	}
	return err == nil
}
func (l *fkcLease) Strict() bool                     { return false }
func (l *fkcLease) RollbackTolerance() time.Duration { return 30 * time.Second }

// fkcO4Violation is the O4 mint check, shared by the real mint paths and planted
// mutant M4: an expiry that precedes its own issue instant has wrapped around.
func fkcO4Violation(kind string, issue, expiry time.Time) string {
	if expiry.Before(issue) {
		return fmt.Sprintf("O4: %s minted at %v has expiry %v BEFORE its issue instant (wrap-around)", kind, issue, expiry)
	}
	return ""
}

// fkcMint mints the selected credential at the world's current (start) clock.
// ok=false with a reason means a CLEAN refusal to mint at this instant (O4 pass).
func fkcMint(t testing.TB, w *fkcWorld, sel int, ttl time.Duration) (cred fkcCred, issue, expiry time.Time, ok bool, note string) {
	ctx := context.Background()
	issue = w.clock.t
	if issue.Year() < 1 || issue.Year() >= 9999 {
		// KNOWN-LIMIT domain, pinned by TestKnownLimit_* below. The production SQLite
		// dialect cannot scan a stored year >= 10000 back, and the table's only instant
		// in year 9999 is its last second, so every TTL from it lands in year 10000.
		// The auth watermark starts at the zero time (year 1), so a clock in year <= 0
		// reads as already past every expiry. Both fail CLOSED (credential refused early).
		return nil, issue, expiry, false, "instant outside the minted year range 1..9998"
	}
	switch sel % 3 {
	case 0:
		s, _, err := w.core.Login(ctx, &LoginRequest{Username: "fcadmin", Password: "FakeClockAdmin123!"})
		if err != nil {
			return nil, issue, expiry, false, "login refused: " + err.Error()
		}
		if s.ExpiresAt == nil {
			return nil, issue, expiry, false, "session without ExpiresAt"
		}
		expiry = *s.ExpiresAt
		if v := fkcO4Violation("session", issue, expiry); v != "" {
			t.Error(v)
			return nil, issue, expiry, false, "wrapped"
		}
		return &fkcSession{w: w, token: s.SessionToken, expiry: expiry}, issue, expiry, true, ""
	case 1:
		exp := issue.Add(ttl)
		r, err := w.core.CreateOwnPAT(ctx, w.userID, "fc-pat", &exp, nil, 0, 0, nil)
		if err != nil {
			return nil, issue, expiry, false, "PAT refused: " + err.Error()
		}
		return &fkcPAT{w: w, token: r.PlainToken, expiry: exp}, issue, exp, true, ""
	default:
		cfg, err := w.core.CreateDynamicSecretConfig(ctx, &CreateDynamicSecretConfigRequest{
			Name: "fc-cfg", ProjectID: w.boot.Project.ID, EnvironmentID: w.boot.Environments[0].ID,
			BackendType: "postgres", AdminDSN: "postgres://admin:s3cr3t@db.internal:5432/app",
			CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
			DefaultTTLSeconds: int(ttl.Seconds()), CreatedBy: "fcadmin", ActorID: w.userID})
		if err != nil {
			return nil, issue, expiry, false, "lease config refused: " + err.Error()
		}
		secs := max(int(ttl.Seconds()), 1)
		l, err := w.core.IssueLease(ctx, cfg.ID, secs, w.userID)
		if err != nil {
			return nil, issue, expiry, false, "lease refused: " + err.Error()
		}
		if v := fkcO4Violation("lease", issue, l.ExpiresAt); v != "" {
			t.Error(v)
			return nil, issue, l.ExpiresAt, false, "wrapped"
		}
		return &fkcLease{w: w, id: l.LeaseID, ttl: secs, expiry: l.ExpiresAt}, issue, l.ExpiresAt, true, ""
	}
}

func fkcDecode(data []byte) (start time.Time, credSel int, ttl time.Duration, steps []fkcStep, ok bool) {
	if len(data) < 12 {
		return start, 0, 0, nil, false
	}
	base := fakeClockInstants[int(data[0])%len(fakeClockInstants)]
	var off int64
	for i := range 4 {
		off = off<<8 | int64(data[1+i])
	}
	start = base.Add(time.Duration(off%7200) * time.Second)
	credSel = int(data[5]) % 3
	ttl = fakeClockTTLs[int(data[6])%len(fakeClockTTLs)]
	n := 1 + int(data[7])%6
	rest := data[8:]
	for i := 0; i < n && len(rest) >= 9; i++ {
		var d int64
		for j := range 8 {
			d = d<<8 | int64(rest[1+j])
		}
		steps = append(steps, fkcStep{kind: rest[0], delta: d})
		rest = rest[9:]
	}
	return start, credSel, ttl, steps, len(steps) > 0
}

// fkcCheckOne mints at start and runs the program; returns violations.
func fkcCheckOne(t testing.TB, start time.Time, credSel int, ttl time.Duration, steps []fkcStep) []string {
	w := buildFkcWorld(t, start)
	cred, issue, expiry, ok, _ := fkcMint(t, w, credSel, ttl)
	if !ok {
		return nil
	}
	return fkcRun(cred, func(x time.Time) { w.clock.t = x }, issue, expiry, steps)
}

// FuzzFakeClockExtremes: see FAKE_CLOCK_FUZZ.md.
func FuzzFakeClockExtremes(f *testing.F) {
	enc := func(base, cred, ttl, n byte, steps ...[9]byte) []byte {
		b := []byte{base, 0, 0, 0, 0, cred, ttl, n}
		for _, s := range steps {
			b = append(b, s[:]...)
		}
		return b
	}
	f.Add(enc(10, 0, 1, 1, [9]byte{3}))                                     // session, expiry+1ns
	f.Add(enc(10, 1, 2, 1, [9]byte{2}))                                     // PAT at exactly expiry
	f.Add(enc(13, 1, 0, 2, [9]byte{3}, [9]byte{0}))                         // PAT minted 2106, then back
	f.Add(enc(0, 1, 3, 1, [9]byte{0}))                                      // PAT minted at the zero time
	f.Add(enc(12, 1, 7, 2, [9]byte{3}, [9]byte{8}))                         // 2100, 100y TTL, jump back to issue
	f.Add(enc(0, 2, 5, 1, [9]byte{3}))                                      // lease minted at the zero time
	f.Add(enc(11, 0, 4, 2, [9]byte{4, 0, 0, 0, 0, 0, 0, 0, 6}, [9]byte{6})) // minted 2038, special instant, zero time
	f.Add(enc(7, 1, 3, 3, [9]byte{2}, [9]byte{3}, [9]byte{1}))              // DST edge, expire, back by 1ns
	f.Fuzz(func(t *testing.T, data []byte) {
		start, credSel, ttl, steps, ok := fkcDecode(data)
		if !ok {
			t.Skip("input too short")
		}
		if v := fkcCheckOne(t, start, credSel, ttl, steps); len(v) > 0 {
			t.Errorf("start=%v cred=%d ttl=%v steps=%v:\n  %s", start, credSel%3, ttl, steps, strings.Join(v, "\n  "))
		}
	})
}

// TestFakeClockExtremes_Cross is the deterministic enumeration: every special
// start instant x TTL x each step kind, per credential type. A default run uses
// three TTLs to bound its cost; KEYORIX_FAKE_CLOCK_FULL_CROSS=1 runs all of them,
// which is the R2 campaign. Each program's first step is R2's single step, and the
// two steps after it (past expiry, then back to issue) only add checks.
func TestFakeClockExtremes_Cross(t *testing.T) {
	if testing.Short() {
		t.Skip("enumeration builds one core per case; skipped with -short")
	}
	ttls := []time.Duration{time.Second, time.Hour, 100 * 365 * 24 * time.Hour}
	if os.Getenv("KEYORIX_FAKE_CLOCK_FULL_CROSS") != "" {
		ttls = fakeClockTTLs
	}
	programs := 0
	defer func() { t.Logf("%d TTLs, %d programs ran", len(ttls), programs) }()
	for si, start := range fakeClockInstants {
		for cred := range 3 {
			for _, ttl := range ttls {
				for kind := range uint8(9) {
					// A fresh world per program: a credential observed expired (or a lease
					// renewed) in one program must not leak into the next.
					w := buildFkcWorld(t, start)
					c, issue, expiry, ok, _ := fkcMint(t, w, cred, ttl)
					if !ok {
						break
					}
					programs++
					steps := []fkcStep{{kind: kind, delta: int64(si)}, {kind: 3}, {kind: 8, delta: 0}}
					if v := fkcRun(c, func(x time.Time) { w.clock.t = x }, issue, expiry, steps); len(v) > 0 {
						t.Errorf("start#%d=%v cred=%d ttl=%v kind=%d: %s", si, start, cred, ttl, kind, strings.Join(v, "; "))
					}
				}
			}
		}
	}
}

// ---- planted mutants (R1) ----------------------------------------------------

// fkcModel is a correct reference credential with a watermark.
type fkcModel struct {
	now       *time.Time
	expiry    time.Time
	watermark time.Time
	mut       string
}

func (m *fkcModel) Expiry() time.Time { return m.expiry }

func (m *fkcModel) Check() bool {
	now := *m.now
	if m.mut != "M3" { // M3: no anti-rollback watermark
		if now.Before(m.watermark) {
			now = m.watermark
		}
		m.watermark = now
	}
	switch m.mut {
	case "M1": // accepts 1ns past expiry (acceptance at exactly expiry is correct)
		return !now.After(m.expiry.Add(1))
	case "M2": // rejects 1ns before expiry
		return now.Before(m.expiry.Add(-1))
	}
	return !now.After(m.expiry)
}
func (m *fkcModel) Strict() bool                     { return true }
func (m *fkcModel) RollbackTolerance() time.Duration { return 0 }

func TestFakeClockOracles_PlantedMutants(t *testing.T) {
	issue := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	expiry := issue.Add(time.Minute)
	scenarios := [][]fkcStep{
		{{kind: 2}},                      // exactly expiry
		{{kind: 1}},                      // expiry-1ns
		{{kind: 3}, {kind: 8}},           // past, then back to issue
		{{kind: 3}, {kind: 6}},           // past, then zero time
		{{kind: 0, delta: 1}, {kind: 1}}, // wobble around expiry
	}
	run := func(mut string) (viol int) {
		for _, sc := range scenarios {
			now := issue
			m := &fkcModel{now: &now, expiry: expiry, mut: mut}
			viol += len(fkcRun(m, func(x time.Time) { now = x }, issue, expiry, sc))
		}
		return viol
	}
	if n := run(""); n != 0 {
		t.Fatalf("CONTROL: the correct reference model reports %d violations: oracle driver unsound", n)
	}
	for _, mut := range []string{"M1", "M2", "M3"} {
		if run(mut) == 0 {
			t.Errorf("planted mutant %s was NOT detected by the oracle driver", mut)
		}
	}
	// M4: a mint that computes the expiry in 32-bit seconds wraps the 100-year TTL to
	// the past. It goes through fkcO4Violation, the check the real mint paths use.
	mintViolations := func(mut string) (viol int) {
		for _, ttl := range fakeClockTTLs {
			mintedExpiry := issue.Add(ttl)
			if mut == "M4" {
				mintedExpiry = issue.Add(time.Duration(int32(ttl/time.Second)) * time.Second) // #nosec G115 -- the overflow is the planted defect
			}
			if fkcO4Violation("model credential", issue, mintedExpiry) != "" {
				viol++
			}
		}
		return viol
	}
	if n := mintViolations(""); n != 0 {
		t.Fatalf("CONTROL: the correct reference mint reports %d O4 violations: oracle unsound", n)
	}
	if mintViolations("M4") == 0 {
		t.Errorf("planted mutant M4 was NOT detected by the O4 check")
	}
}

// ---- schedule across real zones (O5/O6) -----------------------------------------

var fkcZones = []string{
	"UTC", "America/New_York", "Europe/Madrid", "Australia/Lord_Howe", "Pacific/Chatham",
	"America/Sao_Paulo", "Asia/Kolkata", "Pacific/Apia", "Africa/Casablanca", "Europe/Dublin",
	"Asia/Tehran", "America/St_Johns", "Asia/Kathmandu", "Pacific/Kiritimati",
}

var fkcScheduleInstants = []time.Time{
	time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC),
	time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC),
	time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC), time.Date(2026, 4, 4, 15, 0, 0, 0, time.UTC),
	time.Date(2011, 12, 30, 10, 0, 0, 0, time.UTC), // Apia skipped 2011-12-30
	time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC), time.Date(2100, 2, 28, 23, 0, 0, 0, time.UTC),
	time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), {}, time.Unix(0, 0).UTC(),
}

// fkcIndependentVerdict recomputes allow/deny from the UTC instant and the
// zone's offset at that instant, without t.In(loc).Hour()/Weekday().
func fkcIndependentVerdict(s *models.SecretAccessSchedule, t time.Time, loc *time.Location) bool {
	_, off := t.In(loc).Zone()
	wall := t.UTC().Add(time.Duration(off) * time.Second)
	if s.AllowedDays != "*" {
		iso := int(wall.Weekday())
		if iso == 0 {
			iso = 7
		}
		ok := false
		for p := range strings.SplitSeq(s.AllowedDays, ",") {
			if d, _ := strconv.Atoi(strings.TrimSpace(p)); d == iso {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	h := wall.Hour()
	return h >= s.StartHour && h < s.EndHour
}

func FuzzEnforceScheduleDST(f *testing.F) {
	f.Add(uint8(1), uint8(0), int64(0), uint8(0), uint8(24), uint8(0))
	f.Add(uint8(1), uint8(0), int64(3600), uint8(2), uint8(3), uint8(1)) // NY spring-forward gap hour
	f.Add(uint8(3), uint8(1), int64(1800), uint8(1), uint8(2), uint8(2)) // Lord Howe 30-min DST
	f.Add(uint8(7), uint8(6), int64(0), uint8(0), uint8(24), uint8(0))   // Apia skipped day
	f.Fuzz(func(t *testing.T, zoneSel, instSel uint8, offSec int64, startH, endH, daysSel uint8) {
		zone := fkcZones[int(zoneSel)%len(fkcZones)]
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Skipf("zone %s unavailable: %v", zone, err)
		}
		days := []string{"*", "1,2,3,4,5", "6,7", "1", "7", "0,8,abc"}[int(daysSel)%6]
		sh := int(startH) % 24
		eh := sh + 1 + int(endH)%(24-sh)
		s := &models.SecretAccessSchedule{AllowedDays: days, StartHour: sh, EndHour: eh, Timezone: zone}
		inst := fkcScheduleInstants[int(instSel)%len(fkcScheduleInstants)].Add(time.Duration(offSec%(48*3600)) * time.Second)

		got := enforceSchedule(s, inst) == nil
		want := fkcIndependentVerdict(s, inst, loc)
		if got != want {
			t.Errorf("O6: zone=%s days=%q [%d,%d) at %v: enforceSchedule allowed=%v, independent computation says %v", zone, days, sh, eh, inst, got, want)
		}
		for _, rep := range []time.Time{inst.UTC(), inst.Round(0), inst.In(time.FixedZone("z", 3*3600+1800)), inst.In(loc)} {
			if (enforceSchedule(s, rep) == nil) != got {
				t.Errorf("O5: verdict depends on representation of %v (%v)", inst, rep.Location())
			}
		}
	})
}

// TestScheduleMutantLocalHour (R1/M5): the independent oracle must catch an
// implementation that reads a host-local hour instead of the zone's. The mutant's
// host zone is explicit, so the result does not depend on the machine's TZ.
func TestScheduleMutantLocalHour(t *testing.T) {
	s := &models.SecretAccessSchedule{AllowedDays: "*", StartHour: 9, EndHour: 17, Timezone: "Asia/Kolkata"}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	disagreements := func(host *time.Location) (n int) {
		for h := range 24 {
			inst := time.Date(2026, 6, 12, h, 0, 0, 0, time.UTC)
			hour := inst.In(host).Hour()
			if (hour >= s.StartHour && hour < s.EndHour) != fkcIndependentVerdict(s, inst, loc) {
				n++
			}
		}
		return n
	}
	if disagreements(time.FixedZone("mutant-host", -5*3600)) == 0 {
		t.Errorf("M5 not detected: reading the hour in a host zone agrees with the oracle")
	}
	if n := disagreements(loc); n != 0 {
		t.Errorf("CONTROL: reading the hour in the schedule's own zone disagrees with the oracle %d times", n)
	}
	for h := range 24 { // control: real implementation agrees everywhere
		inst := time.Date(2026, 6, 12, h, 30, 0, 0, time.UTC)
		if (enforceSchedule(s, inst) == nil) != fkcIndependentVerdict(s, inst, loc) {
			t.Errorf("CONTROL: enforceSchedule disagrees with the independent computation at %v", inst)
		}
	}
}

// TestKnownLimit_SQLiteYear10000IsNotReadBack pins today's behaviour (R3
// classification EXPECTED, fail-closed): an expiry beyond year 9999 is stored by
// SQLite without error but never read back as the stored instant (the production
// dialect fails the scan, the other driver returned the zero time). Not
// reachable through the API (RFC 3339 input stops at year 9999); reachable only by
// clock arithmetic past 9999. If storage ever starts rejecting or preserving
// such values, this test should change with it.
func TestKnownLimit_SQLiteYear10000IsNotReadBack(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(models.AllTestModels()...); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		in    time.Time
		exact bool
	}{
		{time.Date(9999, 12, 31, 23, 59, 59, 5, time.UTC), true},
		{time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC), true},
		{time.Date(10000, 1, 2, 1, 27, 11, 999999999, time.UTC), false},
	} {
		in := c.in
		n := &models.SecretNode{Name: "kl", Expiration: &in}
		if err := db.Create(n).Error; err != nil {
			t.Fatalf("create %v: %v", in, err)
		}
		var out models.SecretNode
		err := db.First(&out, n.ID).Error
		if !c.exact {
			// On the production dialect (modernc) the stored year-10000 text cannot
			// be scanned back into a time at all; the other SQLite driver read it
			// back as the zero time. Either way the value is never read back as
			// the stored instant.
			if err == nil && out.Expiration != nil && !out.Expiration.IsZero() {
				t.Errorf("%v: documented known-limit changed (now reads back %v); update this test", in, *out.Expiration)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if out.Expiration == nil {
			t.Fatalf("%v: expiration vanished", in)
		}
		if !out.Expiration.Equal(in) {
			t.Errorf("%v did not round-trip: got %v", in, *out.Expiration)
		}
	}
}

// TestKnownLimit_Year0ClockFailsClosed pins that a session minted with the clock in
// year 0 mints, then is refused at validation (the auth watermark starts at year 1)
// rather than accepted. It calls Login directly: fkcMint refuses year 0 before
// reaching the core, so going through it would prove nothing about Keyorix.
func TestKnownLimit_Year0ClockFailsClosed(t *testing.T) {
	w := buildFkcWorld(t, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	s, _, err := w.core.Login(ctx, &LoginRequest{Username: "fcadmin", Password: "FakeClockAdmin123!"})
	if err != nil {
		t.Fatalf("Login at year 0 no longer mints; the documented known limit changed, update this test and FAKE_CLOCK_FUZZ.md: %v", err)
	}
	if s.ExpiresAt == nil || s.ExpiresAt.Year() != 0 {
		t.Fatalf("session minted at year 0 has expiry %v; the documented known limit changed", s.ExpiresAt)
	}
	if _, _, err := w.core.ValidateSessionToken(ctx, s.SessionToken); err == nil {
		t.Errorf("session minted at year 0 is accepted; the documented behaviour is fail-closed refusal, review the watermark")
	}
}

// TestSeamGap_UnexpiredSecretIgnoresInjectedClock pins a SEAM-GAP (R3) and asserts
// today's behaviour: unexpiredSecret, behind GetSecret, reads time.Now() directly, so
// the injected clock cannot decide a secret's expiry there. The smallest change (R4)
// is to pass c.now() into it. This test then goes red and should be replaced by one
// asserting that the injected clock decides. The fixed dates keep it independent of
// the real date until the year 9000.
func TestSeamGap_UnexpiredSecretIgnoresInjectedClock(t *testing.T) {
	w := buildFkcWorld(t, time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC))
	ctx := context.Background()
	for i, c := range []struct {
		expiration, injected time.Time
		wantExpired          bool
	}{
		{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), true},  // real clock past expiry, injected before it
		{time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9001, 1, 1, 0, 0, 0, 0, time.UTC), false}, // real clock before expiry, injected past it
	} {
		expiration := c.expiration
		s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
			Name: fmt.Sprintf("fc-seam-%d", i), ProjectID: w.boot.Project.ID, EnvironmentID: w.boot.Environments[0].ID,
			Type: "password", OwnerID: w.userID, IsSecret: true, Expiration: &expiration,
		})
		if err != nil {
			t.Fatal(err)
		}
		w.clock.t = c.injected
		_, err = w.core.GetSecret(ctx, s.ID)
		if expired := errors.Is(err, ErrSecretExpired); expired != c.wantExpired {
			t.Errorf("expiration %v, injected clock %v: expired=%v (err %v), want %v; if GetSecret now uses the injected clock the seam gap is closed, replace this test", c.expiration, c.injected, expired, err, c.wantExpired)
		}
	}
}

// TestSeamGap_SecretScheduleIgnoresInjectedClock pins the same SEAM-GAP for
// checkSecretAccessScheduleWith, which also reads time.Now() directly. Each window is
// one UTC hour, and the injected clock is 12 hours from the real one, so enforceSchedule
// at the injected instant gives the opposite verdict from the one asserted. The smallest
// change (R4) is to pass c.now() in from checkSecretAccessSchedule and the versions.go
// callers. This test then goes red and should be replaced by one asserting that the
// injected clock decides.
func TestSeamGap_SecretScheduleIgnoresInjectedClock(t *testing.T) {
	w := buildFkcWorld(t, time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC))
	ctx := context.Background()
	s, err := w.core.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "fc-seam-schedule", ProjectID: w.boot.Project.ID, EnvironmentID: w.boot.Environments[0].ID,
		Type: "password", OwnerID: w.userID, IsSecret: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, realInWindow := range []bool{true, false} {
		for attempt := 0; ; attempt++ {
			wall := time.Now().UTC()
			injected := wall.Add(12 * time.Hour)
			hour := injected.Hour()
			if realInWindow {
				hour = wall.Hour()
			}
			sched := &models.SecretAccessSchedule{SecretNodeID: s.ID, AllowedDays: "*", StartHour: hour, EndHour: hour + 1, Timezone: "UTC"}
			if err := w.core.storage.SetSecretAccessSchedule(ctx, sched); err != nil {
				t.Fatal(err)
			}
			w.clock.t = injected
			err := w.core.checkSecretAccessSchedule(ctx, s.ID)
			if time.Now().UTC().Hour() != wall.Hour() && attempt == 0 {
				continue // the real clock crossed an hour mid-check; the window no longer applies
			}
			if allowed := err == nil; allowed != realInWindow {
				t.Errorf("real clock in window=%v: allowed=%v (err %v); if the check now uses the injected clock the seam gap is closed, replace this test", realInWindow, allowed, err)
			}
			if allowedAtInjected := enforceSchedule(sched, injected) == nil; allowedAtInjected == realInWindow {
				t.Errorf("real clock in window=%v: enforceSchedule at the injected instant allowed=%v, so this case cannot tell the two clocks apart", realInWindow, allowedAtInjected)
			}
			break
		}
	}
}
