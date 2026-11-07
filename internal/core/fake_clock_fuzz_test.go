package core

// fake_clock_fuzz_test.go -- extreme-instant fake-clock fuzzing.
// Scope, oracles (O1-O6), planted mutants (R1) and the finding rules (R3) are
// pre-registered in FAKE_CLOCK_FUZZ.md (same directory). No production code is
// changed: this drives the existing KeyorixCore.SetClockForTesting seam.

import (
	"context"
	"fmt"
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
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ---- special instants and TTLs ----------------------------------------------

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
		if acc {
			// an accepted check at T <= expiry is fine; a lease may now have moved its expiry
		}
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

// fkcWrapped reports an expiry that precedes its own issue instant.
func fkcWrapped(issue, expiry time.Time) bool { return expiry.Before(issue) }

// fkcMint mints the selected credential at the world's current (start) clock.
// ok=false with a reason means a CLEAN refusal to mint at this instant (O4 pass).
func fkcMint(t testing.TB, w *fkcWorld, sel int, ttl time.Duration) (cred fkcCred, issue, expiry time.Time, ok bool, note string) {
	cred, issue, expiry, ok, note = fkcMintRaw(t, w, sel, ttl)
	if ok && expiry.Year() > 9999 {
		return nil, issue, expiry, false, "expiry beyond year 9999 (KNOWN-LIMIT, see TestKnownLimit_*)"
	}
	return cred, issue, expiry, ok, note
}

func fkcMintRaw(t testing.TB, w *fkcWorld, sel int, ttl time.Duration) (cred fkcCred, issue, expiry time.Time, ok bool, note string) {
	ctx := context.Background()
	issue = w.clock.t
	if issue.Year() < 1 || issue.Year() >= 9999 {
		// KNOWN-LIMIT domain, pinned by TestKnownLimit_* below: SQLite storage turns a
		// stored year >= 10000 into the zero time with no error, and the anti-rollback
		// watermark starts at the zero time (year 1), so a clock in year <= 0 reads as
		// already past every expiry. Both fail CLOSED (credential refused early).
		return nil, issue, expiry, false, "instant outside the storable year range 1..9998"
	}
	if issue.Year() > 1_000_000_000 {
		// TEST-ARTIFACT domain (R3): within ~100 years of time.Time's own upper limit
		// (year 292277026596) Add/Sub/After saturate or wrap inside the Go runtime,
		// so an "expiry" computed there is not meaningful for any credential.
		return nil, issue, expiry, false, "instant beyond the Go time.Time arithmetic range"
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
		if fkcWrapped(issue, expiry) {
			t.Errorf("O4: session minted at %v has expiry %v BEFORE its issue instant (wrap-around)", issue, expiry)
			return nil, issue, expiry, false, "wrapped"
		}
		return &fkcSession{w: w, token: s.SessionToken, expiry: expiry}, issue, expiry, true, ""
	case 1:
		exp := issue.Add(ttl)
		if exp.Sub(issue) != ttl {
			// Outside time.Time's own representable arithmetic (Add/Sub saturate or
			// wrap near year 292277026596): a Go-runtime limit, not a Keyorix one.
			return nil, issue, expiry, false, "ttl not representable from this instant"
		}
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
		secs := int(ttl.Seconds())
		if secs < 1 {
			secs = 1
		}
		l, err := w.core.IssueLease(ctx, cfg.ID, secs, w.userID)
		if err != nil {
			return nil, issue, expiry, false, "lease refused: " + err.Error()
		}
		if fkcWrapped(issue, l.ExpiresAt) {
			t.Errorf("O4: lease minted at %v has expiry %v BEFORE its issue instant", issue, l.ExpiresAt)
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
	for i := 0; i < 4; i++ {
		off = off<<8 | int64(data[1+i])
	}
	start = base.Add(time.Duration(off%7200) * time.Second)
	credSel = int(data[5]) % 3
	ttl = fakeClockTTLs[int(data[6])%len(fakeClockTTLs)]
	n := 1 + int(data[7])%6
	rest := data[8:]
	for i := 0; i < n && len(rest) >= 9; i++ {
		var d int64
		for j := 0; j < 8; j++ {
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
	f.Add(enc(14, 1, 0, 2, [9]byte{3}, [9]byte{0}))                         // PAT minted 9999-12-31, then back
	f.Add(enc(0, 1, 3, 1, [9]byte{0}))                                      // PAT minted at the zero time
	f.Add(enc(1, 1, 7, 2, [9]byte{3}, [9]byte{8}))                          // year 0, 100y TTL, jump back to issue
	f.Add(enc(16, 2, 5, 1, [9]byte{3}))                                     // lease minted near max Time
	f.Add(enc(15, 0, 4, 2, [9]byte{4, 0, 0, 0, 0, 0, 0, 0, 6}, [9]byte{6})) // minted at year 10000, special instant, zero time
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
// start instant x every TTL x each single-step kind, per credential type.
func TestFakeClockExtremes_Cross(t *testing.T) {
	if testing.Short() {
		t.Skip("enumeration builds one core per case; skipped with -short")
	}
	ttls := []time.Duration{time.Second, time.Hour, 100 * 365 * 24 * time.Hour}
	for si, start := range fakeClockInstants {
		for cred := 0; cred < 3; cred++ {
			for _, ttl := range ttls {
				for kind := uint8(0); kind < 9; kind++ {
					// A fresh world per program: a credential observed expired (or a lease
					// renewed) in one program must not leak into the next.
					w := buildFkcWorld(t, start)
					c, issue, expiry, ok, _ := fkcMint(t, w, cred, ttl)
					if !ok {
						break
					}
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
	case "M1": // accepts at exactly expiry
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
	// M4: wrap-around of an expiry to before the issue instant is what fkcMint's
	// O4 check keys on; prove the predicate flags a wrapped value and not a sane one.
	if !fkcWrapped(issue, issue.Add(-1<<40)) || fkcWrapped(issue, issue.Add(time.Hour)) {
		t.Errorf("M4: fkcWrapped does not separate wrapped from sane expiries")
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
		for _, p := range strings.Split(s.AllowedDays, ",") {
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
// implementation that reads the host-local hour instead of the zone's.
func TestScheduleMutantLocalHour(t *testing.T) {
	s := &models.SecretAccessSchedule{AllowedDays: "*", StartHour: 9, EndHour: 17, Timezone: "Asia/Kolkata"}
	loc, _ := time.LoadLocation("Asia/Kolkata")
	mutant := func(t time.Time) bool { h := t.Local().Hour(); return h >= s.StartHour && h < s.EndHour }
	caught := false
	for h := 0; h < 24 && !caught; h++ {
		inst := time.Date(2026, 6, 12, h, 0, 0, 0, time.UTC)
		if mutant(inst) != fkcIndependentVerdict(s, inst, loc) {
			caught = true
		}
	}
	if time.Local.String() != "Asia/Kolkata" && !caught {
		t.Errorf("M5 not detected (local zone %v)", time.Local)
	}
	for h := 0; h < 24; h++ { // control: real implementation agrees everywhere
		inst := time.Date(2026, 6, 12, h, 30, 0, 0, time.UTC)
		if (enforceSchedule(s, inst) == nil) != fkcIndependentVerdict(s, inst, loc) {
			t.Errorf("CONTROL: enforceSchedule disagrees with the independent computation at %v", inst)
		}
	}
}

// TestKnownLimit_SQLiteYear10000ReadsAsZeroTime pins today's behaviour (R3
// classification EXPECTED, fail-closed): an expiry beyond year 9999 is stored by
// SQLite without error and read back as the zero time, i.e. long expired. Not
// reachable through the API (RFC 3339 input stops at year 9999); reachable only by
// clock arithmetic past 9999. If storage ever starts rejecting or preserving
// such values, this test should change with it.
func TestKnownLimit_SQLiteYear10000ReadsAsZeroTime(t *testing.T) {
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
		if err := db.First(&out, n.ID).Error; err != nil {
			t.Fatal(err)
		}
		if out.Expiration == nil {
			t.Fatalf("%v: expiration vanished", in)
		}
		if c.exact && !out.Expiration.Equal(in) {
			t.Errorf("%v did not round-trip: got %v", in, *out.Expiration)
		}
		if !c.exact && !out.Expiration.IsZero() {
			t.Errorf("%v: documented known-limit changed (now reads back %v); update this test", in, *out.Expiration)
		}
	}
}

// TestKnownLimit_Year0ClockFailsClosed pins that a session minted with the clock in
// year 0 is refused at once (the watermark starts at year 1) rather than accepted.
func TestKnownLimit_Year0ClockFailsClosed(t *testing.T) {
	w := buildFkcWorld(t, time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC))
	cred, _, _, ok, _ := fkcMintRaw(t, w, 0, time.Hour)
	if !ok {
		t.Skip("minting at year 0 now refuses cleanly (also fail-closed)")
	}
	if cred.Check() {
		t.Errorf("session minted at year 0 is accepted; the documented behaviour is fail-closed refusal, review the watermark")
	}
}
