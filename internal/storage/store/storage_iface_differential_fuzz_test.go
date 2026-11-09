package store_test

// FuzzStorageIfaceDifferential drives one byte-generated sequence of storage-interface
// calls against SQLite and PostgreSQL in lockstep, one level down from the core layer:
// the method families FuzzStorageBackendDifferential{,V2} do not drive (environments,
// RBAC reads, group and project membership, sessions, PATs, setup tokens, MFA, system
// metadata, login attempts, notifications and channels, templates, secret ACLs, shares,
// connect-ref grants, audit reads). V1/V2 stay the home of users, projects, groups,
// secrets and versions. FuzzStorageIfaceMetamorphicSQLite runs the same programs with
// no second backend, for the per-backend checks only, and needs no server.
//
// An oracle here is a comparison the storage contract actually promises. What the two
// backends are allowed to differ on is in ifaceIntendedDiffs; every entry says why and
// whether it ends the program. Everything else is a candidate finding.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ifaceAnchorDB, ifaceClonePrefix: every database this harness creates starts w4_, and
// the template pgdsn derives from the anchor's name does too. A shared server's other
// databases are never touched, including by pgdsn's stale-template clean-up, which only
// looks at templates named after the base database.
const (
	ifaceAnchorDB    = "w4_iface_anchor"
	ifaceClonePrefix = "w4_iface"
	ifaceMaxSteps    = 14
)

// ifaceDiffContext is what an intended-difference rule may look at.
type ifaceDiffContext struct {
	label            string
	sqlite, postgres string
	pgCollateC       bool // the PG database orders text bytewise, as SQLite BINARY does
	pgCtypeC         bool // LOWER() on the PG database folds ASCII only
}

// ifaceDiffRule is one row of the intended-difference table. Applies decides from the
// op label and the two rendered results only, so a rule can be read and checked on its
// own. Stops ends the program because the two backends now hold different state.
type ifaceDiffRule struct {
	ID      string
	Why     string
	Stops   bool
	Applies func(c *ifaceDiffContext) bool
}

// ifaceIntendedDiffs lists every difference this harness accepts at compare time. The
// differences it removes by construction instead of by a rule are listed in
// ifaceConstructionDiffs. Written before the oracle.
var ifaceIntendedDiffs = []ifaceDiffRule{
	{
		ID: "FOLD-CTYPE-C",
		Why: "foldedContainsClause documents it: on a C/POSIX ctype database PG LOWER() leaves non-ASCII " +
			"letters unchanged while SQLite's keyorix_fold folds Unicode, so a search whose term or stored " +
			"value differs only by non-ASCII case matches on SQLite alone. Read-only.",
		Applies: func(c *ifaceDiffContext) bool {
			return c.pgCtypeC && strings.Contains(c.label, "foldterm=") && labelHasNonASCIIAfter(c.label, "foldterm=")
		},
	},
	{
		ID: "VARCHAR-LENGTH",
		Why: "gorm size:N is a real VARCHAR(N) on PG and is not enforced by SQLite (login_attempts.reservation_key " +
			"size:64, audit_events.event_type size:100). A too-long value is rejected only by PG. The fuzz " +
			"stream keeps these within the limit; the positive control drives the over-length case.",
		Stops: true,
		Applies: func(c *ifaceDiffContext) bool {
			return strings.Contains(c.label, "overlong=") && c.postgres != c.sqlite
		},
	},
	{
		ID: "TEXT-ORDER-COLLATION",
		Why: "ORDER BY on a text column follows the database collation on PG and bytes on SQLite " +
			"(pg-sqlite-differential.md O-2). On a C-collated database the two agree and the order is compared; " +
			"on any other collation only the multiset is.",
		Applies: func(c *ifaceDiffContext) bool {
			return !c.pgCollateC && strings.Contains(c.label, "textorder=") && sameRows(c.sqlite, c.postgres)
		},
	},
}

// ifaceKnownFindings are real divergences this harness already reported, gated so a
// campaign looks past them. They are not intended differences: each one has a findings
// document, and a fix removes the row. IFACE_DIFF_STRICT=1 turns every gate off for a
// replay. Applies must stay as narrow as the reported shape.
var ifaceKnownFindings = []ifaceDiffRule{
	{
		ID:  "F-AUDIT-RESOURCE-LIKE-CASE",
		Why: "docs/findings/2026-11-09-FINDING-audit-resource-type-like-case.md",
		Applies: func(c *ifaceDiffContext) bool {
			return strings.HasPrefix(c.label, "Audit(mode=2,") && labelAfterHasUpper(c.label, "resource=") && !sameRows(c.sqlite, c.postgres)
		},
	},
}

// labelAfterHasUpper reports an uppercase ASCII letter in the quoted value after marker.
func labelAfterHasUpper(label, marker string) bool {
	_, rest, ok := strings.Cut(label, marker)
	if !ok {
		return false
	}
	v, _, _ := strings.Cut(rest, ",")
	return strings.IndexFunc(v, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0
}

// ifaceConstructionDiffs documents the intended differences this harness removes before
// comparing, so no rule is needed for them. Each entry is enforced by the code named.
var ifaceConstructionDiffs = []struct{ ID, Why, Where string }{
	{"IDS", "Row ids are engine-assigned; sequences skip on failed inserts, rowid does not.", "ifaceHandles: every id is rendered as a per-backend handle"},
	{"ENGINE-TIME", "created_at/updated_at written by the engine differ; only presence is compared.", "fp* renderers"},
	{"SUB-MICROSECOND", "PG timestamptz keeps microseconds, SQLite text keeps nanoseconds.", "ifaceInstant: generated instants are whole microseconds"},
	{"NUL-INVALID-UTF8", "PG rejects NUL and invalid UTF-8 at the driver; the API layer filters them.", "diffValidString on the fuzzer strings"},
	{"NIL-VS-EMPTY-BYTES", "An empty blob reads as nil on SQLite and []byte{} on PG.", "byte fields render as len/hash"},
	{"ORDER-UNSPECIFIED", "A list with no total ORDER BY has an engine-defined order.", "ops compare such lists as sorted sets; LIMIT is exercised only on lists with distinct sort keys"},
	{"BOTH-UNIQUE-INDEXES", "One row violating two unique indexes reports whichever the engine checked first.", "ops violate one index at a time"},
	{"INT64-RANGE", "A uint id above math.MaxInt64 fails differently in each driver.", "handles and boundary ids stay below 2^63"},
}

// ifaceRuleHits counts accepted differences per rule, per process, for the run log.
var ifaceRuleHits = map[string]int{}

func labelHasNonASCIIAfter(label, marker string) bool {
	i := strings.Index(label, marker)
	if i < 0 {
		return false
	}
	return strings.IndexFunc(label[i+len(marker):], func(r rune) bool { return r > unicode.MaxASCII }) >= 0
}

// sameRows reports whether two rendered lists hold the same rows in any order.
func sameRows(a, b string) bool {
	as, bs := strings.Split(a, ifaceRowSep), strings.Split(b, ifaceRowSep)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

const ifaceRowSep = "\x1f"

// ifaceClass collapses an error to the class both backends must agree on. Text is used
// only to reach a class, as isUniqueViolation in production does; it is never compared.
func ifaceClass(err error) string {
	if err == nil {
		return "ok"
	}
	if c := diffClass(err); c != "other" {
		return c
	}
	for _, s := range []struct {
		name string
		err  error
	}{
		{"ProjectNotFound", storage.ErrProjectNotFound}, {"EnvironmentNotFound", storage.ErrEnvironmentNotFound},
		{"RoleNotFound", storage.ErrRoleNotFound}, {"RoleNotAssigned", storage.ErrRoleNotAssigned},
		{"RoleAlreadyAssigned", storage.ErrRoleAlreadyAssigned}, {"DuplicateRolePermission", storage.ErrDuplicateRolePermission},
		{"RolePermissionNotAssigned", storage.ErrRolePermissionNotAssigned}, {"PermissionNotFound", storage.ErrPermissionNotFound},
		{"DuplicateActiveMembership", storage.ErrDuplicateActiveMembership}, {"DuplicateChannelName", storage.ErrDuplicateNotificationChannelName},
		{"DuplicateReminder", storage.ErrDuplicateReminderNotification}, {"ChannelNotFound", storage.ErrNotificationChannelNotFound},
		{"NotificationNotFound", storage.ErrNotificationNotFound}, {"TemplateNotFound", storage.ErrSecretTemplateNotFound},
		{"ACLNotFound", storage.ErrSecretACLNotFound}, {"InvalidACL", storage.ErrInvalidSecretACLRequest},
		{"ShareNotFound", storage.ErrShareNotFound}, {"ShareExpiryNotInFuture", storage.ErrShareExpiryNotInFuture},
		{"SessionNotFound", storage.ErrSessionNotFound}, {"ConnectorBindingNotFound", storage.ErrConnectorBindingNotFound},
		{"MFAChallengeInvalid", storage.ErrMFAChallengeInvalid}, {"MFASecretActivated", storage.ErrMFASecretActivated},
		{"InvalidGroup", storage.ErrInvalidGroupRequest},
	} {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	msg := err.Error()
	switch {
	case ifaceIsConnectionError(msg):
		return ifaceConnClass
	case strings.Contains(msg, "UNIQUE constraint failed"), strings.Contains(msg, "duplicate key value violates unique constraint"):
		return "unique-violation"
	case strings.Contains(msg, "NOT NULL constraint failed"), strings.Contains(msg, "violates not-null constraint"):
		return "notnull-violation"
	case strings.Contains(msg, "value too long for type"):
		return "too-long"
	}
	return "other"
}

// ifaceConnClass is the error class of a lost connection to Postgres. A program that
// hits it is abandoned, not compared: a dropped link is not a backend divergence.
const ifaceConnClass = "infra-connection"

func ifaceIsConnectionError(msg string) bool {
	for _, s := range []string{"connection refused", "broken pipe", "connection reset", "conn closed", "dial error", "unexpected EOF", "bad connection", "timeout expired", "failed to connect"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// ifaceInstant is the only source of caller-supplied times: whole microseconds around a
// fixed origin, in one of three zones so that a bound denoting the same instant but
// written in another zone reaches the backend. Not time.Now: a program must be
// repeatable.
type ifaceInstant struct {
	offset time.Duration
	zone   int
}

var ifaceZones = []*time.Location{time.UTC, time.FixedZone("plus3", 3*3600), time.FixedZone("minus730", -(7*3600 + 30*60))}

var ifaceOffsets = []time.Duration{
	-720 * time.Hour, -48 * time.Hour, -time.Second, -time.Millisecond, -time.Microsecond, 0,
	time.Microsecond, time.Millisecond, time.Second, 48 * time.Hour, 720 * time.Hour,
}

func (i ifaceInstant) time() time.Time {
	return diffAuditBaseTime.Add(i.offset).In(ifaceZones[i.zone%len(ifaceZones)])
}

func fpTime(t *time.Time) string {
	if t == nil {
		return "nil"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// ifaceStringPool extends V2's pool with normalisation twins, quoting and whitespace.
var ifaceStringPool = append(append([]string{}, diffNamePool...),
	"café", "café", "CAFÉ", "ẞ", "ſ", "ı",
	"o'brien", `quo"te`, "semi;colon", "tab\there", "new\nline", "​zw",
	"SELECT", "%", "_", `\`, "system", "SYSTEM", "sys",
	strings.Repeat("z", 2000),
)

// ifaceHandles maps each backend's engine-assigned ids to creation-order handles, so a
// row renders the same on both sides. Fixture rows (user0, project0, ...) are created
// lazily on first reference.
type ifaceHandles struct {
	m map[string][]uint
}

func newIfaceHandles() *ifaceHandles { return &ifaceHandles{m: map[string][]uint{}} }

func (h *ifaceHandles) add(kind string, id uint) int {
	h.m[kind] = append(h.m[kind], id)
	return len(h.m[kind]) - 1
}

func (h *ifaceHandles) get(kind string, i int) (uint, bool) {
	ids := h.m[kind]
	if i < 0 || i >= len(ids) {
		return 0, false
	}
	return ids[i], true
}

// name renders id as its handle, or "kind?" for an id this program never created.
func (h *ifaceHandles) name(kind string, id uint) string {
	if i := slices.Index(h.m[kind], id); i >= 0 {
		return fmt.Sprintf("%s%d", kind, i)
	}
	return kind + "?"
}

// ifaceT is the part of testing.TB the harness uses, so the red-proof tests can observe
// an oracle firing without failing themselves.
type ifaceT interface {
	Helper()
	Logf(format string, args ...any)
	Fatalf(format string, args ...any)
	Skipf(format string, args ...any)
}

// ifaceSide is one backend of a pair.
type ifaceSide struct {
	label string
	db    *gorm.DB
	ls    ifaceStore
	h     *ifaceHandles
}

// ifaceWorld is the migrated pair of backends a target runs against. pg is nil for the
// metamorphic-only target.
type ifaceWorld struct {
	s, p                 *ifaceSide
	pgCollateC, pgCtypeC bool
	wipeTables           []string
	infraFaults          int
}

// ifaceMaxInfraFaults is how many programs in a row may lose the connection before the
// run is stopped, so that a dead backend does not turn a campaign into a silent no-op.
const ifaceMaxInfraFaults = 50

// noteInfraFault abandons the program after a lost connection; enough in a row is fatal.
func (w *ifaceWorld) noteInfraFault(t ifaceT, where string) {
	w.infraFaults++
	if w.infraFaults > ifaceMaxInfraFaults {
		t.Fatalf("HARNESS INFRASTRUCTURE FAULT (not a backend divergence): lost Postgres for %d programs in a row (%s)", w.infraFaults, where)
	}
	t.Skipf("infrastructure: lost Postgres connection at %s, program abandoned", where)
}

// newIfaceWorld opens SQLite and, when withPG, PostgreSQL. Both are migrated by the
// production path. Over a high-latency link, PG is a clone of a once-migrated template,
// so a fuzz worker pays one CREATE DATABASE instead of the migration.
func newIfaceWorld(tb testing.TB, withPG bool) *ifaceWorld {
	tb.Helper()
	sqliteDSN := sqlitetest.DSN("w4iface_")
	if err := createStorageClosedAtCleanup(tb, &config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqliteDSN}},
	}); err != nil {
		tb.Fatalf("sqlite production migration: %v", err)
	}
	sdb, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open sqlite: %v", err)
	}
	if s, e := sdb.DB(); e == nil {
		s.SetMaxOpenConns(1)
	}
	w := &ifaceWorld{s: &ifaceSide{label: "sqlite", db: sdb}, pgCollateC: true}
	var pdb *gorm.DB
	if withPG {
		base := os.Getenv("KEYORIX_TEST_PG_DSN")
		if base == "" {
			tb.Skip("KEYORIX_TEST_PG_DSN not set: the differential needs a real Postgres")
		}
		clone := ifaceCloneDSN(tb, base)
		// SkipDefaultTransaction removes gorm's implicit BEGIN/COMMIT around a single
		// statement, which only costs two round trips here. Multi-statement methods use
		// explicit transactions and are unaffected.
		pdb, err = gorm.Open(postgres.Open(clone), &gorm.Config{Logger: logger.Discard, SkipDefaultTransaction: true})
		if err != nil {
			tb.Fatalf("open pg clone: %v", err)
		}
		if p, e := pdb.DB(); e == nil {
			p.SetMaxOpenConns(1)
			tb.Cleanup(func() { _ = p.Close() })
		}
		var coll, ctype string
		if err := pdb.Raw("SELECT datcollate, datctype FROM pg_database WHERE datname = current_database()").Row().Scan(&coll, &ctype); err != nil {
			tb.Fatalf("read pg collation: %v", err)
		}
		w.pgCollateC, w.pgCtypeC = coll == "C" || coll == "POSIX", ctype == "C" || ctype == "POSIX"
		w.p = &ifaceSide{label: "postgres", db: pdb}
	}
	if w.wipeTables, err = ifaceTablesToWipe(sdb, pdb); err != nil {
		tb.Fatalf("list wipe tables: %v", err)
	}
	return w
}

// ifaceCloneDSN creates the w4_ anchor database if needed and returns a fresh clone of
// the migrated template, dropped on cleanup. The anchor keeps the template's advisory
// lock and name inside the w4_ namespace.
func ifaceCloneDSN(tb testing.TB, base string) string {
	tb.Helper()
	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open pg admin: %v", err)
	}
	if a, e := admin.DB(); e == nil {
		defer func() { _ = a.Close() }()
	}
	exists := func() (bool, error) {
		var n int64
		err := admin.Raw("SELECT count(*) FROM pg_database WHERE datname = ?", ifaceAnchorDB).Scan(&n).Error
		return n > 0, err
	}
	ok, err := exists()
	if err != nil {
		tb.Fatalf("check anchor: %v", err)
	}
	if !ok {
		// A concurrent worker may win this; the re-check decides.
		createErr := admin.Exec("CREATE DATABASE " + ifaceAnchorDB).Error
		if ok, err = exists(); err != nil || !ok {
			tb.Fatalf("create anchor: %v / %v", createErr, err)
		}
	}
	return pgdsn.MigratedDatabase(tb, pgdsn.PGReplaceDBName(base, ifaceAnchorDB), ifaceClonePrefix,
		pgdsn.SchemaFingerprint(), kxstorage.MigrateExisting)
}

// ifaceTablesToWipe returns every application table that is empty right after
// migration and exists on both backends. Tables holding migration-seeded rows are left
// alone (system_metadata carries the schema epoch). Computed once per world.
func ifaceTablesToWipe(sdb, pdb *gorm.DB) ([]string, error) {
	var names []string
	if err := sdb.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&names).Error; err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if n == "system_metadata" {
			continue
		}
		var c int64
		if err := sdb.Raw(`SELECT count(*) FROM "` + n + `"`).Scan(&c).Error; err != nil {
			return nil, err
		}
		if c == 0 {
			out = append(out, n)
		}
	}
	if pdb == nil {
		return out, nil
	}
	var pgNames []string
	if err := pdb.Raw("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()").Scan(&pgNames).Error; err != nil {
		return nil, err
	}
	out = slices.DeleteFunc(out, func(n string) bool { return !slices.Contains(pgNames, n) })
	if len(out) == 0 {
		return nil, errors.New("no tables to wipe")
	}
	return out, nil
}

// reset empties every table and gives both backends a new LocalStorage, so no
// in-process cache survives from the previous program. A failed reset is a harness
// fault, reported under its own prefix so it cannot be mistaken for a divergence.
func (w *ifaceWorld) reset(t ifaceT, wrap func(side string, ls ifaceStore) ifaceStore) {
	t.Helper()
	for _, s := range []*ifaceSide{w.s, w.p} {
		if s == nil {
			continue
		}
		var err error
		if s.label == "postgres" {
			// One statement, one round trip.
			quoted := make([]string, 0, len(w.wipeTables))
			for _, n := range w.wipeTables {
				quoted = append(quoted, `"`+n+`"`)
			}
			err = s.db.Exec("TRUNCATE TABLE " + strings.Join(quoted, ", ") + " RESTART IDENTITY").Error
		} else {
			for _, n := range w.wipeTables {
				if err = s.db.Exec(`DELETE FROM "` + n + `"`).Error; err != nil {
					break
				}
			}
		}
		if err == nil {
			err = s.db.Exec("DELETE FROM system_metadata WHERE key LIKE 'w4%'").Error
		}
		if err != nil {
			if ifaceIsConnectionError(err.Error()) {
				w.noteInfraFault(t, "reset "+s.label)
			}
			t.Fatalf("HARNESS INFRASTRUCTURE FAULT (not a backend divergence): reset %s: %v", s.label, err)
		}
		w.infraFaults = 0
		var ls ifaceStore = store.NewLocalStorage(s.db)
		if wrap != nil {
			ls = wrap(s.label, ls)
		}
		s.ls, s.h = ls, newIfaceHandles()
	}
}

// ifaceExec is one program in flight.
type ifaceExec struct {
	t       ifaceT
	w       *ifaceWorld
	ctx     context.Context
	pool    []string
	step    int
	stopped bool
}

// opParams are the fields decoded from a program's three bytes for one step.
type opParams struct {
	name, name2 string
	mode        uint32
	a, b        byte
	instant     ifaceInstant
}

// pick returns one of n fixture indices from the given byte.
func pick(b byte, n int) int { return int(b) % n }

func (e *ifaceExec) both(label string, fn func(*ifaceSide) string) {
	if e.stopped {
		return
	}
	got1 := fn(e.w.s)
	if e.w.p == nil {
		return
	}
	got2 := fn(e.w.p)
	if strings.Contains(got1, ifaceConnClass) || strings.Contains(got2, ifaceConnClass) {
		e.w.noteInfraFault(e.t, label)
	}
	if got1 == got2 {
		return
	}
	dc := &ifaceDiffContext{label: label, sqlite: got1, postgres: got2, pgCollateC: e.w.pgCollateC, pgCtypeC: e.w.pgCtypeC}
	rules := ifaceIntendedDiffs
	if os.Getenv("IFACE_DIFF_STRICT") != "1" {
		rules = append(slices.Clone(rules), ifaceKnownFindings...)
	}
	for _, r := range rules {
		if r.Applies(dc) {
			ifaceRuleHits[r.ID]++
			e.t.Logf("ACCEPTED DIFFERENCE %s at step=%d op=%s\n  sqlite:   %s\n  postgres: %s", r.ID, e.step, label, got1, got2)
			if r.Stops {
				e.stopped = true
			}
			return
		}
	}
	e.t.Fatalf("BACKEND DIVERGENCE: step=%d op=%s\n  sqlite:   %s\n  postgres: %s", e.step, label, got1, got2)
}

// meta fails a per-backend check (a metamorphic relation that must hold on any backend).
func (e *ifaceExec) meta(s *ifaceSide, cond bool, format string, args ...any) {
	e.t.Helper()
	if !cond {
		e.t.Fatalf("METAMORPHIC VIOLATION on %s: step=%d "+format, append([]any{s.label, e.step}, args...)...)
	}
}

// runProgram runs one byte program with the shared per-program fixture.
func (w *ifaceWorld) runProgram(t ifaceT, program []byte, s1, s2 string, wrap func(string, ifaceStore) ifaceStore) *ifaceExec {
	t.Helper()
	w.reset(t, wrap)
	e := &ifaceExec{t: t, w: w, ctx: context.Background(), pool: append(slices.Clone(ifaceStringPool), s1, s2)}
	// A step is four bytes: op, mode, a (primary name, row index), b (secondary name,
	// instant, row index).
	const stepWidth = 4
	for i := 0; i+stepWidth <= len(program) && e.step < ifaceMaxSteps && !e.stopped; i += stepWidth {
		opb, mode, a, b := program[i], program[i+1], program[i+2], program[i+3]
		p := opParams{
			name:  e.pool[int(a)%len(e.pool)],
			name2: e.pool[int(b)%len(e.pool)],
			mode:  uint32(mode),
			a:     a,
			b:     b,
			instant: ifaceInstant{
				offset: ifaceOffsets[int(b)%len(ifaceOffsets)],
				zone:   int(a) >> 6,
			},
		}
		e.dispatch(opb%byte(len(ifaceOps)), p)
		e.step++
	}
	return e
}

func (e *ifaceExec) dispatch(op byte, p opParams) { ifaceOps[op](e, p) }

// FuzzStorageIfaceDifferential: see the file comment.
func FuzzStorageIfaceDifferential(f *testing.F) {
	w := newIfaceWorld(f, true)
	ifaceSeeds(f)
	f.Fuzz(func(t *testing.T, program []byte, s1, s2 string) {
		if !diffValidString(s1) || !diffValidString(s2) {
			t.Skip("string outside the declared domain (NUL / invalid UTF-8 / >512 B)")
		}
		w.runProgram(t, program, s1, s2, nil)
	})
}

// FuzzStorageIfaceMetamorphicSQLite runs the same programs on SQLite alone. It needs no
// server, so it also runs where KEYORIX_TEST_PG_DSN is unset.
func FuzzStorageIfaceMetamorphicSQLite(f *testing.F) {
	w := newIfaceWorld(f, false)
	ifaceSeeds(f)
	f.Fuzz(func(t *testing.T, program []byte, s1, s2 string) {
		if !utf8.ValidString(s1) || !utf8.ValidString(s2) || strings.ContainsRune(s1, 0) || strings.ContainsRune(s2, 0) {
			t.Skip("string outside the declared domain")
		}
		w.runProgram(t, program, s1, s2, nil)
	})
}
