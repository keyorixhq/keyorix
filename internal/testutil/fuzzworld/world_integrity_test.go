package fuzzworld

import (
	"errors"
	"os"
	"strconv"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type jwA struct {
	ID uint `gorm:"primaryKey"`
}

func (jwA) TableName() string { return "jw_a" }

type jwB struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

func (jwB) TableName() string { return "jw_b" }

var jwTables = []string{"jw_a", "jw_b"}

func newSQLiteWorld(t *testing.T) *World {
	t.Helper()
	db := OpenSQLite(t, ":memory:", 1)
	if err := db.AutoMigrate(&jwA{}, &jwB{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &World{Backend: BackendSQLite, DB: db}
}

func TestWorldDigestEqualAndDiff(t *testing.T) {
	w := newSQLiteWorld(t)
	base, err := Digest(w, jwTables)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// Insert, then reset, then re-digest: must equal the empty baseline.
	w.DB.Create(&jwA{})
	w.DB.Create(&jwB{Name: "x"})
	if err := w.Reset(jwTables); err != nil {
		t.Fatalf("reset: %v", err)
	}
	after, err := Digest(w, jwTables)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if ok, diff := base.Equal(after); !ok {
		t.Fatalf("digest after reset should equal baseline: %s", diff)
	}

	// A world with a stray row must NOT equal the baseline (red).
	w.DB.Create(&jwA{})
	dirty, _ := Digest(w, jwTables)
	if ok, _ := base.Equal(dirty); ok {
		t.Fatalf("digest with a stray row must differ from baseline")
	}
}

func TestCheckResetList(t *testing.T) {
	w := newSQLiteWorld(t)

	// Exact match: no error.
	if err := CheckResetList(w, jwTables); err != nil {
		t.Fatalf("exact list should pass: %v", err)
	}
	// FORGOTTEN: jw_b live but omitted -> error names it.
	err := CheckResetList(w, []string{"jw_a"})
	if err == nil || !contains(err.Error(), "FORGOTTEN") || !contains(err.Error(), "jw_b") {
		t.Fatalf("forgotten table should be flagged, got %v", err)
	}
	// Exempt jw_b: no error.
	if err := CheckResetList(w, []string{"jw_a"}, "jw_b"); err != nil {
		t.Fatalf("exempted table should pass: %v", err)
	}
	// STALE: a reset entry that does not exist.
	err = CheckResetList(w, append(append([]string{}, jwTables...), "ghost_table"))
	if err == nil || !contains(err.Error(), "STALE") || !contains(err.Error(), "ghost_table") {
		t.Fatalf("stale table should be flagged, got %v", err)
	}
}

func TestProcessReset(t *testing.T) {
	var pr ProcessReset
	n := 0
	pr.Add(func() { n++ })
	pr.Add(nil) // ignored
	pr.Add(func() { n += 10 })
	pr.Run()
	pr.Run()
	if n != 22 {
		t.Fatalf("ProcessReset ran wrong: n=%d want 22", n)
	}
}

func TestReVerify(t *testing.T) {
	fresh := newSQLiteWorld(t)
	// Reproduces on a clean world -> genuine, empty verdict.
	if r := ReVerify(fresh, func(*World) bool { return true }); r != "" {
		t.Fatalf("reproducing failure should be genuine, got %q", r)
	}
	// Passes on a clean world -> STATE-DEPENDENT.
	r := ReVerify(fresh, func(*World) bool { return false })
	if !contains(r, "STATE-DEPENDENT") {
		t.Fatalf("non-reproducing failure should be STATE-DEPENDENT, got %q", r)
	}
}

func TestPidFromSchemaName(t *testing.T) {
	cases := []struct {
		name, prefix string
		pid          int
		ok           bool
	}{
		{"rsg1_fuzz_1234_7", "rsg1_fuzz", 1234, true},
		{"rsg1_fuzz_0_1", "rsg1_fuzz", 0, false},   // pid must be > 0
		{"rsg1_fuzz_12", "rsg1_fuzz", 0, false},    // missing seq
		{"rsg1_fuzz_a_1", "rsg1_fuzz", 0, false},   // non-numeric pid
		{"other_fuzz_1_1", "rsg1_fuzz", 0, false},  // wrong prefix
		{"rsg1_fuzz_1_2_3", "rsg1_fuzz", 0, false}, // too many parts
	}
	for _, c := range cases {
		pid, ok := pidFromSchemaName(c.name, c.prefix)
		if ok != c.ok || (ok && pid != c.pid) {
			t.Errorf("pidFromSchemaName(%q,%q)=(%d,%v) want (%d,%v)", c.name, c.prefix, pid, ok, c.pid, c.ok)
		}
	}
}

func TestJanitorRefusesUnsafePrefix(t *testing.T) {
	for _, bad := range []string{"", "public", "pg_temp", "information_schema", "rsg1;drop", "a b"} {
		_, err := JanitorSchemas("postgres://unused/db", bad)
		if !errors.Is(err, ErrUnsafePrefix) {
			t.Errorf("prefix %q should be refused with ErrUnsafePrefix, got %v", bad, err)
		}
	}
}

// TestJanitorSchemas_PG is PG-gated: it needs KEYORIX_TEST_PG_DSN and uses only
// the rsg1_jantest_ prefix, never touching another session's schemas.
func TestJanitorSchemas_PG(t *testing.T) {
	dsn := os.Getenv(PGDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set", PGDSNEnv)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	}()

	const prefix = "rsg1_jantest"
	self := SelfPID()
	deadPID := 999111 // a pid that is not this process
	live := prefix + "_" + strconv.Itoa(self) + "_1"
	dead := prefix + "_" + strconv.Itoa(deadPID) + "_1"

	// Clean slate, then create one "live" and one "dead" schema.
	for _, s := range []string{live, dead} {
		if err := db.Exec("DROP SCHEMA IF EXISTS " + quoteSchemaIdent(s) + " CASCADE").Error; err != nil {
			t.Fatalf("pre-drop %s: %v", s, err)
		}
		if err := db.Exec("CREATE SCHEMA " + quoteSchemaIdent(s)).Error; err != nil {
			t.Fatalf("create %s: %v", s, err)
		}
	}
	t.Cleanup(func() {
		for _, s := range []string{live, dead} {
			_ = db.Exec("DROP SCHEMA IF EXISTS " + quoteSchemaIdent(s) + " CASCADE").Error
		}
	})

	dropped, err := JanitorSchemas(dsn, prefix, self)
	if err != nil {
		t.Fatalf("janitor: %v", err)
	}
	if !containsStr(dropped, dead) {
		t.Fatalf("janitor should drop the dead-worker schema %s, dropped=%v", dead, dropped)
	}
	if containsStr(dropped, live) {
		t.Fatalf("janitor must preserve the live schema %s", live)
	}

	// Confirm in the catalog.
	var remaining []string
	db.Raw("SELECT nspname FROM pg_namespace WHERE starts_with(nspname, ?)", prefix+"_").Scan(&remaining)
	if containsStr(remaining, dead) {
		t.Fatalf("dead schema still present: %v", remaining)
	}
	if !containsStr(remaining, live) {
		t.Fatalf("live schema was wrongly dropped: %v", remaining)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
