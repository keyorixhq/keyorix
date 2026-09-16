package store

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// FuzzStorageBackendDifferential runs the SAME sequence of storage operations against
// a SQLite backend and a PostgreSQL backend in lockstep and asserts they AGREE after
// normalising away legitimate engine differences. The two backends are each other's
// oracle — no correct answer is hand-specified — so this catches the "passes on SQLite,
// breaks on Postgres" class: ordering without ORDER BY, NULL vs empty-string, unique/
// upsert semantics, case/collation, typed-error mapping.
//
// It is a differential harness, not an in-wall one: it needs a real Postgres, so it
// SKIPS unless $KEYORIX_TEST_PG_DSN is set (a rig with PG, or the demo container). CI
// and dev without PG skip cleanly.
//
// Soundness lives entirely in the normalisation: we compare only genuine contracts —
// error CLASS agreement (both nil / both error), value equality by NATURAL KEY (ids
// and timestamps zeroed), and list results as SETS. A differing row ORDER is NOT a hard
// failure here (order without ORDER BY is engine-defined); phase 1 sticks to set/value
// agreement to stay false-positive-free.
func FuzzStorageBackendDifferential(f *testing.F) {
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set — differential fuzzing needs a real Postgres (rig-only)")
	}

	// migrateSet is the schema both backends are brought to; one model per AutoMigrate
	// call (the pgx prepared-statement cache mishandles inspect-after-create otherwise).
	migrateSet := []interface{}{
		&models.Project{}, &models.Environment{}, &models.User{},
	}
	migrate := func(db *gorm.DB) error {
		for _, m := range migrateSet {
			if err := db.AutoMigrate(m); err != nil {
				return fmt.Errorf("migrate %T: %w", m, err)
			}
		}
		return nil
	}

	// --- SQLite backend (shared-cache in-memory so the single logical DB persists) ---
	sqliteDSN := fmt.Sprintf("file:difffuzz_%d?mode=memory&cache=shared", pgSchemaSeq.Add(1))
	sdb, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if s, e := sdb.DB(); e == nil {
		s.SetMaxOpenConns(1)
	}
	if err := migrate(sdb); err != nil {
		f.Fatalf("sqlite migrate: %v", err)
	}

	// --- Postgres backend, isolated in a fresh schema for this process ---
	schema := fmt.Sprintf("difffuzz_%d_%d", os.Getpid(), pgSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open pg admin: %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		f.Fatalf("pg drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		f.Fatalf("pg create schema: %v", err)
	}
	f.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		}
	})
	pdb, err := gorm.Open(postgres.Open(pgDSN+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open pg: %v", err)
	}
	if err := migrate(pdb); err != nil {
		f.Fatalf("pg migrate: %v", err)
	}

	sls, pls := NewLocalStorage(sdb), NewLocalStorage(pdb)

	// wipe resets both backends to an identical empty state (child tables first).
	wipe := func(db *gorm.DB) {
		for _, tbl := range []string{"environments", "secret_versions", "secret_nodes", "users", "projects"} {
			_ = db.Exec("DELETE FROM " + tbl).Error
		}
	}

	// errClass collapses an error to the only thing both engines must agree on.
	errClass := func(e error) bool { return e == nil }

	f.Add([]byte{0, 1, 0, 1, 2, 1, 0, 1})

	f.Fuzz(func(t *testing.T, program []byte) {
		wipe(sdb)
		wipe(pdb)
		ctx := context.Background()

		// small alphabets so keys collide → unique/dup/case paths are actually hit.
		names := []string{"alpha", "Alpha", "", "beta", "beta "}

		apply := func(op, a byte) (bool, bool) { // returns (sqliteOK, pgOK)
			name := names[int(a)%len(names)]
			switch op % 3 {
			case 0: // CreateProject
				_, se := sls.CreateProject(ctx, &models.Project{Name: name})
				_, pe := pls.CreateProject(ctx, &models.Project{Name: name})
				return errClass(se), errClass(pe)
			case 1: // CreateUser
				su := &models.User{Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io", IsActive: true}
				pu := &models.User{Username: name, UsernameFolded: name, Email: name + "@x.io", EmailFolded: name + "@x.io", IsActive: true}
				_, se := sls.CreateUser(ctx, su)
				_, pe := pls.CreateUser(ctx, pu)
				return errClass(se), errClass(pe)
			default: // GetProjectByName
				sp, se := sls.GetProjectByName(ctx, name)
				pp, pe := pls.GetProjectByName(ctx, name)
				if errClass(se) != errClass(pe) {
					return errClass(se), errClass(pe)
				}
				if se == nil && pe == nil && sp != nil && pp != nil && sp.Name != pp.Name {
					t.Fatalf("BACKEND DIVERGENCE: GetProjectByName(%q) name mismatch sqlite=%q pg=%q", name, sp.Name, pp.Name)
				}
				return errClass(se), errClass(pe)
			}
		}

		const maxSteps = 24
		steps := 0
		for i := 0; i+1 < len(program) && steps < maxSteps; i += 2 {
			sOK, pOK := apply(program[i], program[i+1])
			if sOK != pOK {
				t.Fatalf("BACKEND DIVERGENCE: op=%d operand=%d error-class disagreement sqliteOK=%v pgOK=%v",
					program[i]%3, program[i+1], sOK, pOK)
			}
			steps++
		}

		// Final state: the set of project names must be identical across backends.
		sProjects, se := sls.ListProjects(ctx)
		pProjects, pe := pls.ListProjects(ctx)
		if errClass(se) != errClass(pe) {
			t.Fatalf("BACKEND DIVERGENCE: ListProjects error-class sqlite=%v pg=%v", se, pe)
		}
		if se == nil && pe == nil {
			ss, ps := projectNameSet(sProjects), projectNameSet(pProjects)
			if len(ss) != len(ps) {
				t.Fatalf("BACKEND DIVERGENCE: ListProjects set size sqlite=%v pg=%v", ss, ps)
			}
			for i := range ss {
				if ss[i] != ps[i] {
					t.Fatalf("BACKEND DIVERGENCE: ListProjects set sqlite=%v pg=%v", ss, ps)
				}
			}
		}
	})
}

var pgSchemaSeq atomic.Int64

// projectNameSet normalises a project list to a sorted set of names (ids/timestamps
// are engine-assigned and deliberately ignored).
func projectNameSet(ps []*models.Project) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}
