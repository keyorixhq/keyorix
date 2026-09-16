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

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

// scope + role IDs the differential drives. There is no FK from user_roles to a
// roles table at this layer, so we assign fixed role IDs directly (the target hunts
// engine divergence in the write/read path, not business validation).
const (
	diffFixedProjectID = 1
	diffFixedEnvID     = 1
)

var diffRoleIDs = []uint{501, 502}

// FuzzStorageBackendDifferential runs the SAME sequence of storage operations against
// a SQLite backend and a PostgreSQL backend in lockstep and asserts they AGREE after
// normalising away legitimate engine differences. The two backends are each other's
// oracle — no correct answer is hand-specified — so this catches the "passes on SQLite,
// breaks on Postgres" class: ordering without ORDER BY, NULL vs empty-string, unique/
// upsert semantics, case/collation, composite-key upsert, typed-error mapping.
//
// It is a differential harness, not an in-wall one: it needs a real Postgres, so it
// SKIPS unless $KEYORIX_TEST_PG_DSN is set (a rig with PG, or the demo container). CI
// and dev without PG skip cleanly.
//
// Soundness lives entirely in the normalisation: we compare only genuine contracts —
// error CLASS agreement (both nil / both error), value equality by NATURAL KEY (ids
// and timestamps zeroed), and list/table results as SETS. A differing row ORDER is NOT
// a hard failure here (order without ORDER BY is engine-defined); we stick to
// set/value agreement to stay false-positive-free.
//
// Phase 2 grows the command set from projects/users to also cover the two tables that
// carry a secrets product's crown jewels and its authorization state: secret_nodes
// (CreateSecret / GetSecretByName) and user_roles (AssignRole, whose composite primary
// key exercises each engine's upsert/duplicate-grant path inside a transaction).
func FuzzStorageBackendDifferential(f *testing.F) {
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		f.Skip("KEYORIX_TEST_PG_DSN not set — differential fuzzing needs a real Postgres (rig-only)")
	}

	// migrateSet is the schema both backends are brought to; one model per AutoMigrate
	// call (the pgx prepared-statement cache mishandles inspect-after-create otherwise).
	migrateSet := []interface{}{
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.SecretNode{}, &models.UserRole{},
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
		for _, tbl := range []string{"user_roles", "secret_nodes", "environments", "users", "projects"} {
			_ = db.Exec("DELETE FROM " + tbl).Error
		}
	}

	// errClass collapses an error to the only thing both engines must agree on.
	errClass := func(e error) bool { return e == nil }

	f.Add([]byte{0, 1, 0, 1, 2, 1, 0, 1})
	f.Add([]byte{3, 3, 4, 3, 1, 3, 5, 3, 3, 4}) // create-secret, get-secret, create-user, assign-role

	f.Fuzz(func(t *testing.T, program []byte) {
		wipe(sdb)
		wipe(pdb)
		ctx := context.Background()

		// small alphabets so keys collide → unique/dup/case paths are actually hit.
		names := []string{"alpha", "Alpha", "", "beta", "beta "}

		apply := func(op, a byte) (bool, bool) { // returns (sqliteOK, pgOK)
			name := names[int(a)%len(names)]
			switch op % 6 {
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
			case 2: // GetProjectByName
				sp, se := sls.GetProjectByName(ctx, name)
				pp, pe := pls.GetProjectByName(ctx, name)
				if errClass(se) != errClass(pe) {
					return errClass(se), errClass(pe)
				}
				if se == nil && pe == nil && sp != nil && pp != nil && sp.Name != pp.Name {
					t.Fatalf("BACKEND DIVERGENCE: GetProjectByName(%q) name mismatch sqlite=%q pg=%q", name, sp.Name, pp.Name)
				}
				return errClass(se), errClass(pe)
			case 3: // CreateSecret (storage-layer node insert, fixed scope)
				sn := &models.SecretNode{Name: name, ProjectID: diffFixedProjectID, EnvironmentID: diffFixedEnvID}
				pn := &models.SecretNode{Name: name, ProjectID: diffFixedProjectID, EnvironmentID: diffFixedEnvID}
				_, se := sls.CreateSecret(ctx, sn)
				_, pe := pls.CreateSecret(ctx, pn)
				return errClass(se), errClass(pe)
			case 4: // GetSecretByName (same scope)
				ss, se := sls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				ps, pe := pls.GetSecretByName(ctx, name, diffFixedProjectID, diffFixedEnvID)
				if errClass(se) != errClass(pe) {
					return errClass(se), errClass(pe)
				}
				if se == nil && pe == nil && ss != nil && ps != nil && ss.Name != ps.Name {
					t.Fatalf("BACKEND DIVERGENCE: GetSecretByName(%q) name mismatch sqlite=%q pg=%q", name, ss.Name, ps.Name)
				}
				return errClass(se), errClass(pe)
			default: // AssignRole — composite-PK grant, exercises each engine's upsert path
				su, serr := sls.GetUserByUsername(ctx, name)
				pu, perr := pls.GetUserByUsername(ctx, name)
				if serr != nil || perr != nil {
					// user absent in one/both → nothing to grant; agree on resolvability.
					return errClass(serr), errClass(perr)
				}
				roleID := diffRoleIDs[int(a)%len(diffRoleIDs)]
				se := sls.AssignRole(ctx, su.ID, roleID, storage.Scope{})
				pe := pls.AssignRole(ctx, pu.ID, roleID, storage.Scope{})
				return errClass(se), errClass(pe)
			}
		}

		const maxSteps = 24
		steps := 0
		for i := 0; i+1 < len(program) && steps < maxSteps; i += 2 {
			sOK, pOK := apply(program[i], program[i+1])
			if sOK != pOK {
				t.Fatalf("BACKEND DIVERGENCE: op=%d operand=%d error-class disagreement sqliteOK=%v pgOK=%v",
					program[i]%6, program[i+1], sOK, pOK)
			}
			steps++
		}

		// Final state: each table's natural-key SET must be identical across backends.
		assertSetEqual(t, "projects", projectNameSet(mustListProjects(t, sls, ctx)), projectNameSet(mustListProjects(t, pls, ctx)))
		assertSetEqual(t, "secret_nodes", secretNameSet(sdb), secretNameSet(pdb))
		assertSetEqual(t, "user_roles", userRoleKeySet(sdb), userRoleKeySet(pdb))
	})
}

var pgSchemaSeq atomic.Int64

func mustListProjects(t *testing.T, ls *LocalStorage, ctx context.Context) []*models.Project {
	t.Helper()
	ps, err := ls.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	return ps
}

// assertSetEqual fails with a diff if the two sorted natural-key sets differ.
func assertSetEqual(t *testing.T, table string, s, p []string) {
	t.Helper()
	if len(s) != len(p) {
		t.Fatalf("BACKEND DIVERGENCE: %s set size sqlite=%v pg=%v", table, s, p)
	}
	for i := range s {
		if s[i] != p[i] {
			t.Fatalf("BACKEND DIVERGENCE: %s set sqlite=%v pg=%v", table, s, p)
		}
	}
}

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

// secretNameSet is the sorted set of secret-node names in one backend (scope is fixed,
// ids/timestamps ignored).
func secretNameSet(db *gorm.DB) []string {
	var nodes []models.SecretNode
	db.Find(&nodes)
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	sort.Strings(out)
	return out
}

// userRoleKeySet is the sorted set of grants keyed by natural identifiers
// (username|roleID|projectID|environmentID) — user ids are engine-assigned, so a grant
// is compared by the username it points at, resolved via each backend's own id map.
func userRoleKeySet(db *gorm.DB) []string {
	var users []models.User
	db.Find(&users)
	nameByID := make(map[uint]string, len(users))
	for _, u := range users {
		nameByID[u.ID] = u.Username
	}
	var urs []models.UserRole
	db.Find(&urs)
	out := make([]string, 0, len(urs))
	for _, ur := range urs {
		out = append(out, fmt.Sprintf("%s|%d|%d|%d", nameByID[ur.UserID], ur.RoleID, ur.ProjectID, ur.EnvironmentID))
	}
	sort.Strings(out)
	return out
}
