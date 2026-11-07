package store_test

// Deterministic companions to FuzzStorageBackendDifferentialV2 (see
// docs/fuzzing/pg-sqlite-differential.md): ORDER BY comparison on seeded data, and a
// concurrent unique-key race whose per-backend error-class multiset must match.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// orderSeedNames mixes case, digits, punctuation, accents and a space so that BINARY
// (SQLite) and en_US.UTF-8 (PostgreSQL) collation orders genuinely differ.
// Every name is distinct after case folding (groups carry a folded unique index).
var orderSeedNames = []string{"alpha", "Bravo", "charlie", "Delta", "echo", "Foxtrot", "_x", "1", "ärger", "zulu", "Zebra", "éclair", "eclair", "a b", "ab", "10", "9"}

// TestBackendDifferentialOrdering compares every ORDER BY list as an ORDERED list.
// One subtest per list function so each divergence is classified on its own. A pure
// collation difference on a text column is "backend-inherent / ordering contract" per
// the pre-registration, but it is still printed: an operator who migrates SQLite ->
// PostgreSQL sees different list order for the same data.
func TestBackendDifferentialOrdering(t *testing.T) {
	w := newDiffWorld(t, "diffv2ord_")
	ctx := context.Background()
	w.reset(t)
	for _, s := range []*diffSide{w.s, w.p} {
		for i, n := range orderSeedNames {
			fn, err := identity.NewFoldedName(n)
			if err != nil {
				t.Fatalf("fold %q: %v", n, err)
			}
			if _, err := s.ls.CreateGroup(ctx, &models.Group{Name: n, NameFolded: fn.Folded()}); err != nil {
				t.Fatalf("%s CreateGroup(%q): %v", s.label, n, err)
			}
			if _, err := s.ls.CreateProject(ctx, &models.Project{Name: "p-" + n}); err != nil {
				t.Fatalf("%s CreateProject(%q): %v", s.label, n, err)
			}
			exp := diffAuditBaseTime.Add(time.Duration(len(orderSeedNames)-i) * time.Hour)
			if _, err := s.ls.CreateSecret(ctx, &models.SecretNode{Name: n, ProjectID: s.proj, EnvironmentID: s.env, OwnerID: diffFixedOwnerID, IsSecret: true, Expiration: &exp}); err != nil {
				t.Fatalf("%s CreateSecret(%q): %v", s.label, n, err)
			}
		}
	}
	lists := []struct {
		name string
		fn   func(s *diffSide) ([]string, error)
	}{
		{"ListGroupsPage(ORDER BY name)", func(s *diffSide) ([]string, error) {
			gs, _, err := s.ls.ListGroupsPage(ctx, 0, 100)
			var out []string
			for _, g := range gs {
				out = append(out, g.Name)
			}
			return out, err
		}},
		{"ListOrphanedSecrets(ORDER BY name ASC)", func(s *diffSide) ([]string, error) {
			ns, err := s.ls.ListOrphanedSecrets(ctx, s.proj)
			var out []string
			for _, n := range ns {
				out = append(out, n.Name)
			}
			return out, err
		}},
		{"ListSecrets(ExpiresBefore: ORDER BY expiration ASC)", func(s *diffSide) ([]string, error) {
			ns, _, err := s.ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: &s.proj, ExpiresBefore: ptrOf(diffAuditBaseTime.Add(1000 * time.Hour)), PageSize: 100})
			var out []string
			for _, n := range ns {
				out = append(out, n.Name)
			}
			return out, err
		}},
		{"ListProjects(unspecified order; informational)", func(s *diffSide) ([]string, error) {
			ps, err := s.ls.ListProjects(ctx)
			var out []string
			for _, p := range ps {
				out = append(out, p.Name)
			}
			return out, err
		}},
	}
	for _, l := range lists {
		t.Run(l.name, func(t *testing.T) {
			a, aerr := l.fn(w.s)
			b, berr := l.fn(w.p)
			if diffClass(aerr) != diffClass(berr) {
				t.Fatalf("BACKEND DIVERGENCE: error class sqlite=%v pg=%v", aerr, berr)
			}
			sa, sb := append([]string{}, a...), append([]string{}, b...)
			sort.Strings(sa)
			sort.Strings(sb)
			if strings.Join(sa, "\x1f") != strings.Join(sb, "\x1f") {
				t.Fatalf("BACKEND DIVERGENCE (row set):\n  sqlite:   %q\n  postgres: %q", a, b)
			}
			if strings.Join(a, "\x1f") != strings.Join(b, "\x1f") {
				// Same rows, different ORDER: SQLite compares text bytewise (BINARY) while
				// PostgreSQL uses the database collation (en_US.UTF-8: case-insensitive
				// first pass, punctuation ignored, accents interleaved). Backend-inherent
				// (pre-registration normalisation 4). Strict mode makes it a failure so a
				// campaign run can record the exact lists.
				msg := fmt.Sprintf("ORDER DIFFERS (backend-inherent collation):\n  sqlite:   %q\n  postgres: %q", a, b)
				if os.Getenv("DIFF_ORDER_STRICT") == "1" {
					t.Fatalf("BACKEND DIVERGENCE (ordering): %s", msg)
				}
				t.Log(msg)
			}
		})
	}
}

// concWorld is a pair of file-backed SQLite / PostgreSQL stores with REAL connection
// pools (the fuzz worlds pin both to one connection, which cannot exercise a race).
type concWorld struct {
	sls, pls *store.LocalStorage
	sdb, pdb *gorm.DB
}

func newConcWorld(t *testing.T) *concWorld {
	t.Helper()
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set")
	}
	path := filepath.Join(t.TempDir(), "conc.db")
	if err := createStorageClosedAtCleanup(t, &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: path}}}); err != nil {
		t.Fatalf("sqlite migration: %v", err)
	}
	// Same DSN suffix the production factory applies (factory_local.go sqliteDSN).
	sdb, err := gorm.Open(sqlite.Open(path+"?_foreign_keys=1&_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate&_synchronous=FULL"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	schema := fmt.Sprintf("diffv2conc_%d_%d", os.Getpid(), pgSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg admin: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if d, e := admin.DB(); e == nil {
			_ = d.Close()
		}
	})
	dsn := pgdsn.PGSearchPathDSN(pgDSN, schema)
	if err := createStorageClosedAtCleanup(t, &config.Config{Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: dsn}}}); err != nil {
		t.Fatalf("pg migration: %v", err)
	}
	pdb, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	t.Cleanup(func() {
		if d, e := sdb.DB(); e == nil {
			_ = d.Close()
		}
		if d, e := pdb.DB(); e == nil {
			_ = d.Close()
		}
	})
	return &concWorld{sls: store.NewLocalStorage(sdb), pls: store.NewLocalStorage(pdb), sdb: sdb, pdb: pdb}
}

// race runs n goroutines released together; returns the sorted multiset of error classes.
func race(n int, fn func(i int) error) string {
	var wg sync.WaitGroup
	start := make(chan struct{})
	res := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res[i] = diffClass(fn(i))
		}(i)
	}
	close(start)
	wg.Wait()
	sort.Strings(res)
	return strings.Join(res, ",")
}

// TestBackendDifferentialConcurrentUnique races N writers at one unique key on each
// backend. The error-class multiset must match, and each backend must admit exactly
// one winner. Rounds: $DIFF_CONC_ROUNDS (default 20).
func TestBackendDifferentialConcurrentUnique(t *testing.T) {
	w := newConcWorld(t)
	ctx := context.Background()
	rounds := 20
	if v, err := strconv.Atoi(os.Getenv("DIFF_CONC_ROUNDS")); err == nil && v > 0 {
		rounds = v
	}
	const n = 8
	caseVariants := []string{"Bob", "bob", "BOB", "bOb"}
	for r := 0; r < rounds; r++ {
		key := fmt.Sprintf("k%d", r)
		cases := []struct {
			name string
			run  func(ls *store.LocalStorage, db *gorm.DB, i int) error
		}{
			{"CreateUser same username", func(ls *store.LocalStorage, _ *gorm.DB, i int) error {
				u := "u" + key
				fn, _ := identity.NewFoldedName(u)
				e := fmt.Sprintf("%d-%s@x.io", i, u) // email distinct: only the username index can fire
				_, err := ls.CreateUser(ctx, &models.User{Username: u, UsernameFolded: fn.Folded(), Email: e, EmailFolded: e, IsActive: true})
				return err
			}},
			{"CreateUser same email", func(ls *store.LocalStorage, _ *gorm.DB, i int) error {
				u := fmt.Sprintf("e%d-%s", i, key) // username distinct: only the email index can fire
				fn, _ := identity.NewFoldedName(u)
				e := "shared-" + key + "@x.io"
				_, err := ls.CreateUser(ctx, &models.User{Username: u, UsernameFolded: fn.Folded(), Email: e, EmailFolded: e, IsActive: true})
				return err
			}},
			{"CreateUser case-variant usernames", func(ls *store.LocalStorage, _ *gorm.DB, i int) error {
				u := caseVariants[i%len(caseVariants)] + key
				fn, _ := identity.NewFoldedName(u)
				_, err := ls.CreateUser(ctx, &models.User{Username: u, UsernameFolded: fn.Folded(), Email: fmt.Sprintf("%d%s@x.io", i, key), EmailFolded: fmt.Sprintf("%d%s@x.io", i, key), IsActive: true})
				return err
			}},
			{"CreateProject case-variant names", func(ls *store.LocalStorage, _ *gorm.DB, i int) error {
				_, err := ls.CreateProject(ctx, &models.Project{Name: caseVariants[i%len(caseVariants)] + "-proj-" + key})
				return err
			}},
			{"CreateGroup same name", func(ls *store.LocalStorage, _ *gorm.DB, i int) error {
				g := "g" + key
				fn, _ := identity.NewFoldedName(g)
				_, err := ls.CreateGroup(ctx, &models.Group{Name: g, NameFolded: fn.Folded()})
				return err
			}},
		}
		for _, c := range cases {
			sOut := race(n, func(i int) error { return c.run(w.sls, w.sdb, i) })
			pOut := race(n, func(i int) error { return c.run(w.pls, w.pdb, i) })
			if sOut != pOut {
				t.Fatalf("BACKEND DIVERGENCE (concurrent): round=%d %s\n  sqlite:   %s\n  postgres: %s", r, c.name, sOut, pOut)
			}
			if strings.Count(sOut, "ok") != 1 {
				t.Fatalf("BACKEND DIVERGENCE (concurrent, both backends): round=%d %s expected exactly one winner, got %s", r, c.name, sOut)
			}
		}
	}
	// Secret/version race on a shared secret.
	mk := func(ls *store.LocalStorage) (uint, uint, uint) {
		p, err := ls.CreateProject(ctx, &models.Project{Name: "conc-base"})
		if err != nil {
			t.Fatalf("base project: %v", err)
		}
		e, err := ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "e0"})
		if err != nil {
			t.Fatalf("base env: %v", err)
		}
		return p.ID, e.ID, 0
	}
	sp, se, _ := mk(w.sls)
	pp, pe, _ := mk(w.pls)
	for r := 0; r < rounds; r++ {
		name := fmt.Sprintf("secret-%d", r)
		sOut := race(8, func(int) error {
			_, err := w.sls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: sp, EnvironmentID: se, OwnerID: diffFixedOwnerID, IsSecret: true})
			return err
		})
		pOut := race(8, func(int) error {
			_, err := w.pls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: pp, EnvironmentID: pe, OwnerID: diffFixedOwnerID, IsSecret: true})
			return err
		})
		if sOut != pOut {
			t.Fatalf("BACKEND DIVERGENCE (concurrent): round=%d CreateSecret same name\n  sqlite:   %s\n  postgres: %s", r, sOut, pOut)
		}
		sn, _ := w.sls.GetSecretByName(ctx, name, sp, se)
		pn, _ := w.pls.GetSecretByName(ctx, name, pp, pe)
		if sn == nil || pn == nil {
			t.Fatalf("round=%d secret missing after race sqlite=%v pg=%v", r, sn != nil, pn != nil)
		}
		vs := race(8, func(int) error {
			_, err := w.sls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: sn.ID, VersionNumber: 1, EncryptedValue: []byte("v")})
			return err
		})
		vp := race(8, func(int) error {
			_, err := w.pls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: pn.ID, VersionNumber: 1, EncryptedValue: []byte("v")})
			return err
		})
		if vs != vp {
			t.Fatalf("BACKEND DIVERGENCE (concurrent): round=%d CreateSecretVersion same number\n  sqlite:   %s\n  postgres: %s", r, vs, vp)
		}
	}
}
