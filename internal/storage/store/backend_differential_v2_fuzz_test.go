package store_test

// FuzzStorageBackendDifferentialV2 is the second-generation SQLite-vs-PostgreSQL
// differential. It keeps v1's design (the two backends are each other's oracle, both
// migrated through the production factory) and closes v1's gaps: typed error CLASS
// instead of nil/non-nil, an edge-string pool plus fuzzer-supplied strings, updates,
// delete/recreate, list filters with pagination, byte-exact secret version payloads and
// project delete/restore. Concurrency and ORDER BY comparison live in
// backend_differential_v2_extra_test.go. The success rule and the declared
// normalisations are in docs/fuzzing/pg-sqlite-differential.md and were committed
// before the first campaign.

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// diffSide is one backend of the pair plus the ids of its base project/environment
// (engine-assigned, so they differ between sides and are never compared).
type diffSide struct {
	label     string
	ls        *store.LocalStorage
	db        *gorm.DB
	proj, env uint
}

type diffWorld struct{ s, p *diffSide }

// diffSentinels is the closed set of storage error classes both backends must agree on.
var diffSentinels = []struct {
	name string
	err  error
}{
	{"UserNotFound", storage.ErrUserNotFound},
	{"GroupNotFound", storage.ErrGroupNotFound},
	{"DuplicateEmail", storage.ErrDuplicateEmail},
	{"DuplicateUsername", storage.ErrDuplicateUsername},
	{"DuplicateProjectName", storage.ErrDuplicateProjectName},
	{"DuplicateGroupName", storage.ErrDuplicateGroupName},
	{"DuplicateSecretVersion", storage.ErrDuplicateSecretVersion},
	{"SecretValueTooLarge", storage.ErrSecretValueTooLarge},
	{"SecretVersionNotFound", storage.ErrSecretVersionNotFound},
	{"SecretNotFound", storage.ErrSecretNotFound},
	{"RecordNotFound", gorm.ErrRecordNotFound},
}

// diffClass collapses an error to its sentinel class: "ok", a sentinel name, or "other".
func diffClass(err error) string {
	if err == nil {
		return "ok"
	}
	for _, s := range diffSentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	return "other"
}

// diffNamePool is the edge-string alphabet. Pairs are chosen so that case folding,
// normalisation, LIKE metacharacters, whitespace and length boundaries collide.
var diffNamePool = []string{
	"alpha", "Alpha", "", "beta", "beta ", " beta",
	"ÄÖ", "äö", "İstanbul", "istanbul", "straße", "STRASSE",
	"Σίσυφος", "ΣΊΣΥΦΟΣ", "é", "é",
	"a%b", "a_b", `a\b`, "日本語", "🔑", "NULL", "null",
	strings.Repeat("x", 255), strings.Repeat("y", 300),
}

func diffValidString(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(s) <= 512
}

func newDiffWorld(tb testing.TB, prefix string) *diffWorld {
	tb.Helper()
	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if pgDSN == "" {
		tb.Skip("KEYORIX_TEST_PG_DSN not set — differential fuzzing needs a real Postgres (rig-only)")
	}
	sqliteDSN := sqlitetest.DSN(prefix)
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
	schema := fmt.Sprintf("%s%d_%d", prefix, os.Getpid(), pgSchemaSeq.Add(1))
	admin, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open pg admin: %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		tb.Fatalf("pg drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		tb.Fatalf("pg create schema: %v", err)
	}
	if a, e := admin.DB(); e == nil {
		tb.Cleanup(func() { _ = a.Close() })
	}
	tb.Cleanup(func() {
		if c, e := gorm.Open(postgres.Open(pgDSN), &gorm.Config{Logger: logger.Discard}); e == nil {
			_ = c.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
			if d, e2 := c.DB(); e2 == nil {
				_ = d.Close()
			}
		}
	})
	pgTargetDSN := pgdsn.PGSearchPathDSN(pgDSN, schema)
	if err := createStorageClosedAtCleanup(tb, &config.Config{
		Storage: config.StorageConfig{Type: "postgres", Database: config.DatabaseConfig{DSN: pgTargetDSN}},
	}); err != nil {
		tb.Fatalf("pg production migration: %v", err)
	}
	pdb, err := gorm.Open(postgres.Open(pgTargetDSN), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open pg: %v", err)
	}
	if p, e := pdb.DB(); e == nil {
		p.SetMaxOpenConns(1)
		tb.Cleanup(func() { _ = p.Close() })
	}
	return &diffWorld{
		s: &diffSide{label: "sqlite", ls: store.NewLocalStorage(sdb), db: sdb},
		p: &diffSide{label: "postgres", ls: store.NewLocalStorage(pdb), db: pdb},
	}
}

// reset wipes both sides and recreates the base project + environment.
func (w *diffWorld) reset(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, sd := range []*diffSide{w.s, w.p} {
		err := diffWipeTables(sd.db)
		if err != nil {
			err = diffWipeTables(sd.db)
		}
		if err != nil {
			t.Fatalf("HARNESS INFRASTRUCTURE FAULT (not a backend divergence): could not reset the %s backend: %v", sd.label, err)
		}
		p, err := sd.ls.CreateProject(ctx, &models.Project{Name: "base-project"})
		if err != nil {
			t.Fatalf("HARNESS INFRASTRUCTURE FAULT: base project on %s: %v", sd.label, err)
		}
		e, err := sd.ls.CreateEnvironment(ctx, &models.Environment{ProjectID: p.ID, Name: "e0"})
		if err != nil {
			t.Fatalf("HARNESS INFRASTRUCTURE FAULT: base env on %s: %v", sd.label, err)
		}
		sd.proj, sd.env = p.ID, e.ID
	}
}

func diffTimeStr(t *time.Time) string {
	if t == nil {
		return "nil"
	}
	return t.UTC().Format(time.RFC3339)
}

func diffSecretFP(n *models.SecretNode) string {
	if n == nil {
		return "<nil>"
	}
	maxReads := "nil"
	if n.MaxReads != nil {
		maxReads = fmt.Sprint(*n.MaxReads)
	}
	return fmt.Sprintf("name=%q secret=%v type=%q desc=%q class=%q exp=%s max=%s status=%q parentNil=%v reads=%d meta=%q metaNil=%v",
		n.Name, n.IsSecret, n.Type, n.Description, n.Classification, diffTimeStr(n.Expiration), maxReads, n.Status, n.ParentID == nil, n.ReadCount, string(n.Metadata), n.Metadata == nil)
}

func diffVersionFP(v *models.SecretVersion) string {
	if v == nil {
		return "<nil>"
	}
	// Normalisation 7 (known difference A; added after campaign 1, declared in the doc's
	// Outcome section, not part of the pre-registered list): an empty value reads back as nil on SQLite and
	// as []byte{} on PostgreSQL, so nil-ness of EncryptedValue is not compared (length and
	// bytes are). Real values are ciphertext and never empty.
	return fmt.Sprintf("v%d len=%d crc=%08x meta=%q metaNil=%v reads=%d", v.VersionNumber, len(v.EncryptedValue),
		crc32.ChecksumIEEE(v.EncryptedValue), string(v.EncryptionMetadata), v.EncryptionMetadata == nil, v.ReadCount)
}

func diffValueOfKind(kind int, fill byte) []byte {
	sizes := []int{-1, 0, 1, 4096, 65536, 1 << 20, 1<<20 + 1}
	n := sizes[kind%len(sizes)]
	if n < 0 {
		return nil
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = fill + byte(i)
	}
	return b
}

func diffJoinSorted(xs []string) string {
	sort.Strings(xs)
	return strings.Join(xs, "\x1f")
}

// FuzzStorageBackendDifferentialV2 — see the file comment.
func FuzzStorageBackendDifferentialV2(f *testing.F) {
	w := newDiffWorld(f, "diffv2_")

	// opcode = low nibble of byte 0; mode = high nibble; operand low 5 bits = name.
	f.Add([]byte{3, 1, 6, 1, 0x16, 1, 0x26, 1, 0x56, 1, 0x66, 1, 7, 1, 0x47, 1}, "Zürich", "ǅungla") // secret, versions of every payload kind, list
	f.Add([]byte{3, 0, 3, 1, 4, 0xa0, 4, 0x41, 0x17, 0, 0x87, 0, 5, 0, 7, 0}, "alpha", "ALPHA")      // update set/clear, delete/restore, list
	f.Add([]byte{1, 6, 0x11, 6, 0x21, 6, 8, 6, 0x28, 6, 9, 6, 2, 6, 1, 6}, "İ", "i̇")                // user create modes, list, deactivate, delete, recreate
	f.Add([]byte{3, 0, 6, 0x10, 6, 0x20, 6, 0x30, 6, 0x40}, "", "")
	f.Add([]byte{10, 3, 10, 4, 0x1a, 3, 0x1a, 5, 0x2a, 9}, "grp", "Grp")                                // groups: create, rename, page
	f.Add([]byte{11, 1, 0x1b, 1, 12, 2, 0, 1, 13, 1}, "proj", "Proj")                                   // project lifecycle, rename, case probe
	f.Add([]byte{1, 1, 0x48, 0}, "", "")                                                                // F-2 shape: user "Alpha", Username filter "alpha"
	f.Add([]byte{3, 6, 0x17, 7}, "", "")                                                                // secret "ÄÖ", search "äö" (was F-1, fixed by #4019)
	f.Add([]byte{0x21, 1, 0x58, 0}, "", "")                                                             // F-3 shape: user+email "Alpha", Email filter "alpha"
	f.Add([]byte{3, 1, 3, 2, 3, 3, 0x37, 1, 0x47, 2, 0x57, 3, 0x67, 4, 0x77, 5, 0x87, 6}, "alp", "ALP") // every ListSecrets variant

	f.Fuzz(func(t *testing.T, program []byte, s1, s2 string) {
		if !diffValidString(s1) || !diffValidString(s2) {
			t.Skip("string outside the declared domain (NUL / invalid UTF-8 / >512 B)")
		}
		w.reset(t)
		ctx := context.Background()
		pool := append(append([]string{}, diffNamePool...), s1, s2)
		const maxSteps = 24
		steps := 0

		both := func(label string, fn func(*diffSide) string) {
			got1, got2 := fn(w.s), fn(w.p)
			if os.Getenv("DIFF_TRACE") == "1" { // harness self-check: show what each op really did
				fmt.Fprintf(os.Stderr, "TRACE step=%d %s => %s\n", steps, label, got1)
			}
			if got1 != got2 {
				t.Fatalf("BACKEND DIVERGENCE: step=%d op=%s\n  sqlite:   %s\n  postgres: %s\n  program=%x s1=%q s2=%q",
					steps, label, got1, got2, program, s1, s2)
			}
		}

		for i := 0; i+1 < len(program) && steps < maxSteps; i += 2 {
			op, a := (program[i]&0x0f)%14, program[i+1]
			mode := int(program[i] >> 4)
			bits := uint(a>>5) | uint(mode)<<3
			// Low 5 bits of the operand pick the primary name, so two ops given the same
			// low bits target the same row; the high 3 bits (+ the op's mode nibble)
			// feed option bits and the secondary name.
			name := pool[int(a&0x1f)%len(pool)]
			name2 := pool[(int(a>>5)*5+mode)%len(pool)]

			switch op {
			case 0: // CreateProject + readback
				both(fmt.Sprintf("CreateProject(%q)", name), func(s *diffSide) string {
					_, err := s.ls.CreateProject(ctx, &models.Project{Name: name, Description: name2})
					g, gerr := s.ls.GetProjectByName(ctx, name)
					gn := "<nil>"
					if g != nil {
						gn = fmt.Sprintf("%q/%q", g.Name, g.Description)
					}
					return fmt.Sprintf("%s get=%s %s", diffClass(err), diffClass(gerr), gn)
				})
			case 1: // CreateUser + both lookups
				// mode%3 picks which unique index can fire, so a single-constraint
				// violation is classified exactly: 0 = username only (email unique per
				// step), 1 = email only (username unique per step), 2 = both. When BOTH
				// the username and email indexes are violated the engine decides which
				// one it reports (SQLite: DuplicateEmail, PostgreSQL: DuplicateUsername
				// observed in the first smoke run) — declared normalisation 6: in mode 2
				// the two Duplicate* classes are treated as one.
				uname, email := name, name+"@x.io"
				switch mode % 3 {
				case 0:
					email = fmt.Sprintf("step%d@x.io", steps)
				case 1:
					uname = fmt.Sprintf("%s-step%d", name, steps)
				}
				fn, ferr := identity.NewFoldedName(uname)
				en, eerr := identity.NewFoldedName(email)
				if ferr != nil || eerr != nil {
					break
				}
				both(fmt.Sprintf("CreateUser(%q,%q,mode=%d)", uname, email, mode%3), func(s *diffSide) string {
					_, err := s.ls.CreateUser(ctx, &models.User{Username: uname, UsernameFolded: fn.Folded(), Email: email, EmailFolded: en.Folded(), IsActive: true})
					gu, gerr := s.ls.GetUserByUsername(ctx, uname)
					ge, geerr := s.ls.GetUserByEmail(ctx, email)
					c := diffClass(err)
					if mode%3 == 2 && (c == "DuplicateEmail" || c == "DuplicateUsername") {
						c = "DuplicateUserKey"
					}
					return fmt.Sprintf("%s byName=%s/%q byEmail=%s/%q", c, diffClass(gerr), userNameOrNil(gu), diffClass(geerr), userNameOrNil(ge))
				})
			case 2: // DeleteUser then lookup (frees the partial unique index)
				both(fmt.Sprintf("DeleteUser(%q)", name), func(s *diffSide) string {
					u, err := s.ls.GetUserByUsername(ctx, name)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					derr := s.ls.DeleteUser(ctx, u.ID)
					_, gerr := s.ls.GetUserByUsername(ctx, name)
					return fmt.Sprintf("%s after=%s", diffClass(derr), diffClass(gerr))
				})
			case 3: // CreateSecret (rich fields) + readback
				typ := []string{"", "password", "api_key"}[int(a)%3]
				class := []string{"", "restricted"}[int(a>>1)%2]
				both(fmt.Sprintf("CreateSecret(%q,type=%q,class=%q)", name, typ, class), func(s *diffSide) string {
					_, err := s.ls.CreateSecret(ctx, &models.SecretNode{Name: name, ProjectID: s.proj, EnvironmentID: s.env, OwnerID: diffFixedOwnerID,
						IsSecret: a&1 == 0, Type: typ, Description: name2, Classification: class})
					g, gerr := s.ls.GetSecretByName(ctx, name, s.proj, s.env)
					return fmt.Sprintf("%s get=%s %s", diffClass(err), diffClass(gerr), diffSecretFP(g))
				})
			case 4: // UpdateSecretFields with every set/clear combination
				both(fmt.Sprintf("UpdateSecretFields(%q,bits=%06b,name2=%q)", name, bits, name2), func(s *diffSide) string {
					n, err := s.ls.GetSecretByName(ctx, name, s.proj, s.env)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					at := diffAuditBaseTime
					u := storage.SecretFieldUpdate{UpdatedAt: &at}
					effective := name
					if bits&1 != 0 {
						u.Name, effective = &name2, name2
					}
					if bits&2 != 0 {
						d := name2
						u.Description = &d
					}
					if bits&4 != 0 {
						c := []string{"", "restricted"}[(bits>>5)&1]
						u.Classification = &c
					}
					if bits&8 != 0 {
						u.SetExpiration = true
						if bits&16 != 0 {
							e := diffAuditBaseTime.Add(48 * time.Hour)
							u.Expiration = &e
						}
					}
					if bits&32 != 0 {
						u.SetMaxReads = true
						if bits&64 != 0 {
							m := 3
							u.MaxReads = &m
						}
					}
					if bits&128 != 0 {
						u.SetParentID = true
					}
					ok, uerr := s.ls.UpdateSecretFields(ctx, n.ID, u)
					g, gerr := s.ls.GetSecretByName(ctx, effective, s.proj, s.env)
					return fmt.Sprintf("%s ok=%v get=%s %s", diffClass(uerr), ok, diffClass(gerr), diffSecretFP(g))
				})
			case 5: // delete/restore toggle by current state
				both(fmt.Sprintf("DeleteOrRestoreSecret(%q)", name), func(s *diffSide) string {
					id, deleted, err := diffSecretIDAndState(s.db, name)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					var oerr error
					if deleted {
						oerr = s.ls.RestoreSecret(ctx, id)
					} else {
						oerr = s.ls.DeleteSecret(ctx, id)
					}
					_, gerr := s.ls.GetSecretByName(ctx, name, s.proj, s.env)
					return fmt.Sprintf("wasDeleted=%v %s afterGet=%s", deleted, diffClass(oerr), diffClass(gerr))
				})
			case 6: // CreateSecretVersion with byte-exact payloads
				both(fmt.Sprintf("CreateSecretVersion(%q,v=%d,kind=%d)", name, int(a)%3+1, mode%7), func(s *diffSide) string {
					n, err := s.ls.GetSecretByName(ctx, name, s.proj, s.env)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					var meta models.JSON
					switch (a >> 3) % 3 {
					case 1:
						meta = models.JSON(`{"k":"v"}`)
					case 2:
						meta = models.JSON(`{}`)
					}
					_, cerr := s.ls.CreateSecretVersion(ctx, &models.SecretVersion{SecretNodeID: n.ID, VersionNumber: int(a)%3 + 1,
						EncryptedValue: diffValueOfKind(mode%7, a), EncryptionMetadata: meta})
					lv, lerr := s.ls.GetLatestSecretVersion(ctx, n.ID)
					vs, verr := s.ls.GetSecretVersions(ctx, n.ID)
					var parts []string
					for _, v := range vs {
						parts = append(parts, fmt.Sprintf("%d:%d", v.VersionNumber, len(v.EncryptedValue)))
					}
					return fmt.Sprintf("%s latest=%s/%s list=%s/%s", diffClass(cerr), diffClass(lerr), diffVersionFP(lv), diffClass(verr), strings.Join(parts, ","))
				})
			case 7: // ListSecrets: filters + full page walk
				term := diffTerm(name, name2, a)
				both(fmt.Sprintf("ListSecrets(variant=%d,term=%q,pageSize=%d)", mode%9, term, int(a)%3+1), func(s *diffSide) string {
					return diffListSecrets(t, ctx, s, mode%9, term, int(a)%3+1)
				})
			case 8: // ListUsers: filters + full page walk
				term := diffTerm(name, name2, a)
				both(fmt.Sprintf("ListUsers(variant=%d,term=%q,pageSize=%d)", mode%6, term, int(a)%3+1), func(s *diffSide) string {
					return diffListUsers(t, ctx, s, mode%6, term, int(a)%3+1)
				})
			case 9: // deactivate/reactivate a user via the state-matching update
				both(fmt.Sprintf("ToggleUserActive(%q)", name), func(s *diffSide) string {
					u, err := s.ls.GetUserByUsername(ctx, name)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					from := u.IsActive
					u.IsActive = !from
					ok, uerr := s.ls.UpdateUserIfActiveStateMatches(ctx, u, from)
					g, _ := s.ls.GetUserByUsername(ctx, name)
					return fmt.Sprintf("%s ok=%v now=%v", diffClass(uerr), ok, g != nil && g.IsActive)
				})
			case 10: // CreateGroup / rename / paged list
				fn, ferr := identity.NewFoldedName(name)
				f2, f2err := identity.NewFoldedName(name2)
				if ferr != nil || f2err != nil {
					break
				}
				both(fmt.Sprintf("Group(%q->%q,mode=%d)", name, name2, mode%3), func(s *diffSide) string {
					var out string
					switch mode % 3 {
					case 0:
						_, err := s.ls.CreateGroup(ctx, &models.Group{Name: name, NameFolded: fn.Folded()})
						out = diffClass(err)
					case 1:
						id, rerr := diffGroupIDByName(s.db, name)
						if rerr != nil {
							return "resolve:" + diffClass(rerr)
						}
						d := name2
						ok, uerr := s.ls.UpdateGroupFields(ctx, id, &name2, ptrOf(f2.Folded()), &d, diffAuditBaseTime)
						out = fmt.Sprintf("%s ok=%v", diffClass(uerr), ok)
					default:
						out = "list"
					}
					var names []string
					var total int64
					for off := 0; off < 60; off += 2 {
						gs, tot, lerr := s.ls.ListGroupsPage(ctx, off, 2)
						if lerr != nil {
							return out + " listErr=" + diffClass(lerr)
						}
						total = tot
						for _, g := range gs {
							names = append(names, g.Name)
						}
						if len(gs) < 2 {
							break
						}
					}
					return fmt.Sprintf("%s total=%d walk=%s", out, total, diffJoinSorted(names))
				})
			case 11: // project lifecycle: create, delete, maybe recreate the name, restore
				both(fmt.Sprintf("ProjectLifecycle(%q,bits=%d)", name, bits&3), func(s *diffSide) string {
					p, err := s.ls.CreateProject(ctx, &models.Project{Name: name})
					if err != nil {
						return "create:" + diffClass(err)
					}
					derr := s.ls.DeleteProject(ctx, p.ID)
					rc := "-"
					if bits&1 != 0 {
						_, e2 := s.ls.CreateProject(ctx, &models.Project{Name: name})
						rc = diffClass(e2)
					}
					envs, secs, rerr := s.ls.RestoreProject(ctx, p.ID)
					g, gerr := s.ls.GetProjectByName(ctx, name)
					return fmt.Sprintf("del=%s recreate=%s restore=%s envs=%d secrets=%d get=%s/%q", diffClass(derr), rc, diffClass(rerr), envs, secs, diffClass(gerr), projNameOrNil(g))
				})
			case 12: // UpdateProjectFields (rename / MFA flag)
				both(fmt.Sprintf("UpdateProjectFields(%q->%q)", name, name2), func(s *diffSide) string {
					p, err := s.ls.GetProjectByName(ctx, name)
					if err != nil {
						return "resolve:" + diffClass(err)
					}
					var mfa *bool
					if bits&1 != 0 {
						m := bits&2 != 0
						mfa = &m
					}
					ok, uerr := s.ls.UpdateProjectFields(ctx, p.ID, name2, name, mfa, diffAuditBaseTime)
					g, gerr := s.ls.GetProjectByName(ctx, name2)
					return fmt.Sprintf("%s ok=%v get=%s/%q", diffClass(uerr), ok, diffClass(gerr), projNameOrNil(g))
				})
			default: // case-sensitivity probes across the lookup paths
				up := strings.ToUpper(name)
				both(fmt.Sprintf("CaseProbe(%q)", name), func(s *diffSide) string {
					u1, e1 := s.ls.GetUserByUsername(ctx, up)
					u2, e2 := s.ls.GetUserByEmail(ctx, up+"@x.io")
					n3, e3 := s.ls.GetSecretByName(ctx, up, s.proj, s.env)
					p4, e4 := s.ls.GetProjectByName(ctx, up)
					return fmt.Sprintf("user=%s/%q email=%s/%q secret=%s/%q project=%s/%q", diffClass(e1), userNameOrNil(u1), diffClass(e2), userNameOrNil(u2),
						diffClass(e3), secNameOrNil(n3), diffClass(e4), projNameOrNil(p4))
				})
			}
			steps++
		}

		// Final state: natural-key sets must agree.
		assertSetEqual(t, "projects", projectNameSet(mustListProjects(t, w.s.ls, ctx)), projectNameSet(mustListProjects(t, w.p.ls, ctx)))
		assertSetEqual(t, "secret_nodes", secretNameSet(w.s.db), secretNameSet(w.p.db))
		assertSetEqual(t, "groups", groupNameSet(w.s.db), groupNameSet(w.p.db))
		assertSetEqual(t, "users", liveUsernameSet(t, w.s.label, w.s.db), liveUsernameSet(t, w.p.label, w.p.db))
	})
}

// diffTerm derives a filter/search term from the primary and secondary names: as-is,
// upper-cased, lower-cased, or the secondary name. The case variants are what make a
// collation/LIKE-case divergence reachable without the fuzzer having to find a matching
// pair of names across two separate ops.
func diffTerm(name, name2 string, a byte) string {
	switch (a >> 5) & 3 {
	case 1:
		return strings.ToUpper(name)
	case 2:
		return strings.ToLower(name)
	case 3:
		return name2
	}
	return name
}

func ptrOf[T any](v T) *T { return &v }

func userNameOrNil(u *models.User) string {
	if u == nil {
		return "<nil>"
	}
	return u.Username
}

func projNameOrNil(p *models.Project) string {
	if p == nil {
		return "<nil>"
	}
	return p.Name
}

func secNameOrNil(n *models.SecretNode) string {
	if n == nil {
		return "<nil>"
	}
	return n.Name
}

func liveUsernameSet(t *testing.T, label string, db *gorm.DB) []string {
	t.Helper()
	var us []models.User
	if err := db.Find(&us).Error; err != nil {
		t.Fatalf("%s list users for final-state compare: %v", label, err)
	}
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, fmt.Sprintf("%s|%v", u.Username, u.IsActive))
	}
	sort.Strings(out)
	return out
}

// diffListSecrets runs ListSecrets under a filter variant and walks every page. It
// returns total, first-page length, and the SORTED union of names (page CONTENT of an
// unordered query is not a contract — see normalisation 2). It also enforces the
// within-backend invariant: the page walk is duplicate-free and equals the unpaged set.
func diffListSecrets(t *testing.T, ctx context.Context, s *diffSide, variant int, name string, pageSize int) string {
	mk := func(page, size int) *storage.SecretFilter {
		fl := &storage.SecretFilter{ProjectID: &s.proj, Page: page, PageSize: size}
		switch variant {
		case 1:
			fl.Search = &name
		case 2:
			fl.Type = ptrOf("password")
		case 3:
			fl.Classification = ptrOf("unclassified")
		case 4:
			fl.IncludeDeleted = true
		case 5:
			fl.DeletedOnly = true
		case 6:
			fl.ExpiresBefore = ptrOf(diffAuditBaseTime.Add(100 * time.Hour))
		case 7:
			fl.IsSecret = ptrOf(false)
		case 8:
			fl.Search = &name
			fl.IncludeDeleted = true
		}
		return fl
	}
	var union []string
	var total int64
	firstLen := -1
	for page := 1; page <= 60; page++ {
		rows, tot, err := s.ls.ListSecrets(ctx, mk(page, pageSize))
		if err != nil {
			return "listErr=" + diffClass(err)
		}
		total = tot
		if firstLen < 0 {
			firstLen = len(rows)
		}
		for _, r := range rows {
			union = append(union, fmt.Sprintf("%q/%v", r.Name, r.DeletedAt.Valid))
		}
		if len(rows) < pageSize {
			break
		}
	}
	all, _, err := s.ls.ListSecrets(ctx, mk(1, 1000))
	if err != nil {
		return "listAllErr=" + diffClass(err)
	}
	var allNames []string
	for _, r := range all {
		allNames = append(allNames, fmt.Sprintf("%q/%v", r.Name, r.DeletedAt.Valid))
	}
	u, a := diffJoinSorted(append([]string{}, union...)), diffJoinSorted(allNames)
	if u != a {
		t.Fatalf("BACKEND DIVERGENCE (within-backend pagination): %s ListSecrets variant=%d pageSize=%d page walk != unpaged set\n  walk=%q\n  all =%q", s.label, variant, pageSize, u, a)
	}
	return fmt.Sprintf("total=%d first=%d set=%s", total, firstLen, u)
}

func diffListUsers(t *testing.T, ctx context.Context, s *diffSide, variant int, name string, pageSize int) string {
	mk := func(page, size int) *storage.UserFilter {
		fl := &storage.UserFilter{Page: page, PageSize: size}
		switch variant {
		case 1:
			fl.Search = &name
		case 2:
			fl.IsActive = ptrOf(false)
		case 3:
			fl.IncludeDeleted = true
		case 4:
			fl.Username = &name
		case 5:
			fl.Email = ptrOf(name + "@x.io")
		}
		return fl
	}
	var union []string
	var total int64
	firstLen := -1
	for page := 1; page <= 60; page++ {
		rows, tot, err := s.ls.ListUsers(ctx, mk(page, pageSize))
		if err != nil {
			return "listErr=" + diffClass(err)
		}
		total = tot
		if firstLen < 0 {
			firstLen = len(rows)
		}
		for _, r := range rows {
			union = append(union, fmt.Sprintf("%q/%v/%v", r.Username, r.IsActive, r.DeletedAt.Valid))
		}
		if len(rows) < pageSize {
			break
		}
	}
	all, _, err := s.ls.ListUsers(ctx, mk(1, 1000))
	if err != nil {
		return "listAllErr=" + diffClass(err)
	}
	var allNames []string
	for _, r := range all {
		allNames = append(allNames, fmt.Sprintf("%q/%v/%v", r.Username, r.IsActive, r.DeletedAt.Valid))
	}
	u, a := diffJoinSorted(append([]string{}, union...)), diffJoinSorted(allNames)
	if u != a {
		t.Fatalf("BACKEND DIVERGENCE (within-backend pagination): %s ListUsers variant=%d pageSize=%d page walk != unpaged set\n  walk=%q\n  all =%q", s.label, variant, pageSize, u, a)
	}
	return fmt.Sprintf("total=%d first=%d set=%s", total, firstLen, u)
}
