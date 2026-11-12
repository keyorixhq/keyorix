package store_test

// Red-proofs for the FuzzStorageIfaceDifferential oracles: each breaks ONE ifaceStore
// method on ONE backend with a test-local wrapper (no production edit), runs a program
// that reaches it, and shows the oracle fires, while the same program with no wrapper is
// silent. A differential case needs a real Postgres; a metamorphic case runs on SQLite.

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ifaceFatalSpy is an ifaceT that records the first Fatalf instead of failing the test.
type ifaceFatalSpy struct{ fatal string }

func (*ifaceFatalSpy) Helper()                     {}
func (*ifaceFatalSpy) Logf(string, ...any)         {}
func (s *ifaceFatalSpy) Fatalf(f string, a ...any) { s.fatal = fmt.Sprintf(f, a...); runtime.Goexit() }
func (s *ifaceFatalSpy) Skipf(f string, a ...any) {
	s.fatal = "skip: " + fmt.Sprintf(f, a...)
	runtime.Goexit()
}

// ifaceRunSpy runs a program on a goroutine (Fatalf ends it with Goexit) and returns
// what the oracle reported, "" when it stayed silent.
func ifaceRunSpy(w *ifaceWorld, program []byte, s1, s2 string, wrap func(string, ifaceStore) ifaceStore) string {
	spy := &ifaceFatalSpy{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.runProgram(spy, program, s1, s2, wrap)
	}()
	<-done
	return spy.fatal
}

type redDropTemplate struct{ ifaceStore }

func (b redDropTemplate) ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error) {
	ts, err := b.ifaceStore.ListSecretTemplates(ctx)
	if len(ts) > 0 {
		ts = ts[1:]
	}
	return ts, err
}

// redWrongClass lets the create-then-read relation pass (the first lookup) and then
// reports a row the other backend has as not found.
type redWrongClass struct {
	ifaceStore
	calls *int
}

func (b redWrongClass) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	*b.calls++
	if *b.calls == 1 {
		return b.ifaceStore.GetRoleByName(ctx, name)
	}
	return nil, storage.ErrRoleNotFound
}

type redReorderChannels struct{ ifaceStore }

func (b redReorderChannels) ListNotificationChannels(ctx context.Context) ([]*models.NotificationChannel, error) {
	rows, err := b.ifaceStore.ListNotificationChannels(ctx)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows, err
}

type redMangleACL struct{ ifaceStore }

func (b redMangleACL) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	a, err := b.ifaceStore.GetSecretACL(ctx, secretID, userID)
	if a != nil {
		a.Permissions += "x"
	}
	return a, err
}

type redMangleTemplate struct{ ifaceStore }

func (b redMangleTemplate) GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error) {
	t, err := b.ifaceStore.GetSecretTemplateByName(ctx, name)
	if t != nil {
		c := *t
		c.Description += "x"
		return &c, err
	}
	return t, err
}

type redZombieEnv struct{ ifaceStore }

func (b redZombieEnv) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return b.ifaceStore.ListEnvironmentsByProjectIncludingDeleted(ctx, projectID)
}

type redDupAuditRow struct{ ifaceStore }

func (b redDupAuditRow) GetAuditLogs(ctx context.Context, f *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	rows, total, err := b.ifaceStore.GetAuditLogs(ctx, f)
	if f.Page == 2 && len(rows) > 0 {
		rows = append(rows, rows[0])
	}
	return rows, total, err
}

type redStaleCAS struct{ ifaceStore }

func (b redStaleCAS) SetSystemMetadata(context.Context, string, string) error { return nil }

type redOtherTemplateID struct{ ifaceStore }

func (b redOtherTemplateID) GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error) {
	t, err := b.ifaceStore.GetSecretTemplateByName(ctx, name)
	if t != nil {
		c := *t
		c.ID += 7
		return &c, err
	}
	return t, err
}

func redOnlySide(side string, build func(ifaceStore) ifaceStore) func(string, ifaceStore) ifaceStore {
	return func(label string, ls ifaceStore) ifaceStore {
		if label == side {
			return build(ls)
		}
		return ls
	}
}

type redCase struct {
	name       string
	program    []byte
	s1, s2     string
	wrap       func(string, ifaceStore) ifaceStore
	wantSubstr string
}

// TestIfaceRedProof_Metamorphic shows the per-backend relations fire on planted faults
// and stay silent on the control. It runs without Postgres.
func TestIfaceRedProof_Metamorphic(t *testing.T) {
	w := newIfaceWorld(t, false)
	cases := []redCase{
		{"list-after-delete", ifaceProgram(ifaceStep(opIdxEnv, 0, 3, 0), ifaceStep(opIdxEnv, 1, 0, 0)), "dev", "x",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redZombieEnv{ls} }), "deleted environment still in"},
		{"create-then-get", ifaceProgram(ifaceStep(opIdxTemplate, 0, 1, 0)), "t1", "d",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redOtherTemplateID{ls} }), "created template does not read back"},
		{"upsert-then-get", ifaceProgram(ifaceStep(opIdxACL, 0, 1, 0)), "p", "",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redMangleACL{ls} }), "ACL upsert does not read back"},
		{"page-walk-duplicate", ifaceProgram(
			ifaceStep(opIdxAudit, 0, 0, 0), ifaceStep(opIdxAudit, 0, 1, 1), ifaceStep(opIdxAudit, 0, 4, 2),
			ifaceStep(opIdxAudit, 3, 0, 2)), "n", "ip",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redDupAuditRow{ls} }), "audit page walk"},
		{"set-then-get", ifaceProgram(ifaceStep(opIdxSysMeta, 0, 1, 2)), "k", "v",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redStaleCAS{ls} }), "set then get did not return"},
	}
	for _, c := range cases {
		t.Run(c.name+"/control", func(t *testing.T) {
			if msg := ifaceRunSpy(w, c.program, c.s1, c.s2, nil); msg != "" {
				t.Fatalf("control must be silent: %s", msg)
			}
		})
		t.Run(c.name+"/planted", func(t *testing.T) {
			msg := ifaceRunSpy(w, c.program, c.s1, c.s2, c.wrap)
			if !strings.Contains(msg, "METAMORPHIC") || !strings.Contains(msg, c.wantSubstr) {
				t.Fatalf("planted fault not detected as expected, got %q", msg)
			}
			t.Logf("fired: %s", msg)
		})
	}
}

// TestIfaceRedProof_Differential shows the two-backend comparison fires on one broken
// backend, in each comparison shape, and stays silent on the control.
func TestIfaceRedProof_Differential(t *testing.T) {
	w := newIfaceWorld(t, true)
	cases := []redCase{
		{"result-set", ifaceProgram(ifaceStep(opIdxTemplate, 0, 1, 0), ifaceStep(opIdxTemplate, 4, 0, 0)), "t1", "d",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redDropTemplate{ls} }), "Template(mode=4"},
		{"error-class", ifaceProgram(ifaceStep(opIdxRole, 0, 1, 0), ifaceStep(opIdxRole, 3, 0, 1)), "r", "r",
			redOnlySide("postgres", func(ls ifaceStore) ifaceStore { return redWrongClass{ifaceStore: ls, calls: new(int)} }), "Role(mode=3"},
		{"mandatory-order", ifaceProgram(ifaceStep(opIdxChannel, 0, 1, 0), ifaceStep(opIdxChannel, 0, 2, 0), ifaceStep(opIdxChannel, 4, 0, 0)), "c1", "c2",
			redOnlySide("postgres", func(ls ifaceStore) ifaceStore { return redReorderChannels{ls} }), "Channel(mode=4"},
		{"value-field", ifaceProgram(ifaceStep(opIdxTemplate, 0, 1, 0), ifaceStep(opIdxTemplate, 1, 1, 0)), "t", "d",
			redOnlySide("sqlite", func(ls ifaceStore) ifaceStore { return redMangleTemplate{ls} }), "Template(mode=1"},
	}
	for _, c := range cases {
		t.Run(c.name+"/control", func(t *testing.T) {
			if msg := ifaceRunSpy(w, c.program, c.s1, c.s2, nil); msg != "" {
				t.Fatalf("control must be silent: %s", msg)
			}
		})
		t.Run(c.name+"/planted", func(t *testing.T) {
			msg := ifaceRunSpy(w, c.program, c.s1, c.s2, c.wrap)
			if !strings.Contains(msg, c.wantSubstr) {
				t.Fatalf("planted fault not detected, got %q", msg)
			}
			t.Logf("fired: %s", msg)
		})
	}
}

// TestIfacePositiveControl_IntendedDifferencesAreClassified drives scenarios known to
// differ legitimately on real backends and asserts they are classified by the table
// and not reported, and that removing the table row turns them into a divergence.
func TestIfacePositiveControl_IntendedDifferencesAreClassified(t *testing.T) {
	w := newIfaceWorld(t, true)
	if !w.pgCtypeC {
		t.Skip("FOLD-CTYPE-C control needs a C-ctype PG database; this server is not one")
	}

	// VARCHAR-LENGTH: one backend enforces size:64, the other does not. The op label
	// carries overlong=, so the rule applies; the fuzz stream truncates and never does.
	run := func(rules []ifaceDiffRule, fn func(e *ifaceExec, spy *ifaceFatalSpy)) string {
		saved := ifaceIntendedDiffs
		ifaceIntendedDiffs = rules
		defer func() { ifaceIntendedDiffs = saved }()
		spy := &ifaceFatalSpy{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			w.reset(spy, nil)
			e := &ifaceExec{t: spy, w: w, ctx: context.Background(), pool: ifaceStringPool}
			fn(e, spy)
		}()
		<-done
		return spy.fatal
	}
	overlong := strings.Repeat("k", 65)
	varcharOp := func(e *ifaceExec, _ *ifaceFatalSpy) {
		e.both("LoginAttemptReserve(overlong=65)", func(s *ifaceSide) string {
			_, err := s.ls.ReserveLoginAttempt(e.ctx, "10.0.0.1", ifacePastBase, overlong)
			return ifaceClass(err)
		})
		if !e.stopped {
			t.Errorf("VARCHAR-LENGTH must stop the program (the backends hold different rows)")
		}
	}
	if msg := run(ifaceIntendedDiffs, varcharOp); msg != "" {
		t.Fatalf("VARCHAR-LENGTH difference must be classified, got: %s", msg)
	}
	if msg := run(nil, varcharOp); !strings.Contains(msg, "BACKEND DIVERGENCE") {
		t.Fatalf("without the table row the same difference must be reported, got %q", msg)
	}

	// FOLD-CTYPE-C: a stored non-ASCII name found by a case variant on SQLite only.
	foldOp := func(e *ifaceExec, _ *ifaceFatalSpy) {
		term := "äö"
		e.both("AuditFold(foldterm="+term+")", func(s *ifaceSide) string {
			uid := s.user(e, 0)
			_ = uid
			err := s.ls.LogAuditEvent(e.ctx, &models.AuditEvent{EventType: "user.login", UserID: &uid, EventTime: ifacePastBase.Add(time.Second)})
			if err != nil {
				return "log:" + ifaceClass(err)
			}
			return "logged"
		})
		e.both("AuditFold2(foldterm="+term+")", func(s *ifaceSide) string {
			// Stored display name in NFC upper case, searched in lower case.
			if err := s.db.Exec("UPDATE users SET username = ? WHERE username = ?", "ÄÖ", "u0").Error; err != nil {
				return "rename:" + ifaceClass(err)
			}
			return s.auditWalk(e, &storage.AuditFilter{ActorUsername: &term})
		})
	}
	if msg := run(ifaceIntendedDiffs, foldOp); msg != "" {
		t.Fatalf("FOLD-CTYPE-C difference must be classified, got: %s", msg)
	}
	if msg := run(nil, foldOp); !strings.Contains(msg, "BACKEND DIVERGENCE") {
		t.Fatalf("without the table row the same difference must be reported, got %q", msg)
	}
}
