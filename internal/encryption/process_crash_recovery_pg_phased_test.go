//go:build !windows

package encryption_test

// process_crash_recovery_pg_phased_test.go -- one exec of the PostgreSQL sweep
// split over several test runs, for a link slow enough that an exec does not fit
// in one run's time limit (-args -pcrash.phased). Each run does the exec's next
// phase and keeps the install directory and database under -pcrash.world:
//
//	death   kill the operation and classify the result
//	reopen  the first half of the SQLite leg's checkAfterDeath (I1 to I4)
//	rerun   its second half, checkRerun (I5)
//
// A phase that a time limit cut off may have changed the install, so its exec
// starts over from a new copy rather than being judged.
//
// What this does not model: anything between the phases. The install is at rest
// and the server has no client for it, which is the state a restart meets anyway.

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// pcrashPGPhaseFile is the state a finished phase leaves for the next one.
type pcrashPGPhaseFile struct {
	Dir, DB, Label, State string
	Pending               bool
	Reopened              bool
	Working               string
	AfterKill             *pcrashModel
}

type pcrashPGPhased struct {
	w          *pcrashPGWorld
	root       string
	op         pcrashOp
	mode       string
	killAt     int64
	st         pcrashExecState
	after      *pcrashModel
	state      pcrashPGPhaseFile
	statePath  string
	markerPath string
}

func (p *pcrashPGPhased) discard() {
	_ = p.w.srv.dropDB(context.Background(), p.state.DB)
	_ = os.RemoveAll(p.root)
}

func (p *pcrashPGPhased) save(t *testing.T) {
	t.Helper()
	b, err := json.Marshal(p.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.statePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (p *pcrashPGPhased) mark(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(p.markerPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (p *pcrashPGPhased) finish(t *testing.T, v []string) {
	t.Helper()
	pcrashOutcome{backend: "postgres", op: p.op.name, mode: p.mode, killAt: p.killAt, label: p.state.Label, state: p.state.State, pending: p.state.Pending}.record(v)
	p.discard()
	if len(v) > 0 {
		t.Errorf("%s", strings.Join(v, "; "))
	}
}

// execPhased runs this exec's remaining phases, starting another only while the
// run is younger than -pcrash.budget.
func (w *pcrashPGWorld) execPhased(t *testing.T, op pcrashOp, killAt int64, mode string, began time.Time) {
	t.Helper()
	root := filepath.Join(*pcrashFlagWorld, "phased", fmt.Sprintf("%s-%s-%d", op.name, mode, killAt))
	p := &pcrashPGPhased{w: w, root: root, op: op, mode: mode, killAt: killAt, statePath: filepath.Join(root, "state.json"), markerPath: filepath.Join(root, "phase-started")}
	p.st = w.prepareCached(t)
	p.after = w.afterModel(t, op, p.st)
	b, err := os.ReadFile(p.statePath) //nolint:gosec // test-chosen path
	switch {
	case errors.Is(err, os.ErrNotExist):
		_ = os.RemoveAll(root) // an earlier death phase that a time limit cut off
	case err != nil:
		t.Fatal(err)
	default:
		if err := json.Unmarshal(b, &p.state); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p.markerPath); err == nil {
			t.Logf("a time limit cut off an earlier phase; starting over")
			p.discard()
			p.state = pcrashPGPhaseFile{}
		}
	}
	for {
		switch {
		case p.state.DB == "":
			if !w.deathPhase(t, p) {
				return
			}
		case !p.state.Reopened:
			if !w.reopenPhase(t, p) {
				return
			}
		default:
			p.mark(t)
			p.finish(t, w.checkRerun(t, op, p.state.Dir, p.state.Working, p.st, p.after, p.state.AfterKill))
			return
		}
		if b := *pcrashFlagBudget; b > 0 && time.Since(began) > b {
			return // the next run does the next phase
		}
	}
}

func (w *pcrashPGWorld) deathPhase(t *testing.T, p *pcrashPGPhased) bool {
	t.Helper()
	dir := filepath.Join(p.root, "inst")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy install: %v", err)
	}
	name := pcrashPGName("p")
	if err := w.srv.createDB(context.Background(), name, w.templateDB); err != nil {
		t.Fatalf("clone database: %v", pcrashPGScrub(err, w.srv.password))
	}
	p.state = pcrashPGPhaseFile{Dir: dir, DB: name}
	// A skip here is a dropped link; the exec is done again from a new copy.
	defer func() {
		if t.Skipped() {
			p.discard()
		}
	}()
	inst := &pcrashPGInst{dir: dir, db: name, yaml: w.yamlFor(name)}
	if err := inst.restoreYAML(); err != nil {
		t.Fatal(err)
	}
	d, v := w.die(t, inst, p.op, p.killAt, p.mode, p.st, p.after)
	p.state.Label = d.label
	if len(v) > 0 {
		p.state.State = "refused"
		p.finish(t, v)
		return false
	}
	p.state.State, p.state.Pending = d.state, d.pending
	p.save(t)
	return true
}

// reopenPhase is checkAfterDeath's first half (process_crash_recovery_fuzz_test.go),
// copied so the exec can stop before the rerun: I1 to I4, in the same order and
// with the same messages. A change to one needs the same change to the other.
// Two differences, neither weakening a check: die has already run the restore
// journal's recovery, and with one passphrase the install stays open for the
// checks rather than being opened again for them.
func (w *pcrashPGWorld) reopenPhase(t *testing.T, p *pcrashPGPhased) bool {
	t.Helper()
	p.mark(t)
	violations := func(v ...string) bool { p.finish(t, v); return false }
	st, after, op := p.st, p.after, p.op
	passes := []string{pcrashPass}
	if op.kek {
		passes = []string{pcrashPass, pcrashPass2}
	}
	if op.passes != nil {
		passes = op.passes
	}
	var (
		working []string
		v       []string
		o       pcrashOpened
	)
	for _, pass := range passes {
		a := pcrashOpenGuarded(p.state.Dir, pass)
		if a.pnc != nil {
			return violations(fmt.Sprintf("I1 reopen panicked: %v", a.pnc))
		}
		if a.err != nil && !pcrashExplicitOpenError(a.err) {
			return violations(fmt.Sprintf("I1 reopen failed without a documented refusal: %v", a.err))
		}
		if a.err != nil {
			continue
		}
		working = append(working, pass)
		if len(passes) == 1 {
			o = a
		} else {
			a.inst.close() // an open install holds the key lock
		}
	}
	if op.kek && len(working) != 1 {
		v = append(v, fmt.Sprintf("I3 rotate-kek: %d passphrases open the install after the kill, want exactly 1", len(working)))
	}
	if len(working) == 0 {
		return violations(append(v, "I1 no passphrase opens the install after the kill")...)
	}
	if o.inst == nil {
		if o = pcrashOpenGuarded(p.state.Dir, working[0]); o.pnc != nil || o.err != nil {
			return violations(append(v, fmt.Sprintf("I1 reopen with the working passphrase failed: panic=%v err=%v", o.pnc, o.err))...)
		}
	}
	defer o.inst.close()
	if op.name == "rotate-dek" {
		cipher, err := o.inst.ciphertexts()
		if err != nil {
			return violations(append(v, "I3 read ciphertexts: "+err.Error())...)
		}
		changed := 0
		for id, c := range st.cipher {
			if cipher[id] != c {
				changed++
			}
		}
		if changed != 0 && changed != len(st.cipher) {
			return violations(append(v, fmt.Sprintf("I3 rotate-dek left a half-rotated set: %d of %d stored versions changed", changed, len(st.cipher)))...)
		}
	}
	m, err := o.inst.observe(context.Background(), w.seed)
	if err != nil {
		return violations(append(v, "I3 observe after the kill: "+err.Error())...)
	}
	ledgerBefore, ledgerAfter := reflect.DeepEqual(m.Ledger, st.before.Ledger), reflect.DeepEqual(m.Ledger, after.Ledger)
	if !ledgerAfter {
		for name, values := range st.before.Ledger {
			if !reflect.DeepEqual(m.Ledger[name], values) {
				v = append(v, fmt.Sprintf("I2 secret %q changed: have %q, want %q", name, m.Ledger[name], values))
			}
		}
	}
	if !ledgerBefore && !ledgerAfter {
		v = append(v, fmt.Sprintf("I3 ledger is neither before nor after: have %v, before %v, after %v", m.Ledger, st.before.Ledger, after.Ledger))
	}
	if !reflect.DeepEqual(m.Roles, st.before.Roles) && !reflect.DeepEqual(m.Roles, after.Roles) {
		v = append(v, fmt.Sprintf("I3 roles are neither before nor after: have %v", m.Roles))
	}
	if !reflect.DeepEqual(m.Authz, st.before.Authz) && !reflect.DeepEqual(m.Authz, after.Authz) {
		v = append(v, fmt.Sprintf("I4 authorization is neither before nor after: vs before %v, vs after %v", pcrashAuthzDiff(m.Authz, st.before.Authz), pcrashAuthzDiff(m.Authz, after.Authz)))
	}
	if len(v) > 0 {
		return violations(v...)
	}
	p.state.Reopened, p.state.Working, p.state.AfterKill = true, working[0], m
	p.save(t)
	if err := os.Remove(p.markerPath); err != nil {
		t.Fatal(err)
	}
	return true
}
