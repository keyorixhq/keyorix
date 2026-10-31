package pgpriv

import (
	"errors"
	"testing"
)

// fakeTB records Skip/Fatal instead of ending the goroutine.
type fakeTB struct {
	testing.TB
	skipped, failed bool
	msg             string
}

func (f *fakeTB) Helper()              {}
func (f *fakeTB) Skipf(string, ...any) {}
func (f *fakeTB) Skip(args ...any) {
	f.skipped = true
	f.msg = args[0].(string)
	panic(f) // stop like runtime.Goexit would
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = format
	panic(f)
}

func run(probe func() error, env map[string]string) (f *fakeTB) {
	f = &fakeTB{}
	defer func() { _ = recover() }()
	requireWith(f, probe, func(k string) string { return env[k] })
	return f
}

var denied = func() error { return errors.New(`permission denied to set parameter "session_replication_role"`) }

func TestRequireWith_PrivilegedRoleContinues(t *testing.T) {
	f := run(func() error { return nil }, map[string]string{"CI": "true"})
	if f.skipped || f.failed {
		t.Fatalf("privileged role must neither skip nor fail: %+v", f)
	}
}

func TestRequireWith_UnprivilegedLocalSkipsNamingThePrivilege(t *testing.T) {
	f := run(denied, nil)
	if !f.skipped || f.failed {
		t.Fatalf("want skip, got %+v", f)
	}
	for _, want := range []string{"session_replication_role", "SUPERUSER", EnvRequire} {
		if !contains(f.msg, want) {
			t.Errorf("skip message %q does not mention %q", f.msg, want)
		}
	}
}

func TestRequireWith_UnprivilegedFailsInCIOrWhenRequired(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"CI=true":     {"CI": "true"},
		"require env": {EnvRequire: "1"},
	} {
		f := run(denied, env)
		if !f.failed || f.skipped {
			t.Errorf("%s: want fatal, got %+v", name, f)
		}
	}
	// Only the exact values count: CI=false must still skip.
	if f := run(denied, map[string]string{"CI": "false", EnvRequire: "0"}); !f.skipped {
		t.Errorf("CI=false / require=0 must skip, got %+v", f)
	}
}

func TestCachedProbe_RunsOnce(t *testing.T) {
	probeMu.Lock()
	probeDone, probeResult = false, nil
	probeMu.Unlock()
	t.Cleanup(func() {
		probeMu.Lock()
		probeDone, probeResult = false, nil
		probeMu.Unlock()
	})
	n := 0
	p := cachedProbe(func() error { n++; return denied() })
	_ = p()
	_ = p()
	if n != 1 {
		t.Fatalf("probe ran %d times, want 1", n)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
