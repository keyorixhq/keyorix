package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// snapshotTree returns relative path -> content for every regular file under
// root, so a test can assert that a refused run left the tree byte-identical.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			out[rel] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTreeUnchanged(t *testing.T, root string, before map[string]string) {
	t.Helper()
	after := snapshotTree(t, root)
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Errorf("%s was removed", name)
		} else if got != want {
			t.Errorf("%s changed: %d bytes -> %d bytes", name, len(want), len(got))
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("%s was created", name)
		}
	}
}

// sourceTree is a toy module copy standing in for a real checkout. The marker is
// removed so it looks like a directory this tool did not create.
func sourceTree(t *testing.T) string {
	t.Helper()
	root := toyModuleCopy(t)
	if err := os.Remove(filepath.Join(root, copyMarker)); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestRun_RefusesOverlappingSrcWork: -work equal to, inside, or containing -src
// used to truncate the source files or copy the work dir into itself until the
// path was too long. run() must refuse and leave the source tree untouched.
func TestRun_RefusesOverlappingSrcWork(t *testing.T) {
	cases := []struct {
		name string
		work func(src string) string
	}{
		{"work equals src", func(src string) string { return src }},
		{"work inside src", func(src string) string { return filepath.Join(src, "zz", "copy") }},
		{"src inside work", func(src string) string { return filepath.Dir(src) }},
		{"work is a symlink to src", func(src string) string {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(src, link); err != nil {
				t.Skipf("symlink: %v", err)
			}
			return link
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The source tree sits in its own parent so "src inside work" cannot
			// reach unrelated files.
			parent := t.TempDir()
			src := filepath.Join(parent, "src")
			if err := copyModule(toyModuleCopy(t), src); err != nil {
				t.Fatal(err)
			}
			before := snapshotTree(t, src)
			err := run(options{src: src, work: tc.work(src), pkg: ".", targets: "FuzzNoop"})
			if err == nil {
				t.Fatal("run() accepted overlapping -src/-work, want an error")
			}
			assertTreeUnchanged(t, src, before)
		})
	}
}

// TestRun_RefusesNonEmptyWorkWithoutMarker: a reused -work must be a previous
// copy of this tool, not an arbitrary directory.
func TestRun_RefusesNonEmptyWorkWithoutMarker(t *testing.T) {
	src := sourceTree(t)
	work := t.TempDir()
	keep := filepath.Join(work, "precious.txt")
	if err := os.WriteFile(keep, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(options{src: src, work: work, pkg: ".", targets: "FuzzNoop"}); err == nil {
		t.Fatal("run() accepted a non-empty -work without marker, want an error")
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "do not touch" {
		t.Fatalf("precious file changed: %q, %v", b, err)
	}
}

// TestRun_RefusesModuleWithoutCopyMarker: -module mutates in place, so it may
// only point at a copy this tool made, never at a checkout.
func TestRun_RefusesModuleWithoutCopyMarker(t *testing.T) {
	t.Run("no marker", func(t *testing.T) {
		mod := sourceTree(t)
		before := snapshotTree(t, mod)
		if err := run(options{module: mod, pkg: ".", targets: "FuzzWeak", fuzztime: time.Second}); err == nil {
			t.Fatal("run() accepted -module without marker, want an error")
		}
		assertTreeUnchanged(t, mod, before)
	})
	t.Run("contains .git", func(t *testing.T) {
		mod := toyModuleCopy(t) // has the marker
		if err := os.Mkdir(filepath.Join(mod, ".git"), 0o750); err != nil {
			t.Fatal(err)
		}
		before := snapshotTree(t, mod)
		if err := run(options{module: mod, pkg: ".", targets: "FuzzWeak", fuzztime: time.Second}); err == nil {
			t.Fatal("run() accepted -module containing .git, want an error")
		}
		assertTreeUnchanged(t, mod, before)
	})
	t.Run("copy made by copyModule is accepted", func(t *testing.T) {
		mod := toyModuleCopy(t)
		if err := checkModuleDir(mod); err != nil {
			t.Fatalf("checkModuleDir rejected a copyModule copy: %v", err)
		}
	})
}

// TestCopyModule_SymlinksAndModes: a symlink to a file outside the module must
// not be copied into the scratch tree, and copies are owner-only.
func TestCopyModule_SymlinksAndModes(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.go"), []byte("package a\n"), 0o644); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "leak.key")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink("a.go", filepath.Join(src, "inside.go")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if err := copyModule(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "leak.key")); err == nil {
		t.Error("symlink to a file outside src was copied")
	}
	for _, name := range []string{"a.go", "inside.go", copyMarker} {
		fi, err := os.Stat(filepath.Join(dst, name))
		if err != nil {
			t.Errorf("%s not copied: %v", name, err)
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %v grants group/other access", name, fi.Mode().Perm())
		}
	}
}

func TestSelectMutations_DeterministicAndCapped(t *testing.T) {
	all := make([]Mutation, 50)
	for i := range all {
		all[i].Line = i
	}
	a := selectMutations(all, 10, 7)
	b := selectMutations(all, 10, 7)
	if len(a) != 10 || len(b) != 10 {
		t.Fatalf("len = %d, %d, want 10", len(a), len(b))
	}
	for i := range a {
		if a[i].Line != b[i].Line {
			t.Fatalf("same seed gave different samples at %d", i)
		}
		if i > 0 && a[i].Line <= a[i-1].Line {
			t.Fatalf("sample not in sorted order: %v", a)
		}
	}
	c := selectMutations(all, 10, 8)
	same := true
	for i := range a {
		if a[i].Line != c[i].Line {
			same = false
		}
	}
	if same {
		t.Error("different seeds produced the identical sample")
	}
}

// TestRunFuzz_CanceledContextIsNotKilled: an interrupted run used to be counted
// as KILLED (non-zero exit, not a deadline) and the report was still written.
func TestRunFuzz_CanceledContextIsNotKilled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzzing integration test in -short mode")
	}
	root := toyModuleCopy(t)
	env := Env{ModuleRoot: root, FuzzTime: 30 * time.Second, Parallel: 1, Nice: 10, GOMAXPROCS: 2}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(2*time.Second, cancel)
	start := time.Now()
	verdict, detail := env.runFuzz(ctx, "FuzzWeak")
	if verdict == Killed {
		t.Errorf("canceled run reported KILLED:\n%s", detail)
	}
	if verdict != Error {
		t.Errorf("verdict = %s, want %s", verdict, Error)
	}
	if d := time.Since(start); d > 25*time.Second {
		t.Errorf("cancel took %v to take effect; the process group was not killed", d)
	}
}

// TestRun_InterruptedWritesNoReportAndFails: the whole run must return an error
// and write no -out file when its context is canceled.
func TestRun_InterruptedWritesNoReportAndFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzzing integration test in -short mode")
	}
	mod := toyModuleCopy(t)
	out := filepath.Join(t.TempDir(), "int.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(3*time.Second, cancel)
	err := runCtx(ctx, options{
		module: mod, pkg: ".", targets: "FuzzWeak", funcs: "Max",
		fuzztime: 30 * time.Second, max: 1, seed: 3, parallel: 1, nice: 10, gomaxp: 2, out: out,
	})
	if err == nil {
		t.Fatal("interrupted run returned nil, want an error")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("interrupted run wrote a report")
	}
}

// TestRunFuzz_NonOracleFailureIsNotKilled: a non-zero exit that is not the
// target failing (here a TestMain that exits 3) says nothing about the oracle.
func TestRunFuzz_NonOracleFailureIsNotKilled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzzing integration test in -short mode")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module exit3\n\ngo 1.21\n",
		"x.go":   "package exit3\n\nfunc F(a int) int { return a }\n",
		"x_test.go": `package exit3

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(3) }

func FuzzX(f *testing.F) {
	f.Add(1)
	f.Fuzz(func(t *testing.T, a int) { _ = F(a) })
}
`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := Env{ModuleRoot: dir, FuzzTime: 3 * time.Second, Parallel: 1, Nice: 10, GOMAXPROCS: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	verdict, detail := env.runFuzz(ctx, "FuzzX")
	if verdict == Killed {
		t.Errorf("non-oracle failure reported KILLED:\n%s", detail)
	}
	if verdict != Error {
		t.Errorf("verdict = %s, want %s\n%s", verdict, Error, detail)
	}
}

// TestBaselineGreen_MissingTargetIsNotGreen: `go test -run ^Typo$` exits 0 with
// "no tests to run"; that must not count as a green baseline.
func TestBaselineGreen_MissingTargetIsNotGreen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go test integration in -short mode")
	}
	env := Env{ModuleRoot: toyModuleCopy(t), Nice: 10, GOMAXPROCS: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if ok, _ := env.baselineGreen(ctx, "FuzzTypo"); ok {
		t.Error("baseline reported green for a target that does not exist")
	}
	if ok, detail := env.baselineGreen(ctx, "FuzzWeak"); !ok {
		t.Errorf("baseline not green for an existing target:\n%s", detail)
	}
}
