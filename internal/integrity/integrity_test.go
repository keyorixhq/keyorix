package integrity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeVerity struct {
	on  bool
	err error
}

func (f fakeVerity) Enabled(string) (bool, error) { return f.on, f.err }

// fakeRoot writes files (slash-separated path -> content) under a temp root.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// dirAt makes rel a directory, so reading it fails with a non-ErrNotExist
// error: the portable stand-in for "exists but unreadable".
func dirAt(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(rel)), 0o750); err != nil {
		t.Fatal(err)
	}
}

func linuxEnv(root string) Env {
	return Env{
		Root:           root,
		GOOS:           "linux",
		Executable:     func() (string, error) { return filepath.Join(root, "bin", "keyorix-server"), nil },
		FSVerity:       fakeVerity{},
		KeylimePresent: func() (bool, error) { return false, nil },
	}
}

func lineOf(r Report, id string) Line {
	for _, l := range r.Lines {
		if l.ID == id {
			return l
		}
	}
	return Line{}
}

// hasLabel is the calibration predicate for the advisory label.
func hasLabel(s string) bool { return strings.Contains(s, "["+Label) }

func TestSecureBoot(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  State
	}{
		{"ok", func(t *testing.T, r string) { writeFile(t, r, secureBootVar, "\x07\x00\x00\x00\x01") }, StateOK},
		{"degraded", func(t *testing.T, r string) { writeFile(t, r, secureBootVar, "\x07\x00\x00\x00\x00") }, StateDegraded},
		{"absent is unknown", func(*testing.T, string) {}, StateUnknown},
		{"truncated is unknown", func(t *testing.T, r string) { writeFile(t, r, secureBootVar, "\x07") }, StateUnknown},
		{"odd value is unknown", func(t *testing.T, r string) { writeFile(t, r, secureBootVar, "\x07\x00\x00\x00\x02") }, StateUnknown},
		{"unreadable is unknown", func(t *testing.T, r string) { dirAt(t, r, secureBootVar) }, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.setup(t, root)
			if got := lineOf(Collect(linuxEnv(root)), CheckSecureBoot).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLockdown(t *testing.T) {
	const p = "sys/kernel/security/lockdown"
	cases := []struct {
		name    string
		content *string
		dir     bool
		want    State
	}{
		{"integrity", ptr("none [integrity] confidentiality\n"), false, StateOK},
		{"confidentiality", ptr("none integrity [confidentiality]\n"), false, StateOK},
		{"none", ptr("[none] integrity confidentiality\n"), false, StateDegraded},
		{"absent", nil, false, StateUnknown},
		{"garbled", ptr("???"), false, StateUnknown},
		{"unreadable", nil, true, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.content != nil {
				writeFile(t, root, p, *c.content)
			}
			if c.dir {
				dirAt(t, root, p)
			}
			if got := lineOf(Collect(linuxEnv(root)), CheckLockdown).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestIMA(t *testing.T) {
	const p = "sys/kernel/security/ima/policy"
	cases := []struct {
		name    string
		content *string
		dir     bool
		want    State
	}{
		{"appraise", ptr("measure func=BPRM_CHECK\nappraise func=BPRM_CHECK appraise_type=imasig\n"), false, StateOK},
		{"measure only", ptr("measure func=BPRM_CHECK\n"), false, StateDegraded},
		{"empty", ptr(""), false, StateDegraded},
		{"dont_appraise alone does not count", ptr("dont_appraise fsmagic=0x9fa0\n"), false, StateDegraded},
		{"absent", nil, false, StateUnknown},
		{"unreadable", nil, true, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.content != nil {
				writeFile(t, root, p, *c.content)
			}
			if c.dir {
				dirAt(t, root, p)
			}
			if got := lineOf(Collect(linuxEnv(root)), CheckIMA).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func TestFSVerity(t *testing.T) {
	cases := []struct {
		name string
		v    fakeVerity
		want State
	}{
		{"ok", fakeVerity{on: true}, StateOK},
		{"degraded", fakeVerity{on: false}, StateDegraded},
		{"ioctl error is unknown", fakeVerity{err: errors.New("ENOTTY")}, StateUnknown},
		{"error wins over a true answer", fakeVerity{on: true, err: errors.New("EIO")}, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := linuxEnv(t.TempDir())
			env.FSVerity = c.v
			if got := lineOf(Collect(env), CheckFSVerity).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
	t.Run("executable path error is unknown", func(t *testing.T) {
		env := linuxEnv(t.TempDir())
		env.Executable = func() (string, error) { return "", errors.New("no exe") }
		if got := lineOf(Collect(env), CheckFSVerity).State; got != StateUnknown {
			t.Fatalf("state = %q", got)
		}
	})
}

func TestManifest(t *testing.T) {
	const content = "pretend binary"
	setup := func(t *testing.T, manifest *string, sig string) Env {
		root := t.TempDir()
		exe := filepath.Join(root, "bin", "keyorix-server")
		writeFile(t, root, "bin/keyorix-server", content)
		if manifest != nil {
			writeFile(t, root, "bin/checksums.txt", *manifest)
		}
		if sig != "" {
			writeFile(t, root, "bin/"+sig, "sig")
		}
		env := linuxEnv(root)
		env.Executable = func() (string, error) { return exe, nil }
		return env
	}
	realHash := func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), "x")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := hashFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	t.Run("no manifest is not checked", func(t *testing.T) {
		if got := lineOf(Collect(setup(t, nil, "")), CheckManifest).State; got != StateNotChecked {
			t.Fatalf("state = %q", got)
		}
	})
	t.Run("unsigned manifest is not checked", func(t *testing.T) {
		m := realHash(t) + "  keyorix-server\n"
		if got := lineOf(Collect(setup(t, &m, "")), CheckManifest).State; got != StateNotChecked {
			t.Fatalf("state = %q", got)
		}
	})
	t.Run("match is ok", func(t *testing.T) {
		m := "deadbeef  other\n" + realHash(t) + "  keyorix-server\n"
		l := lineOf(Collect(setup(t, &m, "checksums.txt.sig")), CheckManifest)
		if l.State != StateOK || !strings.Contains(l.Detail, "NOT verified") {
			t.Fatalf("line = %+v", l)
		}
	})
	t.Run("mismatch is degraded", func(t *testing.T) {
		m := strings.Repeat("ab", 32) + "  keyorix-server\n"
		if got := lineOf(Collect(setup(t, &m, "checksums.txt.sig")), CheckManifest).State; got != StateDegraded {
			t.Fatalf("state = %q", got)
		}
	})
	t.Run("unreadable manifest is unknown", func(t *testing.T) {
		env := setup(t, nil, "checksums.txt.sig")
		exe, _ := env.Executable()
		dirAt(t, filepath.Dir(filepath.Dir(exe)), "bin/checksums.txt")
		if got := lineOf(Collect(env), CheckManifest).State; got != StateUnknown {
			t.Fatalf("state = %q", got)
		}
	})
}

func TestTPM(t *testing.T) {
	cases := []struct {
		name string
		tpm  TPMState
		want State
	}{
		{"ok", TPMState{Configured: true, BlobPresent: true}, StateOK},
		{"not configured", TPMState{}, StateDegraded},
		{"no blob yet", TPMState{Configured: true}, StateDegraded},
		{"blob unreadable", TPMState{Configured: true, BlobErr: errors.New("EACCES")}, StateUnknown},
		{"blob err wins over present", TPMState{Configured: true, BlobPresent: true, BlobErr: errors.New("EIO")}, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := linuxEnv(t.TempDir())
			env.TPM = c.tpm
			if got := lineOf(Collect(env), CheckTPMSealing).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func TestKeylime(t *testing.T) {
	cases := []struct {
		name string
		fn   func() (bool, error)
		want State
	}{
		{"ok", func() (bool, error) { return true, nil }, StateOK},
		{"degraded", func() (bool, error) { return false, nil }, StateDegraded},
		{"unreadable", func() (bool, error) { return false, errors.New("EACCES") }, StateUnknown},
		{"error wins over true", func() (bool, error) { return true, errors.New("EIO") }, StateUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := linuxEnv(t.TempDir())
			env.KeylimePresent = c.fn
			if got := lineOf(Collect(env), CheckKeylime).State; got != c.want {
				t.Fatalf("state = %q, want %q", got, c.want)
			}
		})
	}
}

func TestKeylimeProcScan(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"proc/1/comm":    "systemd\n",
		"proc/42/comm":   "keylime_agent\n",
		"proc/self/comm": "keylime_agent\n", // not a pid dir: ignored
	})
	if on, err := keylimeInProc(root); err != nil || !on {
		t.Fatalf("on=%v err=%v", on, err)
	}
	none := fakeRoot(t, map[string]string{"proc/1/comm": "systemd\n"})
	if on, err := keylimeInProc(none); err != nil || on {
		t.Fatalf("on=%v err=%v", on, err)
	}
	if _, err := keylimeInProc(t.TempDir()); err == nil {
		t.Fatal("a missing /proc must be an error (unknown), not 'absent'")
	}
}

func TestNonLinuxIsNotApplicable(t *testing.T) {
	root := fakeRoot(t, map[string]string{secureBootVar: "\x07\x00\x00\x00\x01"})
	env := linuxEnv(root)
	env.GOOS = "darwin"
	r := Collect(env)
	for _, id := range []string{CheckSecureBoot, CheckLockdown, CheckIMA, CheckFSVerity, CheckKeylime} {
		if got := lineOf(r, id).State; got != StateNotApplicable {
			t.Errorf("%s = %q, want not applicable (a fake tree must not make a non-Linux host look secure)", id, got)
		}
	}
	if r.Tier != 0 {
		t.Errorf("tier = %d, want 0", r.Tier)
	}
}

// TestEveryLineCarriesTheAdvisoryLabel is the calibration case for the label:
// every line, in every state, ends with it. The last subtest proves the
// predicate goes red when the label is dropped.
func TestEveryLineCarriesTheAdvisoryLabel(t *testing.T) {
	states := []Env{
		linuxEnv(t.TempDir()), // everything absent/unknown/degraded
		func() Env {
			root := fakeRoot(t, map[string]string{
				secureBootVar:                    "\x07\x00\x00\x00\x01",
				"sys/kernel/security/lockdown":   "none [integrity] confidentiality",
				"sys/kernel/security/ima/policy": "appraise func=BPRM_CHECK\n",
			})
			e := linuxEnv(root)
			e.FSVerity = fakeVerity{on: true}
			e.TPM = TPMState{Configured: true, BlobPresent: true}
			e.KeylimePresent = func() (bool, error) { return true, nil }
			return e
		}(),
		func() Env { e := linuxEnv(t.TempDir()); e.GOOS = "darwin"; return e }(),
	}
	for i, env := range states {
		r := Collect(env)
		if len(r.Lines) != 7 {
			t.Fatalf("env %d: %d lines, want 7", i, len(r.Lines))
		}
		out := r.Strings()
		if len(out) != 8 {
			t.Fatalf("env %d: %d rendered lines, want 8 (7 + tier)", i, len(out))
		}
		for _, s := range out {
			if !hasLabel(s) {
				t.Errorf("env %d: line lacks %q: %s", i, Label, s)
			}
			if !strings.Contains(s, DocsPath) {
				t.Errorf("env %d: line lacks the docs link: %s", i, s)
			}
		}
	}
	t.Run("calibration: the predicate rejects a dropped label", func(t *testing.T) {
		for _, l := range Collect(linuxEnv(t.TempDir())).Lines {
			dropped := strings.ReplaceAll(l.String(), Label, "")
			if hasLabel(dropped) {
				t.Errorf("%s: predicate still passes without the label", l.ID)
			}
		}
	})
}

// TestEachCheckLineStringIsLabelled makes the label requirement per line id,
// so dropping it from one check's rendering names that check.
func TestEachCheckLineStringIsLabelled(t *testing.T) {
	for _, l := range Collect(linuxEnv(t.TempDir())).Lines {
		if !hasLabel(l.String()) {
			t.Errorf("%s: rendered line lacks the advisory label", l.ID)
		}
	}
}
