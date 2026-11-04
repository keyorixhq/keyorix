package docsdrift

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// INSTALL-AI-TAILS-1 item 2: docs/install/offline-install.sh setup refuses a
// password inside --postgres-dsn in every spelling, URL and key/value form, in
// any letter case. The script is run for real with stub binaries; the refusal
// happens before anything is created, so the stubs only have to exist.

func TestOfflineInstallRefusesPasswordInPostgresDSN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("offline-install.sh is a POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	script := filepath.Join(repoRoot(t), "docs", "install", "offline-install.sh")

	bin := t.TempDir()
	for _, name := range []string{"keyorix", "keyorix-server"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	run := func(dsn string) (string, error) {
		home := t.TempDir()
		cmd := exec.Command(sh, script, "setup", "--bin-dir", bin, "--admin-email", "a@example.com",
			"--dir", filepath.Join(home, "kx"), "--postgres-dsn", dsn)
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	refused := []string{
		// key/value form, any case
		"host=h user=u dbname=d password=hunter2",
		"host=h user=u dbname=d Password=hunter2",
		"host=h user=u dbname=d PASSWORD=hunter2",
		"host=h user=u dbname=d password = hunter2",
		"host=h user=u dbname=d pwd=hunter2",
		"host=h user=u dbname=d PWD=hunter2",
		"host=h user=u dbname=d Pwd = hunter2",
		"host=h user=u dbname=d passwd=hunter2",
		// URL form, userinfo and query string
		"postgres://u:hunter2@h/d",
		"postgresql://u:hunter2@h:5432/d?sslmode=verify-full",
		"postgres://u@h/d?Password=hunter2",
		"postgres://u@h/d?PASSWORD=hunter2",
		"postgres://u@h/d?sslmode=verify-full&PWD=hunter2",
	}
	for _, dsn := range refused {
		out, err := run(dsn)
		if err == nil {
			t.Errorf("--postgres-dsn %q was accepted", dsn)
			continue
		}
		if !strings.Contains(out, "must not contain the password") {
			t.Errorf("--postgres-dsn %q failed for another reason: %s", dsn, out)
		}
		if strings.Contains(out, "hunter2") {
			t.Errorf("--postgres-dsn %q: the refusal echoes the password: %s", dsn, out)
		}
	}

	// Green: a password-free DSN gets past the check (and stops at the missing
	// secrets/db_password, the next step).
	for _, dsn := range []string{
		"host=h user=u dbname=d sslmode=verify-full sslrootcert=/etc/ca.pem",
		"postgres://u@h:5432/d?sslmode=verify-full",
	} {
		out, err := run(dsn)
		if err == nil || !strings.Contains(out, "needs the database password") || strings.Contains(out, "must not contain") {
			t.Errorf("--postgres-dsn %q should stop at the missing db_password file: err=%v out=%s", dsn, err, out)
		}
	}
}
