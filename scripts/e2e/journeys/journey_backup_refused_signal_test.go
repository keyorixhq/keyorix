//go:build e2e

package journeys

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_BackupRefusedSignalWhileStagingSaltPresent is #4105 as an operator
// meets it against a real server: an interrupted rotate-kek left
// kek.salt.pending in the running server's key directory, so the cron
// `keyorix-server admin backup` exits 4 with its keyorix-backup-refused line and
// writes nothing; the administrator sees security.backup_refused in GET
// /api/v1/system/info naming the file and the remedy; `admin encryption
// clear-stale-salt-pending` refuses beside the live server and, with the server
// stopped, removes the file, after which the backup succeeds.
func TestJourney_BackupRefusedSignalWhileStagingSaltPresent(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)

	type refused struct {
		Reason          string   `json:"reason"`
		Files           []string `json:"files"`
		StagingSaltOnly bool     `json:"staging_salt_only"`
		Remedy          string   `json:"remedy"`
	}
	status := func() *refused {
		t.Helper()
		env := restExpect(t, s, adminToken, http.MethodGet, "/api/v1/system/info", nil, http.StatusOK)
		var d struct {
			Security struct {
				BackupRefused *refused `json:"backup_refused"`
			} `json:"security"`
		}
		if err := json.Unmarshal(env.Data, &d); err != nil {
			t.Fatalf("decode system info: %v\n%s", err, env.Raw)
		}
		return d.Security.BackupRefused
	}
	backup := func(out string) (int, string) {
		t.Helper()
		got, err := harness.RunAdminCmd(s.Binary, s.Dir, s.Env, "backup", "--config", s.ConfigPath, "--output", out)
		if err == nil {
			return 0, got
		}
		exit, ok := errors.AsType[*exec.ExitError](err)
		if !ok {
			t.Fatalf("admin backup did not run: %v\n%s", err, got)
		}
		return exit.ExitCode(), got
	}

	if st := status(); st != nil {
		t.Fatalf("control: a fresh server must not report backup_refused: %+v", st)
	}

	salt := findKeyFile(t, s.Dir, "kek.salt")
	pending := salt + ".pending"
	if err := os.WriteFile(pending, []byte("staging salt left by an interrupted rotate-kek"), 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	for range 2 {
		code, out := backup(filepath.Join(outDir, "nightly.tar.gz"))
		if code != 4 || !strings.Contains(out, "keyorix-backup-refused reason=key-rotation-staging-file exit_code=4") {
			t.Fatalf("admin backup with a staging salt present: want exit 4 and the keyorix-backup-refused line, got exit %d:\n%s", code, out)
		}
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("a refused backup must write nothing, found %d entries", len(entries))
	}

	st := status()
	if st == nil {
		t.Fatal("the administrator must see security.backup_refused while the backup is refused")
	}
	if st.Reason != "key-rotation-staging-file" || !st.StagingSaltOnly || len(st.Files) != 1 || !strings.HasSuffix(st.Files[0], "kek.salt.pending") {
		t.Fatalf("backup_refused: %+v", st)
	}
	if !strings.Contains(st.Remedy, "admin encryption clear-stale-salt-pending") {
		t.Fatalf("backup_refused remedy: %q", st.Remedy)
	}

	// The named command refuses beside the live server (it holds the key lock),
	// removes the file once the server is stopped, and has nothing to do after.
	clearSalt := func(extra ...string) (string, error) {
		t.Helper()
		args := append([]string{"encryption", "clear-stale-salt-pending", "--config", s.ConfigPath}, extra...)
		return harness.RunAdminCmd(s.Binary, s.Dir, s.Env, args...)
	}
	if out, err := clearSalt(); err == nil {
		t.Fatalf("clear-stale-salt-pending beside a live server must refuse:\n%s", out)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("a refused clear-stale-salt-pending must leave %s: %v", pending, err)
	}

	s.Close() // SQLite backups need the database to themselves
	if out, err := clearSalt("--dry-run"); err != nil || !strings.Contains(out, "would remove") {
		t.Fatalf("clear-stale-salt-pending --dry-run: %v\n%s", err, out)
	}
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("--dry-run must leave %s: %v", pending, err)
	}
	if out, err := clearSalt(); err != nil || !strings.Contains(out, "removed ") || !strings.Contains(out, "kek.salt.pending") {
		t.Fatalf("clear-stale-salt-pending: %v\n%s", err, out)
	}
	if _, err := os.Stat(pending); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s must be gone: %v", pending, err)
	}
	if out, err := clearSalt(); err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("a second clear-stale-salt-pending must have nothing to do: %v\n%s", err, out)
	}
	if code, out := backup(filepath.Join(outDir, "after.tar.gz")); code != 0 {
		t.Fatalf("backup after clear-stale-salt-pending: exit %d:\n%s", code, out)
	}
}

// findKeyFile returns the path of the file named name under dir.
func findKeyFile(t *testing.T, dir, name string) string {
	t.Helper()
	var found string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no %s under %s", name, dir)
	}
	return found
}
