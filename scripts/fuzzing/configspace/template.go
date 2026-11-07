package configspace

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// BuildTemplate initialises dir as the baseline every case starts from, using the
// server binary's own admin commands: a secure-baseline config, TLS certificate,
// metrics token, install secrets, encryption keys, and a migrated SQLite database.
func BuildTemplate(bin, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	env := append(os.Environ(),
		"KEYORIX_CONFIG_PATH="+filepath.Join(dir, "keyorix.yaml"),
		"KEYORIX_MASTER_PASSWORD_FILE="+filepath.Join(dir, "secrets", "master_password"),
		"GOMAXPROCS=2")
	steps := [][]string{
		{"admin", "init"},
		{"admin", "generate-secrets"},
		{"admin", "encryption", "init"},
		{"admin", "migrate"},
	}
	for _, s := range steps {
		cmd := exec.Command("nice", append([]string{"-n", "15", bin}, s...)...)
		cmd.Dir = dir
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%v: %w\n%s", s, err, out.String())
		}
	}
	return nil
}
