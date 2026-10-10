// Package secretenv resolves a secret that may be supplied either directly in
// an environment variable (X) or as the path of a file holding it (X_FILE) --
// the Docker-secrets / Kubernetes-Secret-volume convention.
//
// Why: a value in the environment is visible in `docker inspect`, in
// /proc/<pid>/environ and in every child process. A file mounted from a
// secrets store is not.
//
// Rules (Andrei, DEPLOY-2 decision 1):
//   - X_FILE set  -> read the file, strip ONE trailing line terminator.
//   - X and X_FILE both set -> error. No silent precedence: an operator who
//     set both has a deployment in an unknown state.
//   - X_FILE set but unreadable / empty / not a regular file -> error. Never
//     fall back to X or to a config-file value.
//   - Neither the value nor the file contents appear in any error or log line;
//     errors name the variable and the path only.
//
// An empty variable counts as unset (`X=${X:-}` passthrough in compose files
// is common, and the pre-existing resolvers already treated "" as unset).
package secretenv

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// FileSuffix is appended to a variable name to form its file-variant.
const FileSuffix = "_FILE"

// maxSecretFileSize bounds what Lookup will read. No legitimate secret in this
// product is larger; the cap stops a mis-pointed X_FILE (a log, a device) from
// being slurped into memory.
const maxSecretFileSize = 1 << 20

// Lookup resolves the secret called name.
//
//   - found=false, err=nil: neither name nor name_FILE is set; the caller may
//     use its own fallback (e.g. a config-file value).
//   - err != nil: the configuration is wrong; the caller must refuse to start
//     (or return an empty secret, never a fallback).
func Lookup(name string) (value string, found bool, err error) {
	direct := os.Getenv(name)
	fileVar := name + FileSuffix
	path := os.Getenv(fileVar)

	switch {
	case direct != "" && path != "":
		return "", false, fmt.Errorf("both %s and %s are set; set exactly one (the secret may come from the environment or from a file, never both)", name, fileVar)
	case path != "":
		v, err := readSecretFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s=%q: %w", fileVar, path, err)
		}
		return v, true, nil
	case direct != "":
		return direct, true, nil
	}
	return "", false, nil
}

// FilePaths returns the paths named by the <name>_FILE variables that are set
// (non-empty), in argument order. Startup uses it to run the file-permission
// check over the secret files.
func FilePaths(names ...string) []string {
	var out []string
	for _, n := range names {
		if p := os.Getenv(n + FileSuffix); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ReadFile reads a secret file named by a config key (e.g.
// server.http.metrics_token_file) under the same rules as an X_FILE variable:
// regular file, size-capped, one trailing line terminator stripped, empty is an
// error, and errors never carry the contents.
func ReadFile(path string) (string, error) {
	return readSecretFile(path)
}

func readSecretFile(path string) (string, error) {
	// Symlinks are followed on purpose: a Kubernetes Secret volume exposes each
	// key as a symlink into the kubelet's ..data/ directory. The permission
	// check (CheckPermissions) stats the target, so a symlink cannot be used to
	// launder a loose file.
	// #nosec G304 G703 -- path is the operator's own X_FILE setting (process environment,
	// not network input); the file must be a regular file and is size-capped below.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open secret file: %w", unwrapPathError(err))
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot stat secret file: %w", unwrapPathError(err))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file is not a regular file")
	}
	if info.Size() > maxSecretFileSize {
		return "", fmt.Errorf("secret file is too large (%d bytes, limit %d)", info.Size(), maxSecretFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileSize+1))
	if err != nil {
		return "", fmt.Errorf("cannot read secret file: %w", unwrapPathError(err))
	}
	if len(data) > maxSecretFileSize {
		return "", fmt.Errorf("secret file is too large (limit %d bytes)", maxSecretFileSize)
	}
	v := trimOneTerminator(string(data))
	if v == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return v, nil
}

// trimOneTerminator strips exactly one trailing "\n" or "\r\n".
func trimOneTerminator(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

// unwrapPathError drops the path prefix os errors carry (the caller already
// names the path) so the message reads "...: permission denied".
func unwrapPathError(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// CheckPermissions applies the key-material permission policy to a secret
// file: it must not be accessible to "other" at all and must not be writable
// by the group. Owner bits are not constrained and the owner is not compared
// with the running uid, because these files are mounted by an orchestrator
// (Docker secrets, Kubernetes Secret volumes) that owns them -- a kubelet
// Secret volume is root-owned 0440 with fsGroup. The path is stat'd through
// symlinks (the Kubernetes layout), so the target's mode is what is judged.
func CheckPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("secret file %q: %w", path, unwrapPathError(err))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secret file %q is not a regular file", path)
	}
	mode := info.Mode()
	if mode.Perm()&0o007 != 0 || mode.Perm()&0o020 != 0 || mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("secret file %q has mode %04o: it must not be accessible to other users or writable by its group -- refusing to trust it (chmod 0400/0440/0600, e.g. defaultMode: 0440 on a Kubernetes Secret volume)", path, mode.Perm())
	}
	return nil
}
