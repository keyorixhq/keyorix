package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// execKeyTimeout bounds how long the resolver command may run before the KEK
// fetch is abandoned. Generous enough for a network round-trip to a secret store,
// short enough that a hung helper fails startup loudly rather than wedging it.
const execKeyTimeout = 30 * time.Second

// execAllowedEnv is the minimal environment passed through to the resolver
// process. Go's os/exec inherits the ENTIRE parent environment whenever
// cmd.Env is left nil, but the resolver is an operator-configured binary
// (op, sops, vault, or a custom helper) — if it's later compromised via a
// supply-chain/PATH hijack, or is simply overly permissive or logs its
// environment, an inherited full environment would hand it every secret the
// server process holds (KEYORIX_MASTER_PASSWORD, DB credentials, ...), not
// just what it needs to resolve the KEK. PATH lets the binary and any
// subprocess it spawns resolve other executables normally; HOME is what most
// CLI credential helpers (op, sops, vault, aws, gcloud, ...) use to locate
// their own config/cache/credential files. Extend this list — or make it
// configurable — if a real resolver genuinely needs more.
var execAllowedEnv = []string{"PATH", "HOME"}

// execEnv builds the minimal Env slice for the resolver command from
// execAllowedEnv, passing through only variables that are actually set.
func execEnv() []string {
	env := make([]string, 0, len(execAllowedEnv))
	for _, k := range execAllowedEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// execMaxStdoutBytes caps how much of the resolver's stdout the exec provider
// will buffer. Legitimate resolvers here only ever emit a few dozen bytes (raw,
// hex, or base64 KEK material), so this stays far above any real need while
// still protecting against a misbehaving or compromised resolver that writes
// gigabytes to stdout and would otherwise OOM the server process.
const execMaxStdoutBytes = 1 << 20 // 1 MiB

// limitedBuffer is a bytes.Buffer capped at max bytes. Writes beyond the cap
// are discarded rather than silently truncated into what becomes the returned
// key material — exceeded is set so the caller can fail closed with a clear
// error instead of attempting to decode a truncated/garbage buffer.
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.exceeded {
		return len(p), nil // already over cap; discard further output
	}
	room := b.max - b.buf.Len()
	if len(p) > room {
		b.buf.Write(p[:room])
		b.exceeded = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// ExecKeyProvider sources the KEK by running an operator-configured command and
// reading the key material (raw 32 bytes, or hex/base64 thereof) from its stdout.
// It is the universal escape hatch for any secret store Keyorix has no built-in
// client for — e.g. `op read op://vault/kek/value` (1Password), `sops -d kek.enc`,
// `vault read -field=kek secret/keyorix`, or a CSI/sidecar helper.
//
// The command is an explicit argv (argv[0] is the binary, the rest are args); it
// is executed directly WITHOUT a shell, so there is no shell-injection surface.
// The argv comes from the deployment's encryption config and is trusted on the
// same footing as the file path / env var the other raw providers read.
type ExecKeyProvider struct {
	command []string
}

// NewExecKeyProvider builds an exec provider from an argv (argv[0] = binary).
func NewExecKeyProvider(command []string) *ExecKeyProvider {
	return &ExecKeyProvider{command: command}
}

func (p *ExecKeyProvider) Name() string { return "exec" }

func (p *ExecKeyProvider) KEK() ([]byte, error) {
	if len(p.command) == 0 || p.command[0] == "" {
		return nil, fmt.Errorf("exec key provider: exec_command is required (argv, e.g. [\"op\", \"read\", \"op://vault/kek/value\"])")
	}
	ctx, cancel := context.WithTimeout(context.Background(), execKeyTimeout)
	defer cancel()

	// #nosec G204 -- the argv is operator-configured deployment config (trusted on
	// the same footing as a file path or env var), run without a shell.
	cmd := exec.CommandContext(ctx, p.command[0], p.command[1:]...)
	// Explicit minimal environment — do NOT inherit the full parent (server)
	// environment; see execAllowedEnv.
	cmd.Env = execEnv()
	stdout := limitedBuffer{max: execMaxStdoutBytes}
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("exec key provider: command %q timed out after %s", p.command[0], execKeyTimeout)
		}
		// stderr can carry the helper's own diagnostic, but may also echo the
		// secret — surface only a trimmed, bounded tail and never the stdout.
		return nil, fmt.Errorf("exec key provider: command %q failed: %w%s", p.command[0], err, stderrHint(stderr.Bytes()))
	}
	if stdout.exceeded {
		return nil, fmt.Errorf("exec key provider: command %q produced more than %d bytes of output (limit exceeded)", p.command[0], execMaxStdoutBytes)
	}
	// Trim a single trailing newline for the encoded forms (helpers usually print
	// one), but never mangle exactly-32 raw bytes.
	out := stdout.buf.Bytes()
	if len(out) != KEKSize {
		out = bytes.TrimRight(out, "\r\n")
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("exec key provider: command %q produced no output", p.command[0])
	}
	return decodeKeyMaterial(out, "exec")
}

// stderrHint returns a short, bounded "(stderr: …)" suffix for an exec failure,
// or "" when stderr was empty. Bounded so a misbehaving helper can't flood the
// startup error, and it is only ever shown on a non-zero exit.
func stderrHint(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return ""
	}
	const max = 200
	if len(b) > max {
		b = append(b[:max:max], []byte("…")...)
	}
	return fmt.Sprintf(" (stderr: %s)", b)
}
