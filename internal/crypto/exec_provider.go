package crypto

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// execKeyTimeout bounds how long the resolver command may run before the KEK
// fetch is abandoned. Generous enough for a network round-trip to a secret store,
// short enough that a hung helper fails startup loudly rather than wedging it.
const execKeyTimeout = 30 * time.Second

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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("exec key provider: command %q timed out after %s", p.command[0], execKeyTimeout)
		}
		// stderr can carry the helper's own diagnostic, but may also echo the
		// secret — surface only a trimmed, bounded tail and never the stdout.
		return nil, fmt.Errorf("exec key provider: command %q failed: %w%s", p.command[0], err, stderrHint(stderr.Bytes()))
	}
	// Trim a single trailing newline for the encoded forms (helpers usually print
	// one), but never mangle exactly-32 raw bytes.
	out := stdout.Bytes()
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
