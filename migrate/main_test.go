package main

import (
	"bytes"
	"strings"
	"testing"
)

// A failing subcommand prints exactly one "Error:" line on stderr (cobra used to print it too,
// then main printed it again) and exits 1.
func TestRun_FailingCommandPrintsErrorOnce(t *testing.T) {
	cases := map[string][]string{
		"runtime error":      {"vault", "plan-access"}, // --output is required
		"unknown flag":       {"version", "--no-such-flag"},
		"unknown subcommand": {"vault", "no-such-subcommand"},
		"flag without value": {"vault", "plan-access", "--output"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr=%q", code, stderr.String())
			}
			if n := strings.Count(stderr.String(), "Error:"); n != 1 {
				t.Fatalf("stderr has %d %q lines, want exactly 1:\n%s", n, "Error:", stderr.String())
			}
			lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
			if len(lines) != 1 {
				t.Fatalf("stderr has %d lines, want 1 (no usage dump, no duplicate):\n%s", len(lines), stderr.String())
			}
		})
	}
}

func TestRun_SuccessExitsZeroAndPrintsNoError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "keyorix-migrate ") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
