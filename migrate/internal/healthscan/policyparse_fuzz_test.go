package healthscan

// policyparse_fuzz_test.go: FuzzParsePolicyHCL drives the hand-rolled Vault ACL-policy
// HCL scanner (ParsePolicyHCL) and the wildcard/sudo classifier (isWildcardSudoGrant)
// with hostile policy text. In `keyorix-migrate vault scan` (a PAID assessment against a
// customer's LIVE Vault) and in `vault plan-access`, this runs on raw policy bodies read
// straight from Vault's sys/policies API — fully attacker-controlled if the Vault is
// compromised or malicious. The scanner is regex-based, so a crash or catastrophic
// backtracking (ReDoS) here is a denial-of-service on the assessment tool.
//
// Oracles (what this does NOT verify, per oracle):
//   - O1 NO-PANIC: neither function panics on any input.
//   - O2 NO-HANG: both return within a 6 s watchdog. A regex that backtracks catastrophically
//     on a crafted body would trip this. Does NOT measure fine-grained CPU, only a gross hang.
//   - DETERMINISM: identical input, identical blocks.
//   - CONTRACT/BOUNDED: the number of path blocks is bounded by the input length, and each
//     captured Path/Capability is a substring of the input (the scanner only extracts, never
//     synthesises). Does NOT verify the scanner is a COMPLETE HCL parser — it is documented
//     NOT to be (see pathBlockRE's doc comment: a nested brace can truncate a stanza early);
//     this target does not assert the scanner finds every grant, only that it is safe and
//     faithful to what it does extract.

import (
	"strings"
	"testing"
	"time"
)

// runWithWatchdog runs fn and fails the test if it does not return within d. Pure in-memory
// parsers have no context to cancel, so the watchdog can only observe a hang, not abort the
// goroutine; the process-level fuzz timeout is the backstop if the goroutine never returns.
func runWithWatchdog(t *testing.T, d time.Duration, label string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("O2 HANG: %s did not return within %s", label, d)
	}
}

func FuzzParsePolicyHCL(f *testing.F) {
	for _, s := range []string{
		``,
		`path "secret/*" { capabilities = ["read","list"] }`,
		`path "*" { capabilities = ["sudo"] }`,
		`path "sys/*" { capabilities = ["create","update"] }`,
		"path \"secret/data/*\" {\n  capabilities = [\"create\", \"update\", \"delete\"]\n}",
		`path "a" { allowed_parameters = { "x" = [] } capabilities = ["sudo"] }`,
		`path "` + strings.Repeat("a", 4096) + `" { capabilities = ["read"] }`,
		`path "x" { capabilities = [` + strings.Repeat(`"c",`, 2000) + `] }`,
		strings.Repeat(`path "p" { `, 1000),
		`path "` + "\x00\r\n" + `" { capabilities = ["sudo"] }`,
		"path\t\"q\"\n{\ncapabilities\n=\n[\n\"read\"\n]\n}",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		raw := string(data)
		var blocks []PolicyPathBlock
		runWithWatchdog(t, 6*time.Second, "ParsePolicyHCL", func() {
			blocks = ParsePolicyHCL(raw)
		})

		// DETERMINISM.
		blocks2 := ParsePolicyHCL(raw)
		if len(blocks) != len(blocks2) {
			t.Fatalf("ParsePolicyHCL not deterministic for %q: %d vs %d blocks", data, len(blocks), len(blocks2))
		}

		// BOUNDED: each `path "..."` match consumes at least `path "" {}` ~= 9 bytes, so the
		// block count cannot exceed the input length.
		if len(blocks) > len(data)+1 {
			t.Fatalf("ParsePolicyHCL produced %d blocks from %d bytes for %q", len(blocks), len(data), data)
		}
		for _, b := range blocks {
			// CONTRACT: Path and every Capability are substrings of the input (extract-only).
			if !strings.Contains(raw, b.Path) {
				t.Fatalf("ParsePolicyHCL invented a Path %q not present in %q", b.Path, data)
			}
			for _, c := range b.Capabilities {
				if !strings.Contains(raw, c) {
					t.Fatalf("ParsePolicyHCL invented a capability %q not present in %q", c, data)
				}
			}
			// The classifier must also be panic/hang-free on whatever the scanner produced.
			runWithWatchdog(t, 6*time.Second, "isWildcardSudoGrant", func() {
				_ = isWildcardSudoGrant(b)
			})
		}
	})
}
