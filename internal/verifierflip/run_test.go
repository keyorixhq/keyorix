package verifierflip_test

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/verifierflip"
)

// TestVerifierBitFlip runs every registered target through the full mutation
// set (PREREG.md). It fails on PANIC, ACCEPT-DIFFERENT and reproduced TIMING
// candidates, except for targets listed in informational (documented
// by-design unauthenticated fields), and writes a JSON report when
// VERIFIERFLIP_REPORT is set. VERIFIERFLIP_SEED selects the seed (default 1).
//
// The planted-defect self-test (selftest_test.go) is the precondition for
// trusting a clean result here: run the whole package, not this test alone.
func TestVerifierBitFlip(t *testing.T) {
	seed := uint64(1)
	if s := os.Getenv("VERIFIERFLIP_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		seed = v
	}
	informational := map[string]bool{
		// KeyVersion/EncryptedAt/AADVersion are outside the GCM tag by design;
		// this target exists to make that visible, not to gate on it.
		"aead-envelope-metadata-informational": true,
		// anchor_token/anchor_provider are outside the checkpoint signature by
		// design (RFC3161 token is authenticated by internal/notary elsewhere).
		"audit-external-anchor-bundle-unsigned-fields-informational": true,
	}
	opts := verifierflip.DefaultOptions(seed)
	opts.SkipTiming = raceEnabled
	var all []*verifierflip.Report
	for _, tg := range allTargets(t) {
		rep, err := verifierflip.Run(tg, opts)
		if err != nil {
			t.Errorf("%s: INVALID target: %v", tg.Name, err)
			continue
		}
		all = append(all, rep)
		t.Logf("%-40s mutations=%-6d reject=%-6d equiv=%-4d DIFFERENT=%-4d PANIC=%-3d timing=%d posRatio=%.2f skew=%v median=%dns",
			rep.Target, rep.Mutations, rep.Rejects, rep.Equivalent, rep.Different, rep.Panics, rep.TimingFlags, rep.PosRatio, rep.PosSkew, rep.MedianNS)
		for k, n := range rep.ByRegion {
			t.Logf("    %s x%d", k, n)
		}
		if informational[rep.Target] {
			continue
		}
		for _, c := range rep.UnexpectedEquivalents(reviewedEquivalents[rep.Target]) {
			t.Errorf("%s: unreviewed ACCEPT-EQUIVALENT class %s", rep.Target, c)
		}
		if rep.Panics > 0 || rep.Different > 0 || rep.TimingFlags > 0 {
			for _, c := range rep.Candidates {
				if c.Kind != verifierflip.AcceptEquivalent {
					t.Errorf("%s: %s %s region=%q %s hex=%.120s", rep.Target, c.Kind, c.Mutation, c.Region, c.Detail, c.Hex)
				}
			}
		}
	}
	if p := os.Getenv("VERIFIERFLIP_REPORT"); p != "" {
		b, _ := json.MarshalIndent(all, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
