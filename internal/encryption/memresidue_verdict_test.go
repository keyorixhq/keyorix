package encryption

// memresidue_verdict_test.go: the red/green proof of the memory-residue
// oracle's verdict (memresidue_test.go). The scan itself needs Linux and a
// child process; the rules that turn its hits into a verdict do not, so they
// run on every platform in the default lane.

import (
	"strings"
	"testing"
)

func TestMemResidueVerdict(t *testing.T) {
	const claimAddr = 0x1000
	claims := []memResidueClaim{{Kind: "dek", What: "EncryptionService.dek", Claim: "INV-ENCRYPTION-24", Addr: claimAddr}}
	live := []memHit{{Name: "dek", Addr: claimAddr}, {Name: "dek", Addr: 0x2000}, {Name: "kek", Addr: 0x3000}}
	ratchet := map[string]int{"dek": 1, "kek": 1}

	cases := []struct {
		name     string
		rep      memResidueReport
		wantFail string // "" = no failure
		wantNote string
	}{
		{
			name:     "within the ratchet",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "dek", Addr: 0x2000}, {Name: "kek", Addr: 0x3000}}},
			wantNote: "at the bound",
		},
		{
			name:     "below the ratchet asks to lower it",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "kek", Addr: 0x3000}}},
			wantNote: `lower memResidueRatchet["dek"] to 0`, // only a hint: counts vary run to run
		},
		{
			name:     "claimed copy survives Shutdown",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "dek", Addr: claimAddr}}},
			wantFail: "CLAIMED COPY NOT WIPED",
		},
		{
			name:     "a kek at the dek claim address is not the claim",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "kek", Addr: claimAddr}, {Name: "kek", Addr: 0x3000}}},
			wantFail: "RATCHET REGRESSION: 2 unclaimed kek",
		},
		{
			name:     "count above the ratchet",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "dek", Addr: 0x2000}, {Name: "dek", Addr: 0x2100}}},
			wantFail: "RATCHET REGRESSION: 2 unclaimed dek",
		},
		{
			name:     "kind without a ratchet entry",
			rep:      memResidueReport{Claims: claims, LiveHits: live, AfterHits: []memHit{{Name: "salt", Addr: 0x4000}}},
			wantFail: `no memResidueRatchet entry for "salt"`,
		},
		{
			name:     "blind scanner",
			rep:      memResidueReport{Claims: claims, LiveHits: []memHit{{Name: "dek", Addr: 0x2000}}},
			wantFail: "scanner is blind",
		},
		{
			name:     "no claims reported",
			rep:      memResidueReport{LiveHits: live},
			wantFail: "no claimed copies",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failures, notes := memResidueVerdict(tc.rep, ratchet)
			got := strings.Join(failures, "\n")
			if tc.wantFail == "" && got != "" {
				t.Fatalf("unexpected failure:\n%s", got)
			}
			if tc.wantFail != "" && !strings.Contains(got, tc.wantFail) {
				t.Fatalf("want a failure containing %q, got:\n%s", tc.wantFail, got)
			}
			if tc.wantNote != "" && !strings.Contains(strings.Join(notes, "\n"), tc.wantNote) {
				t.Fatalf("want a note containing %q, got:\n%s", tc.wantNote, strings.Join(notes, "\n"))
			}
		})
	}
}

func TestMemResidueRedVerdict(t *testing.T) {
	const claimAddr = 0x1000
	claims := []memResidueClaim{{Kind: "dek", What: "EncryptionService.dek", Claim: "INV-ENCRYPTION-24", Addr: claimAddr}}
	live := []memHit{{Name: "dek", Addr: claimAddr}, {Name: "dek", Addr: 0x2000}, {Name: "kek", Addr: 0x3000}}

	cases := []struct {
		name     string
		after    []memHit
		live     []memHit
		wantFail string
	}{
		{name: "zeroing removes exactly the claimed copy", live: live, after: []memHit{{Name: "dek", Addr: 0x2000}, {Name: "kek", Addr: 0x3000}}},
		{name: "claimed copy still found", live: live, after: live, wantFail: "after zeroing it"},
		{name: "another copy vanished too", live: live, after: []memHit{{Name: "kek", Addr: 0x3000}}, wantFail: "does not track product memory"},
		{name: "a copy appeared", live: live, after: []memHit{{Name: "dek", Addr: 0x2000}, {Name: "dek", Addr: 0x5000}}, wantFail: "does not track product memory"},
		{name: "live copy not found", live: []memHit{{Name: "dek", Addr: 0x2000}}, after: nil, wantFail: "live dek not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(memResidueRedVerdict(memResidueReport{Claims: claims, LiveHits: tc.live, AfterHits: tc.after}), "\n")
			if tc.wantFail == "" && got != "" {
				t.Fatalf("unexpected failure:\n%s", got)
			}
			if tc.wantFail != "" && !strings.Contains(got, tc.wantFail) {
				t.Fatalf("want a failure containing %q, got:\n%s", tc.wantFail, got)
			}
		})
	}
	if got := memResidueRedVerdict(memResidueReport{LiveHits: live}); len(got) == 0 {
		t.Fatal("a red control with no claims must fail")
	}
}
