package encryption

// memresidue_verdict_test.go: the red/green proof of the memory-residue
// oracle's verdict (memresidue_test.go). The scan itself needs Linux and a
// child process; the rules that turn its hits into a verdict do not, so they
// run on every platform in the default lane.

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
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
			name:     "kek needle never found live",
			rep:      memResidueReport{Claims: claims, LiveHits: live[:2]},
			wantFail: "no live kek copy",
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

func TestMemResidueSiteVerdict(t *testing.T) {
	const fn = "example.com/pkg.(*Provider).KEK"
	claims := []memResidueSiteClaim{{Scenarios: []string{"s"}, Func: fn, What: "the read buffer", Claim: "INV-X"}}
	under := []string{"io.ReadAll", fn, "example.com/pkg.caller"}
	other := []string{"crypto/aes.NewCipher"}

	cases := []struct {
		name     string
		rep      memAttributionReport
		wantFail string // "" = no failure
	}{
		{name: "wiped: only a live hit under the site", rep: memAttributionReport{Scenario: "s", SitesSeen: map[string]bool{fn: true},
			Hits: []memAttributedHit{{memHit: memHit{Name: "kek-hex", Addr: 0x10}, Phase: "live", Stack: under}, {memHit: memHit{Name: "kek", Addr: 0x20}, Phase: "after", Stack: other}}}},
		{name: "copy under the site survives", rep: memAttributionReport{Scenario: "s", SitesSeen: map[string]bool{fn: true},
			Hits: []memAttributedHit{{memHit: memHit{Name: "kek-hex", Addr: 0x10}, Phase: "after", Stack: under}}}, wantFail: "CLAIMED COPY NOT WIPED: kek-hex"},
		{name: "site never allocated", rep: memAttributionReport{Scenario: "s", SitesSeen: map[string]bool{}}, wantFail: "vacuous"},
		{name: "other scenario is not claimed", rep: memAttributionReport{Scenario: "t",
			Hits: []memAttributedHit{{memHit: memHit{Name: "kek-hex", Addr: 0x10}, Phase: "after", Stack: under}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(memResidueSiteVerdict(tc.rep, claims), "\n")
			if tc.wantFail == "" && got != "" {
				t.Fatalf("unexpected failure:\n%s", got)
			}
			if tc.wantFail != "" && !strings.Contains(got, tc.wantFail) {
				t.Fatalf("want a failure containing %q, got:\n%s", tc.wantFail, got)
			}
		})
	}
}

// TestMemResidueTablesConsistent: every scenario has a ratchet, and every site
// claim names a scenario that exists, so neither table can drift silently.
func TestMemResidueTablesConsistent(t *testing.T) {
	names := map[string]bool{}
	for _, sc := range memResidueScenarios {
		if names[sc.name] {
			t.Errorf("scenario %q listed twice", sc.name)
		}
		names[sc.name] = true
		if _, ok := memResidueRatchet[sc.name]; !ok {
			t.Errorf("scenario %q has no memResidueRatchet entry", sc.name)
		}
	}
	for name := range memResidueRatchet {
		if !names[name] {
			t.Errorf("memResidueRatchet has an entry for unknown scenario %q", name)
		}
	}
	for _, c := range memResidueSiteClaims {
		for _, s := range c.Scenarios {
			if !names[s] {
				t.Errorf("site claim %s names unknown scenario %q", c.Claim, s)
			}
		}
	}
}

// TestMemPBKDF2SHA256 pins the harness's KDF to the provider's: a mismatch
// would make the passphrase scenario's KEK needles match nothing.
func TestMemPBKDF2SHA256(t *testing.T) {
	pass, salt := []byte("correct horse battery staple, at length"), bytes.Repeat([]byte{7}, 32)
	for _, iter := range []int{1, 2, 1000} {
		if got, want := memPBKDF2SHA256(pass, salt, iter), pbkdf2.Key(pass, salt, iter, 32, sha256.New); !bytes.Equal(got, want) {
			t.Fatalf("iterations %d: harness PBKDF2 differs from x/crypto/pbkdf2", iter)
		}
	}
}
