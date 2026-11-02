package integrity

import (
	"os"
	"strings"
	"testing"
)

func ls(states map[string]State) []Line {
	var out []Line
	for _, id := range []string{CheckSecureBoot, CheckLockdown, CheckIMA, CheckFSVerity, CheckManifest, CheckTPMSealing, CheckKeylime} {
		s, ok := states[id]
		if !ok {
			s = StateDegraded
		}
		out = append(out, Line{ID: id, State: s})
	}
	return out
}

func TestTierTable(t *testing.T) {
	ok := StateOK
	cases := []struct {
		name string
		in   map[string]State
		want int
	}{
		{"nothing", nil, 0},
		{"secure boot only", map[string]State{CheckSecureBoot: ok}, 1},
		{"+lockdown", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok}, 2},
		{"+fs-verity", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckFSVerity: ok}, 3},
		{"manifest does not replace fs-verity", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckManifest: ok}, 2},
		{"qualified manifest does not replace fs-verity", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckManifest: StateOKQualified}, 2},
		{"+IMA", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckFSVerity: ok, CheckIMA: ok}, 4},
		{"+TPM", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckFSVerity: ok, CheckIMA: ok, CheckTPMSealing: ok}, 5},
		{"+Keylime", map[string]State{CheckSecureBoot: ok, CheckLockdown: ok, CheckFSVerity: ok, CheckIMA: ok, CheckTPMSealing: ok, CheckKeylime: ok}, 6},
		{"a gap stops the climb", map[string]State{CheckSecureBoot: ok, CheckIMA: ok, CheckTPMSealing: ok, CheckKeylime: ok}, 1},
		{"unknown is not ok", map[string]State{CheckSecureBoot: StateUnknown, CheckLockdown: ok}, 0},
		{"no secure boot, everything else ok", map[string]State{CheckLockdown: ok, CheckFSVerity: ok, CheckIMA: ok, CheckTPMSealing: ok, CheckKeylime: ok}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, why := DetectTier(ls(c.in)); got != c.want || why == "" {
				t.Fatalf("tier = %d (%q), want %d", got, why, c.want)
			}
		})
	}
}

func TestTierUnknownLinesNeverRaiseTheTier(t *testing.T) {
	// Every line unknown, and every line missing: tier 0.
	var unknown []Line
	for _, l := range ls(nil) {
		l.State = StateUnknown
		unknown = append(unknown, l)
	}
	if got, _ := DetectTier(unknown); got != 0 {
		t.Fatalf("all unknown: tier %d", got)
	}
	if got, _ := DetectTier(nil); got != 0 {
		t.Fatalf("no lines: tier %d", got)
	}
}

func TestTierTableMatchesDocs(t *testing.T) {
	b, err := os.ReadFile("../../docs/security/integrity-posture.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for i, name := range LadderNames() {
		row := "| " + string(rune('1'+i)) + " | " + name + " |"
		if !strings.Contains(doc, row) {
			t.Errorf("docs tier table lacks the row %q", row)
		}
	}
	if !strings.Contains(doc, Label) {
		t.Errorf("docs do not mention the label %q", Label)
	}
}
