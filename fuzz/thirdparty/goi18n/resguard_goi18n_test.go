package goi18nhostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

// PK2: port the go-i18n ParseMessageFileBytes target onto resguard. The existing
// no-panic + bounded-wall oracle is UNCHANGED; resguard meters the parse's
// resource cost. Fatal meters: alloc_bytes / mallocs / live_heap (per-byte
// slope). go-i18n routes through json/toml/yaml decoders; the YAML route inherits
// yaml.v3's duplicate-key quadratic (go-yaml #510), so this target has a REAL
// super-linear amplifier reachable through a second library's call path — the RED
// case below drives exactly that. CPU/wall/goroutines advisory.
//
// What the resguard oracle does NOT verify (beyond the existing list): it meters
// ParseMessageFileBytes only; alloc is sampled (slow inputs force-sampled); it
// bounds ratio, not go-i18n's structural correctness.

const rgBudgetPath = "testdata/resguard-goi18n.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

var rgExts = []string{"json", "toml", "yaml"}

func rgRun(sel uint8, data []byte) {
	ext := rgExts[int(sel)%len(rgExts)]
	_, _ = i18n.ParseMessageFileBytes(data, "active."+ext, unmarshalFuncs())
}

type rgSeed struct {
	sel  uint8
	data []byte
}

func rgBenignCorpus() []rgSeed {
	// Valid message files in each format, small and medium, so the slope reflects
	// real linear parse cost. No duplicate-key doc here (that is the amplifier).
	var jsonBig, yamlBig, tomlBig strings.Builder
	jsonBig.WriteString(`{`)
	for i := range 400 {
		if i > 0 {
			jsonBig.WriteByte(',')
		}
		fmt.Fprintf(&jsonBig, `"m%d":{"other":"v%d"}`, i, i)
	}
	jsonBig.WriteString(`}`)
	for i := range 400 {
		fmt.Fprintf(&yamlBig, "m%d:\n  other: v%d\n", i, i)
	}
	for i := range 400 {
		fmt.Fprintf(&tomlBig, "[m%d]\nother = \"v%d\"\n", i, i)
	}
	return []rgSeed{
		{0, []byte(`{"hello":"world"}`)},
		{0, []byte(`{"msg":{"one":"a","other":"b"}}`)},
		{1, []byte("hello = \"world\"\n[msg]\none = \"a\"\nother = \"b\"\n")},
		{2, []byte("hello: world\nmsg:\n  one: a\n  other: b\n")},
		{0, []byte(jsonBig.String())},
		{2, []byte(yamlBig.String())},
		{1, []byte(tomlBig.String())},
	}
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s.data), func() { rgRun(s.sel, s.data) }))
		}
	}
	b := resguard.Calibrate("goi18n_parse", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}

func TestResguardGoI18nCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes must be calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardGoI18nRedGreen proves the oracle with a REAL amplifier: a
// duplicate-key YAML message file (go-yaml #510) parsed through go-i18n's YAML
// route. GREEN: a benign YAML message file passes. RED: the dup-key doc allocates
// super-linearly and trips the alloc budget — a real third-party defect caught
// through a second library's call path, no production plant.
func TestResguardGoI18nRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := []byte("hello: world\nmsg:\n  one: a\n  other: b\n")
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(2, benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign yaml message file tripped the budget: alloc=%d", green.AllocBytes)
	}

	// #510 duplicate-key YAML through go-i18n's yaml route.
	bomb := []byte("a: 1\n" + strings.Repeat("a: 1\n", 1500))
	pr := resguard.New(t, resguard.Options{SampleEvery: 1})
	red := pr.Measure(len(bomb), func() { rgRun(2, bomb) })
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("the #510 dup-key YAML (input %d, alloc %d) did NOT trip the budget via go-i18n", len(bomb), red.AllocBytes)
	}
	t.Logf("RED tripped (real #510 via go-i18n yaml route; input %d, alloc %d, wall %s): %s", len(bomb), red.AllocBytes, red.Wall, msg)
}
