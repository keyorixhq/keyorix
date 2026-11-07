package configspace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReplay re-runs the minimised case of one recorded finding through the process
// stage and prints what the oracle sees. Gated by CONFIGSPACE_REPLAY_KEY (a substring
// of the finding key); CONFIGSPACE_REPLAY_FROM names the findings.jsonl file. Output goes
// to the test log only, so run it against a private directory.
func TestReplay(t *testing.T) {
	key := os.Getenv("CONFIGSPACE_REPLAY_KEY")
	from := os.Getenv("CONFIGSPACE_REPLAY_FROM")
	if key == "" || from == "" {
		t.Skip("set CONFIGSPACE_REPLAY_KEY and CONFIGSPACE_REPLAY_FROM to replay a finding")
	}
	bin := os.Getenv("CONFIGSPACE_BIN")
	tplDir := os.Getenv("CONFIGSPACE_TEMPLATE")
	if bin == "" || tplDir == "" {
		t.Fatal("CONFIGSPACE_BIN and CONFIGSPACE_TEMPLATE are required")
	}
	tpl, err := LoadTemplate(tplDir)
	if err != nil {
		t.Fatal(err)
	}
	m := mustModel(t)
	f, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var u UniqueFinding
		if json.Unmarshal(sc.Bytes(), &u) != nil || !strings.Contains(u.Key, key) {
			continue
		}
		if len(u.MinAssign) == 0 {
			t.Logf("%s: no minimal assignment recorded", u.Key)
			continue
		}
		work := filepath.Join(os.Getenv("CONFIGSPACE_WORK"), "replay")
		if os.Getenv("CONFIGSPACE_WORK") == "" {
			work = t.TempDir()
		}
		for i := 0; i < 3; i++ {
			c := &Case{ID: "replay", Kind: "mutation", Assign: u.MinAssign}
			if err := c.Materialize(m, tpl, work, false); err != nil {
				t.Fatal(err)
			}
			ip := RunInProc(m, c)
			httpOn, grpcOn := enabledFlags(c, ip)
			pr := RunProc(bin, c, httpOn, grpcOn, 30*time.Second, 15*time.Second)
			got := CheckProc(m, c, ip, pr)
			t.Logf("run %d: started=%v exit=%d health=%v findings=%d", i, pr.Started, pr.Exit, pr.Health, len(got))
			for _, g := range got {
				t.Logf("  %s %s %s", g.Inv, g.Key, g.Title)
			}
			if i == 0 {
				t.Logf("log tail:\n%s", tail(pr.Log, 3000))
			}
			os.RemoveAll(c.Dir)
		}
	}
}
