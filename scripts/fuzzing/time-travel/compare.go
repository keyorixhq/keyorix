//go:build ignore

// compare.go diffs two canonical driver outputs (OLD then NEW, JSON-lines as
// produced by the per-version driver) and prints every behaviour change, one per
// line, with a first-cut classification. It is the deterministic half of the
// time-travel differential: run.sh produces per-version JSONL, this joins two
// consecutive versions by id and reports where the verdict, error class, parsed
// shape, or bounded-work bucket changed.
//
// Usage: go run compare.go <old.jsonl> <new.jsonl>
//
// Classification is intentionally conservative and names the AXIS of change, not
// a security verdict — a human decides fixed-bug vs
// introduced-bug vs intentional. The axes:
//
//	VERDICT   accept<->reject<->panic<->driver_exit : the accept/reject decision moved.
//	ERRCLASS  same verdict, different error bucket   : a reject for a different reason.
//	SHAPE     same accept, different ncerts/ncontent : parsed structure changed.
//	WORK      allocbucket moved by >= 3 (8x)         : bounded-work / amplification change.
//	WORDING   only errraw text changed               : cosmetic (reported, never a finding).
//
// A VERDICT move into or out of "panic"/"driver_exit" is flagged CRASH-DELTA:
// one version crashes or is killed where the other returns — the strongest
// signal (a DoS or robustness change).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type rec struct {
	ID          string `json:"id"`
	Verdict     string `json:"verdict"`
	ErrClass    string `json:"errclass"`
	ErrRaw      string `json:"errraw"`
	NCerts      int    `json:"ncerts"`
	NContent    int    `json:"ncontent"`
	AllocBucket int    `json:"allocbucket"`
	InLen       int    `json:"inlen"`
}

func load(path string) (map[string]rec, []string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer f.Close()
	m := map[string]rec{}
	var order []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r rec
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		if _, ok := m[r.ID]; !ok {
			order = append(order, r.ID)
		}
		m[r.ID] = r
	}
	return m, order
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: compare.go <old.jsonl> <new.jsonl>")
		os.Exit(2)
	}
	oldM, order := load(os.Args[1])
	newM, _ := load(os.Args[2])

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	fmt.Fprintf(w, "# axis\tid\told->new\tdetail\n")
	var n int
	crash := map[string]bool{"panic": true, "driver_exit": true}
	for _, id := range order {
		o, ok := oldM[id]
		if !ok {
			continue
		}
		nw, ok := newM[id]
		if !ok {
			fmt.Fprintf(w, "MISSING\t%s\t-\tabsent in new output\n", id)
			n++
			continue
		}
		switch {
		case o.Verdict != nw.Verdict:
			axis := "VERDICT"
			if crash[o.Verdict] || crash[nw.Verdict] {
				axis = "CRASH-DELTA"
			}
			fmt.Fprintf(w, "%s\t%s\t%s->%s\terr %q->%q alloc %d->%d\n",
				axis, id, o.Verdict, nw.Verdict, o.ErrClass, nw.ErrClass, o.AllocBucket, nw.AllocBucket)
			n++
		case o.Verdict == "reject" && o.ErrClass != nw.ErrClass:
			fmt.Fprintf(w, "ERRCLASS\t%s\t%s->%s\terr %q->%q\n", id, o.ErrClass, nw.ErrClass, o.ErrRaw, nw.ErrRaw)
			n++
		case o.Verdict == "accept" && (o.NCerts != nw.NCerts || o.NContent != nw.NContent):
			fmt.Fprintf(w, "SHAPE\t%s\tncerts %d->%d / ncontent %d->%d\t-\n", id, o.NCerts, nw.NCerts, o.NContent, nw.NContent)
			n++
		case abs(o.AllocBucket-nw.AllocBucket) >= 3:
			fmt.Fprintf(w, "WORK\t%s\tallocbucket %d->%d\tinlen %d (same verdict %q)\n", id, o.AllocBucket, nw.AllocBucket, o.InLen, o.Verdict)
			n++
		case o.ErrRaw != nw.ErrRaw:
			fmt.Fprintf(w, "WORDING\t%s\t-\t%q->%q\n", id, o.ErrRaw, nw.ErrRaw)
			n++
		}
	}
	fmt.Fprintf(w, "# %d behaviour change(s)\n", n)
}
