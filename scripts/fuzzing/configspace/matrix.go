package configspace

import (
	"fmt"
	"math/rand"
)

// valueKey identifies one value of one parameter.
type valueKey struct {
	Param string
	Index int
}

// SoloCases returns one case per value of every parameter: that value alone on the
// baseline. These are the single-fault rows (invalid values live only here and in
// mutation rows).
func SoloCases(m *Model) []*Case {
	var out []*Case
	for _, p := range m.Params {
		for i := range p.Values {
			out = append(out, &Case{
				ID:     fmt.Sprintf("solo-%s-%d", p.ID, i),
				Kind:   "solo",
				Assign: map[string]int{p.ID: i},
			})
		}
	}
	return out
}

// PairwiseOpts selects which values enter the covering array.
type PairwiseOpts struct {
	Name        string
	StartOnly   bool              // exclude values that cannot start in the sandbox
	ExcludeSolo map[valueKey]bool // values refused on their own (the "clean" array)
	Seed        int64
	Tries       int
}

// PairwiseCases builds the covering array over every non-invalid value.
func PairwiseCases(m *Model, o PairwiseOpts) ([]*Case, [][]int, []int) {
	type dom struct {
		p    *Param
		vals []int
	}
	var doms []dom
	for i := range m.Params {
		p := &m.Params[i]
		var vals []int
		for j, v := range p.Values {
			if v.Class == ClassInvalid {
				continue
			}
			if o.StartOnly && !v.CanStart() {
				continue
			}
			if o.ExcludeSolo[valueKey{p.ID, j}] {
				continue
			}
			vals = append(vals, j)
		}
		if len(vals) == 0 {
			continue
		}
		doms = append(doms, dom{p, vals})
	}
	sizes := make([]int, len(doms))
	for i, d := range doms {
		sizes[i] = len(d.vals)
	}
	tries := o.Tries
	if tries == 0 {
		tries = 24
	}
	rows := Pairwise(sizes, o.Seed, tries)
	var cases []*Case
	for r, row := range rows {
		c := &Case{ID: fmt.Sprintf("%s-%03d", o.Name, r), Kind: o.Name, Assign: map[string]int{}}
		for i, d := range doms {
			c.Assign[d.p.ID] = d.vals[row[i]]
		}
		cases = append(cases, c)
	}
	return cases, rows, sizes
}

// MutationCases returns n seeded random multi-option combinations of k options
// (k in [kmin,kmax]). With pInvalid probability a chosen option takes an invalid value,
// so these rows also probe fault masking.
func MutationCases(m *Model, n int, seed int64, kmin, kmax int, pInvalid float64) []*Case {
	rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic, seeded sampling so a case set can be reproduced from its seed; not a security use
	var out []*Case
	for i := range n {
		k := kmin + rng.Intn(kmax-kmin+1)
		c := &Case{ID: fmt.Sprintf("mut-%03d", i), Kind: "mutation", Assign: map[string]int{}}
		for _, pi := range rng.Perm(len(m.Params))[:k] {
			p := &m.Params[pi]
			var idxs []int
			for j, v := range p.Values {
				if (v.Class == ClassInvalid) == (rng.Float64() < pInvalid) {
					idxs = append(idxs, j)
				}
			}
			if len(idxs) == 0 {
				for j := range p.Values {
					idxs = append(idxs, j)
				}
			}
			c.Assign[p.ID] = idxs[rng.Intn(len(idxs))]
		}
		out = append(out, c)
	}
	return out
}
