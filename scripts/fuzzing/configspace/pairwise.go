package configspace

import (
	"math/rand"
)

// Pairwise builds a covering array of strength 2: every value of every parameter
// appears together with every value of every other parameter in at least one row.
// sizes[i] is the number of values of parameter i; a row holds one value index per
// parameter. The algorithm is the greedy AETG scheme with a fixed seed, so the same
// model always yields the same rows. tries candidate rows are built per step and the
// one covering the most new pairs is kept.
func Pairwise(sizes []int, seed int64, tries int) [][]int {
	p := len(sizes)
	if p == 0 {
		return nil
	}
	if p == 1 {
		rows := make([][]int, sizes[0])
		for a := 0; a < sizes[0]; a++ {
			rows[a] = []int{a}
		}
		return rows
	}
	maxV := 0
	for _, s := range sizes {
		if s > maxV {
			maxV = s
		}
	}
	idx := func(i, a, j, b int) int { return ((i*maxV+a)*p+j)*maxV + b }
	covered := make([]bool, p*maxV*p*maxV)
	type pair struct{ i, a, j, b int }
	var pending []pair
	for i := range p {
		for j := i + 1; j < p; j++ {
			for a := 0; a < sizes[i]; a++ {
				for b := 0; b < sizes[j]; b++ {
					pending = append(pending, pair{i, a, j, b})
				}
			}
		}
	}
	rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic, seeded sampling so a case set can be reproduced from its seed; not a security use
	remaining := len(pending)
	var rows [][]int
	for remaining > 0 {
		// drop covered pairs from the front lazily
		k := 0
		for k < len(pending) && covered[idx(pending[k].i, pending[k].a, pending[k].j, pending[k].b)] {
			k++
		}
		pending = pending[k:]
		if len(pending) == 0 {
			break
		}
		var best []int
		bestScore := -1
		for t := range tries {
			// seed with an uncovered pair: the first for t==0, a random one otherwise
			var sp pair
			if t == 0 {
				sp = pending[0]
			} else {
				for range 50 {
					c := pending[rng.Intn(len(pending))]
					if !covered[idx(c.i, c.a, c.j, c.b)] {
						sp = c
						break
					}
					sp = pending[0]
				}
			}
			row := make([]int, p)
			for i := range row {
				row[i] = -1
			}
			row[sp.i], row[sp.j] = sp.a, sp.b
			score := 1
			order := rng.Perm(p)
			for _, i := range order {
				if row[i] != -1 {
					continue
				}
				bv, bg := 0, -1
				start := rng.Intn(sizes[i])
				for off := 0; off < sizes[i]; off++ {
					a := (start + off) % sizes[i]
					gain := 0
					for j := range p {
						if row[j] == -1 || j == i {
							continue
						}
						var c bool
						if j < i {
							c = covered[idx(j, row[j], i, a)]
						} else {
							c = covered[idx(i, a, j, row[j])]
						}
						if !c {
							gain++
						}
					}
					if gain > bg {
						bg, bv = gain, a
					}
				}
				row[i] = bv
				score += bg
			}
			if score > bestScore {
				bestScore, best = score, row
			}
		}
		for i := range p {
			for j := i + 1; j < p; j++ {
				id := idx(i, best[i], j, best[j])
				if !covered[id] {
					covered[id] = true
					remaining--
				}
			}
		}
		rows = append(rows, best)
	}
	return rows
}

// PairGaps returns the number of value pairs not covered by rows. A correct covering
// array has none.
func PairGaps(sizes []int, rows [][]int) int {
	p := len(sizes)
	seen := map[[4]int]bool{}
	for _, r := range rows {
		for i := range p {
			for j := i + 1; j < p; j++ {
				seen[[4]int{i, r[i], j, r[j]}] = true
			}
		}
	}
	gaps := 0
	for i := range p {
		for j := i + 1; j < p; j++ {
			for a := 0; a < sizes[i]; a++ {
				for b := 0; b < sizes[j]; b++ {
					if !seen[[4]int{i, a, j, b}] {
						gaps++
					}
				}
			}
		}
	}
	return gaps
}
