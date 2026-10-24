// audit_verify_evidence_test.go — the failure-event part of the evidence index
// (audit_verify_state.go) and the generation a failure event names.
package core

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuditFailureEventGen(t *testing.T) {
	t.Parallel()
	for _, src := range []string{"tail", auditFullSourceRolling, auditFullSourceJob, auditFullSourceCheckpoint} {
		f := &auditVerifyFailure{Source: src, Gen: 42, Reason: "row #7 (state generation 9): hash mismatch"}
		assert.Equal(t, uint64(42), auditFailureEventGen(auditFailureEventText(f)), src)
		// The client-origin note is appended, never prefixed.
		assert.Equal(t, uint64(42), auditFailureEventGen(auditFailureEventText(f)+" [client-asserted origin: x]"), src)
	}
	for _, desc := range []string{
		"",
		"audit chain verification failed (tail): hash mismatch", // an older binary's text
		"audit chain verification failed (tail, state generation 0): x",
		"audit chain verification failed (tail, state generation 01): x",
		"audit chain verification failed (tail, state generation 1000000000000000000): x", // 19 digits
		"audit chain verification failed (tail, state generation 12)x",
		"Audit chain verification failed (tail, state generation 12): x",
		" audit chain verification failed (tail, state generation 12): x",
		"audit chain verification failed (Tail, state generation 12): x",
		"audit chain verification failed (tail): row (x, state generation 12): x",
	} {
		assert.Zero(t, auditFailureEventGen(desc), "%q names no generation", desc)
	}
	assert.Equal(t, uint64(999999999999999999), auditFailureEventGen("audit chain verification failed (tail, state generation 999999999999999999): x"))
}

// ffEvent is one failure event: id and the generation it names.
type ffEvent struct {
	id  uint
	gen uint64
}

// foreignFailureNaive is the definition foreignFailure implements.
func foreignFailureNaive(evs []ffEvent, own uint64) uint {
	var n uint
	for _, e := range evs {
		if own == 0 || e.gen != own {
			n = max(n, e.id)
		}
	}
	return n
}

func TestAuditVerifyEvidence_ForeignFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		evs  []ffEvent
		want map[uint64]uint // own -> foreignFailure(own)
	}{
		{"none", nil, map[uint64]uint{0: 0, 5: 0}},
		{"own only", []ffEvent{{10, 5}}, map[uint64]uint{0: 10, 5: 0, 4: 10}},
		{"older foreign under own", []ffEvent{{10, 3}, {20, 5}}, map[uint64]uint{0: 20, 5: 10, 3: 20}},
		{"newer foreign over own", []ffEvent{{10, 5}, {20, 7}}, map[uint64]uint{0: 20, 5: 20, 7: 10}},
		{"legacy events never own", []ffEvent{{10, 0}, {20, 0}}, map[uint64]uint{0: 20, 5: 20}},
		{"legacy under own", []ffEvent{{10, 0}, {20, 5}}, map[uint64]uint{5: 10}},
		{"repeated own gen", []ffEvent{{10, 3}, {20, 5}, {30, 5}}, map[uint64]uint{5: 10, 3: 30}},
		{"same gen twice then other", []ffEvent{{10, 5}, {20, 5}, {30, 7}}, map[uint64]uint{5: 30, 7: 20}},
	}
	for _, tc := range cases {
		var ev auditVerifyEvidence
		for _, e := range tc.evs {
			ev.noteFailure(e.id, e.gen)
		}
		for own, want := range tc.want {
			assert.Equal(t, want, ev.foreignFailure(own), "%s: own %d", tc.name, own)
		}
	}

	// Any order and any repeats (the scan re-reads a window) give the same
	// answer as the definition, for every own generation.
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 2000 {
		n := 1 + rng.IntN(6)
		evs := make([]ffEvent, n)
		for j := range evs {
			evs[j] = ffEvent{id: uint(1 + j*3 + rng.IntN(3)), gen: uint64(rng.IntN(4))}
		}
		feed := append([]ffEvent(nil), evs...)
		for range rng.IntN(4) {
			feed = append(feed, evs[rng.IntN(n)])
		}
		rng.Shuffle(len(feed), func(a, b int) { feed[a], feed[b] = feed[b], feed[a] })
		var ev auditVerifyEvidence
		var maxGen uint64
		for _, e := range feed {
			ev.noteFailure(e.id, e.gen)
			maxGen = max(maxGen, e.gen)
		}
		for own := range uint64(5) {
			assert.Equal(t, foreignFailureNaive(evs, own), ev.foreignFailure(own), fmt.Sprintf("case %d %v own %d", i, feed, own))
		}
		assert.Equal(t, maxGen, ev.maxFailureGen)
		assert.Equal(t, foreignFailureNaive(evs, 0), ev.failure)
	}
}
