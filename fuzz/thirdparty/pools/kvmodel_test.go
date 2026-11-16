// Shared porcupine models + history machinery for the third-party
// connection-pool linearizability fuzzers (task SC1). See package doc in
// sqlitepool_fuzz_test.go for the overall design and the per-oracle
// "what this does NOT verify" notes.
//
// Two models, each a family of independent per-key registers partitioned by
// hand (keys touch disjoint rows by construction, so a register per key is
// sound without porcupine's Partition callback):
//
//   - regModel: a string register. A write UPSERTs k=v; a read observes it.
//     Catches a torn/stale read, a lost write, or any history no single
//     sequential order explains (the classic linearizability failure).
//   - counterModel: a monotonic counter. An increment does read-modify-write
//     (SELECT n; UPDATE n+1) and returns the NEW value. Linearizability here is
//     exactly the lost-update check: two increments that both read the same n
//     and both return n+1 cannot be ordered sequentially, so a missing FOR
//     UPDATE / wrong isolation level is caught as an Illegal history. This is
//     the transaction-isolation oracle.
package pools

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
)

// --- string register model (read/write) ------------------------------------

type regOp struct {
	write bool
	value string
}

var regModel = porcupine.Model{
	Init: func() any { return "" },
	Step: func(state, input, output any) (bool, any) {
		in := input.(regOp)
		if in.write {
			return true, in.value
		}
		return output.(string) == state.(string), state
	},
	DescribeOperation: func(input, output any) string {
		in := input.(regOp)
		if in.write {
			return fmt.Sprintf("write(%q)", in.value)
		}
		return fmt.Sprintf("read() -> %q", output)
	},
}

// --- counter model (increment, read-modify-write) --------------------------

// counterOp: every op is an increment; output is the value the increment
// returned (the post-increment counter value it observed/wrote).
type counterOp struct{}

var counterModel = porcupine.Model{
	Init: func() any { return int64(0) },
	Step: func(state, input, output any) (bool, any) {
		next := state.(int64) + 1
		return output.(int64) == next, next
	},
	DescribeOperation: func(input, output any) string {
		return fmt.Sprintf("increment() -> %v", output)
	},
}

// --- history recording ------------------------------------------------------

// history accumulates porcupine operations per register key during one fuzz
// iteration. Guarded by mu since goroutines append concurrently; Call/Return
// timestamps are captured by the caller OUTSIDE the lock, immediately around
// the real operation, so lock contention here never distorts the intervals.
type history struct {
	mu  sync.Mutex
	ops map[byte][]porcupine.Operation
}

func newHistory() *history { return &history{ops: map[byte][]porcupine.Operation{}} }

func (h *history) add(key byte, op porcupine.Operation) {
	h.mu.Lock()
	h.ops[key] = append(h.ops[key], op)
	h.mu.Unlock()
}

// checkAll runs the linearizability check for every key's history and fails t
// on the first Illegal one. An Unknown (checker timeout) is logged, never
// failed — porcupine's own docs are explicit that Unknown is not evidence of a
// violation, and these histories are tiny so a genuine timeout is itself
// noteworthy.
func checkAll(t *testing.T, label string, model porcupine.Model, h *history) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, ops := range h.ops {
		if len(ops) == 0 {
			continue
		}
		res, _ := porcupine.CheckOperationsVerbose(model, ops, 5*time.Second)
		switch res {
		case porcupine.Illegal:
			var sb strings.Builder
			fmt.Fprintf(&sb, "NOT LINEARIZABLE: %s key=%d — no sequential order explains this history:\n", label, key)
			for _, op := range ops {
				fmt.Fprintf(&sb, "  client %d: [%d,%d] %s\n", op.ClientId, op.Call, op.Return, model.DescribeOperation(op.Input, op.Output))
			}
			t.Fatalf("%s", sb.String())
		case porcupine.Unknown:
			t.Logf("linearizability check for %s key=%d timed out (Unknown, not a failure) over %d ops", label, key, len(ops))
		}
	}
}
