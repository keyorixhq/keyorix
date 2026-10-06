// cross_replica_forced_interleaving_test.go — GUARD-5 item 2: every one of
// FuzzCrossReplicaInvariants' pending seeds replayed through a FORCED
// interleaving, so each is red-every-run rather than red-if-lucky.
//
// # THE PROBLEM THIS SOLVES
//
// GUARD-4 recorded twelve pending seeds in testdata/fuzz-pending/<issue>/,
// one per open CTA-parent issue. Six of them (#2646, #2647, #2649, #2655,
// #2657, #2659) never reproduced their issue in ~400 blind repetitions each.
// A seed that does not reproduce is not a regression test — once its fix
// lands, promoting it to the live corpus would add an input that passes
// whether or not the fix is actually there.
//
// Replaying the same seed through interleave_sync_points_test.go's driver
// removes the luck: each row below names the sync point on each replica and
// the ordering that reaches the bad end state, and the driver forces exactly
// that, every run, in about a second.
//
// # TWO ROOT CAUSES, NOT ONE
//
// The narrow check-to-act window is the obvious cause, and the forced
// interleaving is its answer. The second cause was a defect in the fuzzer
// itself, found while building this file and fixed in g4Replica: the replica
// was chosen from the OP KIND (`pick%2`), so both ops of a pair landed on the
// SAME replica whenever their kinds shared parity. Six of the twelve pending
// seeds were affected — #2646 (kinds 0+6), #2649 (0+10), #2650 (0+38),
// #2652 (2+30), #2653 (21+23), #2659 (14+12) — and for those, no amount of
// blind racing could ever have worked, because there was only ever one
// connection pool and one *KeyorixCore involved. TestG4PairAlwaysSpansBothReplicas
// is the machine check that keeps that fixed.
//
// # WHY THESE TESTS RUN IN CI INSTEAD OF BEING SKIPPED
//
// C-GUARD2-EXEMPT-REVIEW's sibling tests are t.Skip'd while their issue is
// open, so they contribute nothing to CI until someone lands a fix. These
// assert in BOTH directions instead, driven by whether the issue still has a
// row in pendingSeedFix (the table
// fuzz_cross_replica_invariants_pending_seeds_test.go already maintains):
//
//   - issue still listed in pendingSeedFix  -> this ordering MUST violate an
//     invariant. The test proves, on every CI run, that the reproduction is
//     deterministic and that the bug still has the shape the issue describes.
//   - issue no longer listed (fix merged, seed promoted) -> this ordering MUST
//     keep every invariant. The test is now an ordinary regression test.
//
// So there is exactly one place to update when a fix lands — the same
// pendingSeedFix row the promotion gate already requires you to delete — and
// the transition is loud in both directions: forget to delete the row and
// this test fails saying the bug appears fixed; delete it without the fix
// actually landing and it fails saying the bug is still reproducible.
//
// This is deliberately an assertion that a bug EXISTS, which is unusual.
// It is justified here because the alternative (t.Skip) provides no signal at
// all, and because the thing being pinned is not the bug but the
// REPRODUCTION: the entire premise of promoting these seeds later is that
// they reproduce, and that premise is exactly what six of twelve seeds failed
// to satisfy. "A test whose premise turns out to be untested is a coverage
// gap" (CLAUDE.md) — this tests the premise.
//
// Postgres only; skipped cleanly when KEYORIX_TEST_PG_DSN is unset.
package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// --- sync-point specs --------------------------------------------------------

// g5SyncSpec says where one op's check/act boundary is: the production
// function, and the first GORM statement family + table it issues after its
// check. A nil spec means "no sync point is known for this op", which makes
// the pair unforceable and is reported as such rather than silently raced.
type g5SyncSpec struct {
	fn    string
	kind  string // "create" | "update" | "delete"
	table string
}

// g5OpSyncPoints maps a g4 op kind to its sync-point spec.
//
// COMPLETENESS, STATED RATHER THAN ASSUMED (CLAUDE.md: "an enumeration is only
// as complete as the idioms it knows about"): this table covers exactly the
// op kinds that appear in the twelve pending seeds plus the three already-fixed
// f.Add seeds — 21 of the 40 kinds. It is NOT a full catalog, and
// g5SpecFor returns nil for the other 19 on purpose: a missing entry makes
// TestForcedPendingSeeds fail loudly with "no sync-point spec for op kind N"
// rather than fall back to a blind race that would look like a pass.
//
// Each entry was taken from the corresponding
// concurrency_check_then_act_exempt_review_postgres_test.go test's own
// beforeA("<kind>", "<table>") call — i.e. from a hook that has been observed
// to fire against the real code path — not inferred from reading the function.
// Two entries have no such precedent and are marked; both were verified by
// running the forced test and checking the sync point actually fired.
var g5OpSyncPoints = map[byte]g5SyncSpec{
	// Soft deletes route through GORM's Delete callback family even though the
	// SQL they emit is an UPDATE of deleted_at. Getting this wrong is silent
	// (the sync point never fires), which is why requireForced exists.
	0:  {"DeleteSecret", "delete", "secret_nodes"},
	1:  {"RestoreSecret", "update", "secret_nodes"},
	2:  {"DeleteProject", "delete", "projects"},
	3:  {"RestoreProject", "update", "projects"},
	4:  {"DeleteEnvironment", "delete", "environments"},
	5:  {"RestoreEnvironment", "update", "environments"},
	6:  {"ShareSecret", "create", "share_records"},
	7:  {"ShareSecretWithGroup", "create", "share_records"},
	8:  {"UpdateSharePermission", "update", "share_records"},
	9:  {"RevokeShare", "delete", "share_records"},
	10: {"GrantSecretACL", "create", "secret_acls"},
	11: {"RevokeSecretACL", "delete", "secret_acls"},
	// #2659/#2657: the boundary that matters is the ROLE GRANT insert that
	// follows the membership commit, not the membership write itself.
	12: {"InviteMember", "create", "user_roles"},
	13: {"TransitionMembership(activate)", "create", "user_roles"},
	// Revoke's own decisive write is the grant removal.
	14: {"TransitionMembership(revoke)", "delete", "user_roles"},
	21: {"SuspendUser", "update", "users"},
	22: {"ReactivateUser", "update", "users"},
	23: {"UpdateUser", "update", "users"},
	24: {"UpdateOwnProfile", "update", "users"},
	25: {"ChangePassword", "update", "users"},
	26: {"BeginMFAEnrollment", "update", "mfa_secrets"},
	27: {"ActivateMFA", "update", "mfa_secrets"},
	28: {"AddSecretDependency(1->2)", "create", "secret_dependencies"},
	29: {"AddSecretDependency(2->1)", "create", "secret_dependencies"},
	30: {"IssueLease", "create", "dynamic_secret_leases"},
	32: {"SetDynamicSecretConfigEnabled(off)", "update", "dynamic_secret_configs"},
	33: {"SetDynamicSecretConfigEnabled(on)", "update", "dynamic_secret_configs"},
	36: {"RemoveUserRole(admin1)", "delete", "user_roles"},
	37: {"RemoveUserRole(admin2)", "delete", "user_roles"},
	38: {"SetSecretAutoRotate", "update", "secret_nodes"},
	39: {"CreateDynamicSecretConfig", "update", "dynamic_secret_configs"},
}

// g5SpecFor returns the sync-point spec for an op, or ok=false when none is
// declared. The modulo mirrors g4RunOp's own dispatch so a spec lookup and the
// op actually executed can never disagree.
func g5SpecFor(op g4Op) (g5SyncSpec, bool) {
	s, ok := g5OpSyncPoints[op.kind%g4NumOpKinds]
	return s, ok
}

// --- pending-seed registry ---------------------------------------------------

// g5SeedCase is one pending seed replayed deterministically: the issue it
// belongs to, and the ordering that reaches its bad end state.
//
// The op pair is NOT repeated here — it is read from the seed file in
// testdata/fuzz-pending/<issue>/ at run time, so this registry and the fuzzer's
// own corpus cannot drift apart. A row whose seed file is missing fails.
type g5SeedCase struct {
	issue string
	// stale names which of the seed's two ops is the one whose write lands on
	// a stale check: "A" for pair[0] (replica c0), "B" for pair[1] (c1).
	//
	// That one fact determines the whole interleaving, which is why the
	// registry records it instead of an ordering string: the bad end state in
	// every one of these issues is reached by pausing the STALE WRITER between
	// its check and its write, letting the other op run to completion, then
	// letting the stale write land. Naming the side rather than the ordering
	// also makes a wrong row obvious on inspection — "which op writes stale
	// data" is a property of the issue, while "A-check,B-check,B-act,A-act"
	// has to be mentally re-derived against the seed's byte order every time.
	stale string
	// why names the end state this ordering reaches, for the failure message.
	why string
	// pre runs after g4ResetIteration and before the pair, for a seed whose
	// bad interleaving needs fixture state the fuzzer's world does not have.
	// No row needs it since #2831 promoted #2657 (the only user) to the live
	// corpus; the hook is kept because the gap it covered is still open — the
	// fuzzer's world cannot reach every state a seed may require, and closing
	// that inside the fuzzer means new op kinds, which changes g4NumOpKinds and
	// so reinterprets every byte of every existing seed. See the PR body.
	pre func(t *testing.T, w *g4World)
}

// g5SeedCases: one row per pending seed, naming the stale writer.
//
// Only the stale writer gets a sync point. The other op runs to completion in
// that window — necessary, not merely simpler: a destructive op's decisive
// write is often a DELETE of rows the concurrent constructive op has not
// inserted yet (TransitionMembership's revoke removes a role grant that the
// racing activation is about to create), so there is no statement for a sync
// point to sit on and arming one would time out and report DEGRADED. See the
// nil-sync-point path in interleave_sync_points_test.go.
// #2831 promoted nine of the original twelve seeds (2646, 2647, 2649, 2652,
// 2653, 2654, 2655, 2656, 2657) out of testdata/fuzz-pending/ and into
// testdata/fuzz/FuzzCrossReplicaInvariants/, so their regression coverage is
// now the live corpus rather than a forced ordering here. Their rows are gone
// accordingly: a g5SeedCases row whose seed dir no longer exists is what
// TestG5SyncPointSpecsCoverEveryPendingSeed rejects.
var g5SeedCases = []g5SeedCase{
	// seed (DeleteSecret, SetSecretAutoRotate): the full-row Save is stale.
	{issue: "2650", stale: "B", why: "a secret undeleted by a stale full-row Save"},
	// seed (DeleteProject, CreateDynamicSecretConfig): the second Save is stale.
	{issue: "2651", stale: "B", why: "an enabled dynamic-secret config under a deleted project"},
	// seed (revoke, InviteMember): the invite's grant INSERT is stale.
	{issue: "2659", stale: "B", why: "a revoked membership still holding an invite's role grant"},
}

// order returns the driver ordering that pauses this row's stale writer.
func (c g5SeedCase) order() interleaveOrder {
	if c.stale == "A" {
		return orderABBaAa
	}
	return orderBAAaBa
}

// g5SeedBytes reads the single fuzz corpus entry in
// testdata/fuzz-pending/<issue>/ and decodes its []byte(...) literal.
//
// Go's corpus format is a two-line file: a `go test fuzz v1` header and one
// `[]byte("...")` line per fuzz argument. FuzzCrossReplicaInvariants takes
// exactly one []byte argument, so exactly one such line is expected; anything
// else is an error rather than a best-effort parse.
func g5SeedBytes(t *testing.T, issue string) []byte {
	t.Helper()
	dir := filepath.Join("testdata", "fuzz-pending", issue)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "reading %s", dir)
	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	require.Len(t, files, 1, "expected exactly one seed file in %s, got %v", dir, files)

	raw, err := os.ReadFile(files[0]) //nolint:gosec // our own testdata
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.GreaterOrEqual(t, len(lines), 2, "corpus file %s is missing its []byte line", files[0])
	require.Equal(t, "go test fuzz v1", strings.TrimSpace(lines[0]),
		"corpus file %s does not start with the Go fuzz v1 header", files[0])

	m := regexp.MustCompile(`^\[\]byte\("(.*)"\)$`).FindStringSubmatch(strings.TrimSpace(lines[1]))
	require.NotNil(t, m, "corpus line %q in %s is not a []byte(\"...\") literal", lines[1], files[0])
	unquoted, err := strconv.Unquote(`"` + m[1] + `"`)
	require.NoError(t, err, "unquoting the []byte literal in %s", files[0])
	return []byte(unquoted)
}

// --- the test ----------------------------------------------------------------

// g5NewSyncPoint places a sync point for op on the given replica's own pool.
func g5NewSyncPoint(t *testing.T, db *gorm.DB, op g4Op, label string) *syncPoint {
	t.Helper()
	spec, ok := g5SpecFor(op)
	require.True(t, ok,
		"no sync-point spec for op kind %d (replica %s) — add it to g5OpSyncPoints; "+
			"without one this pair would fall back to a blind race, which is exactly what this file exists to stop",
		op.kind%g4NumOpKinds, label)
	return newSyncPoint(t, db, spec.fn, spec.kind, spec.table)
}

// TestForcedPendingSeeds_Postgres is item 2's deliverable: every pending seed,
// replayed through its forced ordering, asserted in whichever direction
// pendingSeedFix says applies right now.
func TestForcedPendingSeeds_Postgres(t *testing.T) {
	// Not t.Parallel at the top level: every subtest shares one world (one
	// Postgres schema, one fixture), because building the world costs more
	// than every forced interleaving in this file put together. Subtests run
	// sequentially and each starts from g4ResetIteration's baseline.
	w := buildG4World(t)

	for _, tc := range g5SeedCases {
		tc := tc
		t.Run(tc.issue, func(t *testing.T) {
			seed := g5SeedBytes(t, tc.issue)
			pairs := decodeG4Pairs(seed)
			require.Len(t, pairs, 1,
				"seed for #%s decodes to %d pairs; this registry assumes one pair per pending seed", tc.issue, len(pairs))
			pair := pairs[0]

			campaignID := g4ResetIteration(t, w)
			w.mu.Lock()
			w.campaignID = campaignID
			w.mu.Unlock()
			if tc.pre != nil {
				tc.pre(t, w)
			}
			require.Empty(t, g4FindViolation(t, w),
				"the reset baseline already violates an invariant, so nothing this subtest observes can be attributed to the forced ordering")

			var spA, spB *syncPoint
			if tc.stale == "A" {
				spA, spB = interleavePauseA(g5NewSyncPoint(t, w.db0, pair[0], "A"))
			} else {
				spA, spB = interleavePauseB(g5NewSyncPoint(t, w.db1, pair[1], "B"))
			}

			order := tc.order()
			// 3 s rather than the driver's 15 s default. Every one of these
			// pairs reaches its sync point in well under 0.4 s while its issue
			// is open, so 3 s is ~10x headroom; and once a fix SERIALIZES the
			// pair, waiting the full default would be dead wall-clock on
			// twelve subtests. Fail-safe in the direction that matters: a
			// bogus "blocked" verdict on a still-open issue makes
			// requireForced fail loudly below, it cannot turn into a silent
			// pass.
			res := runInterleavingTimeout(t, order, spA, spB,
				func() error { g4RunOp(t, w, w.c0, pair[0]); return nil },
				func() error { g4RunOp(t, w, w.c1, pair[1]); return nil },
				3*time.Second,
			)

			violation := g4FindViolation(t, w)
			fixPR, stillOpen := pendingSeedFix[tc.issue]
			if stillOpen {
				// The reproduction premise: while the issue is open the
				// ordering must be realizable exactly as asked, or this
				// subtest proves nothing about it.
				requireForced(t, res)
				require.NotEmpty(t, violation,
					"#%s is still listed in pendingSeedFix (fix PR #%d not merged), but the %s ordering no longer reaches %s.\n"+
						"Either the fix landed and the pendingSeedFix row + this seed need promoting, or the bug changed shape and the issue needs re-reading. Trace: %s",
					tc.issue, fixPR, order, tc.why, res.String())
				t.Logf("#%s reproduced deterministically under %s: %s", tc.issue, order, violation)
				return
			}

			// The fix has landed. Forced is deliberately NOT required here:
			// a fix that works by SERIALIZING the two replicas (a named or
			// advisory lock — #2669's and #2670's shape) makes the
			// interleaved ordering unreachable by construction, and the
			// driver reports that as Degraded. Demanding Forced would fail
			// the test for the very reason the fix is correct. What must
			// hold either way is the invariant.
			t.Log(res.String())
			require.Empty(t, violation,
				"#%s's fix has landed (no pendingSeedFix row) but the %s ordering still reaches %s. Trace: %s",
				tc.issue, order, tc.why, res.String())
		})
	}
}

// TestG4PairAlwaysSpansBothReplicas is the machine check for the fuzzer defect
// this file's header describes: the two ops of a pair must land on two
// DIFFERENT replicas, for every op-kind pair, unconditionally.
//
// Red on the pre-fix code (g4Replica chose by `kind%2`): any two kinds of the
// same parity collapsed onto one replica — including six of the twelve pending
// seeds. Green now, by construction. Kept as a test rather than trusted to the
// one-line implementation because the failure is completely silent: a
// same-replica "race" still passes every invariant, just without ever having
// been a cross-replica race.
func TestG4PairAlwaysSpansBothReplicas(t *testing.T) {
	t.Parallel()
	w := &g4World{c0: &KeyorixCore{}, c1: &KeyorixCore{}}
	require.NotSame(t, g4Replica(w, 0), g4Replica(w, 1),
		"a pair's two ops must run on two different replicas, or it is not a cross-replica race at all")
	// And the choice must not depend on the op kind in any way: the only
	// inputs are the pair positions 0 and 1.
	for kind := 0; kind < g4NumOpKinds; kind++ {
		require.Same(t, w.c0, g4Replica(w, 0), "position 0 must always be replica c0 (op kind %d)", kind)
		require.Same(t, w.c1, g4Replica(w, 1), "position 1 must always be replica c1 (op kind %d)", kind)
	}
}

// TestG5SyncPointSpecsCoverEveryPendingSeed fails when a pending seed names an
// op kind with no sync-point spec, WITHOUT needing Postgres — so a seed added
// to testdata/fuzz-pending/ that this file cannot force is caught in the
// no-DSN quick CI path, not only in the Postgres leg.
func TestG5SyncPointSpecsCoverEveryPendingSeed(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(filepath.Join("testdata", "fuzz-pending"))
	require.NoError(t, err)

	registered := map[string]bool{}
	for _, tc := range g5SeedCases {
		registered[tc.issue] = true
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		issue := e.Name()
		require.True(t, registered[issue],
			"testdata/fuzz-pending/%s/ has no g5SeedCases row — add one naming the ordering that reproduces #%s, "+
				"or this seed stays a blind-luck seed and must not be promoted", issue, issue)

		seed := g5SeedBytes(t, issue)
		pairs := decodeG4Pairs(seed)
		require.Len(t, pairs, 1, "seed for #%s must decode to exactly one pair", issue)
		for i, op := range pairs[0] {
			spec, ok := g5SpecFor(op)
			require.True(t, ok, "#%s op %d (kind %d) has no g5OpSyncPoints entry", issue, i, op.kind%g4NumOpKinds)
			require.Contains(t, []string{"create", "update", "delete"}, spec.kind,
				"#%s op %d names GORM callback family %q, which newSyncPoint cannot register", issue, i, spec.kind)
		}
	}

	// And the converse: no g5SeedCases row may name an issue with no seed dir.
	for _, tc := range g5SeedCases {
		_, err := os.Stat(filepath.Join("testdata", "fuzz-pending", tc.issue))
		require.NoError(t, err,
			"g5SeedCases has a row for #%s but testdata/fuzz-pending/%s/ does not exist — "+
				"if the seed was promoted, delete the row (it is covered by the live corpus now)", tc.issue, tc.issue)
	}
}
