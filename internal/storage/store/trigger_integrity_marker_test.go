// trigger_integrity_marker_test.go — TRIGGER-INTEGRITY-1 item 1 (#3717): the
// version-marker rule (pgTriggerDef.newerThan) on synthetic catalog facts, no
// database needed. The PostgreSQL tests drive the same rule against a real
// catalog.
package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// installedFacts are the facts the catalog holds for d as its installer
// creates it.
func installedFacts(d *pgTriggerDef) triggerDefFacts {
	f := triggerDefFacts{lang: "plpgsql", config: pgTriggerFuncConfigText, body: d.body}
	for _, t := range d.triggers {
		f.triggers = append(f.triggers, triggerShapeFacts{table: t.table, name: t.trigger, tgtype: d.tgtype})
	}
	return f
}

func TestTriggerDefMarker_OwnMarkersParse(t *testing.T) {
	for _, d := range []*pgTriggerDef{rolePermGenerationDef, secretNodeCacheEpochDef} {
		m := triggerDefMarkerRE.FindStringSubmatch(d.marker())
		require.NotNil(t, m, d.marker())
		require.Equal(t, d.funcName, m[1])
		require.Equal(t, triggerDefDigest(d.funcName, d.version, installedFacts(d)), m[3])
	}
}

// TestTriggerDefMarker_TestReleaseLiterals pins the v2 markers the
// PostgreSQL rolling-upgrade tests install by literal (they also run against
// the release before markers, which cannot compute them).
func TestTriggerDefMarker_TestReleaseLiterals(t *testing.T) {
	for _, tc := range []struct {
		def          *pgTriggerDef
		body, marker string
	}{{rolePermGenerationDef, rpgV2Body, rpgV2Marker}, {secretNodeCacheEpochDef, cacheEpochV2Body, cacheEpochV2Marker}} {
		d := *tc.def
		d.version, d.body = 2, tc.body
		require.Equal(t, tc.marker, d.marker(), "regenerate the literal when the trigger shape or pinned settings change")
	}
}

// TestTriggerDefMarker_ThisReleaseLiterals pins this release's own markers by
// literal, so a change to a body, its settings or a trigger's shape without a
// version bump fails here. Two releases at one version with different
// definitions would each restore its own over the other's (#3717). On a
// failure, bump the def's version and then update the literal; never update
// only the literal.
func TestTriggerDefMarker_ThisReleaseLiterals(t *testing.T) {
	require.Equal(t, "keyorix-trigger-def keyorix_bump_role_permissions_generation v1 sha256:9aea9a29c5654b35953ed726ad7d659e9ba2c03aab91b17de9bc5e77158683b7",
		rolePermGenerationDef.marker())
	require.Equal(t, "keyorix-trigger-def keyorix_secret_nodes_bump_cache_epoch v1 sha256:2b68c58c2646b8298eab807c8a4f6a0391c0ef25f95042d23284e46cbab1d73e",
		secretNodeCacheEpochDef.marker())
}

func TestTriggerDefMarker_NewerThan(t *testing.T) {
	n := rolePermGenerationDef // v1
	next := *n
	next.version, next.body = 2, rpgV2Body
	facts := installedFacts(&next)
	fn := n.funcName
	far := next
	far.version = 3
	cases := []struct {
		name, marker, proname string
		pronargs              int64
		sameNS                bool
		facts                 triggerDefFacts
		ok                    bool
		why                   string
	}{
		{"newer release", next.marker(), fn, 0, true, facts, true, ""},
		{"no marker", "", fn, 0, true, facts, false, "carries no version marker"},
		{"malformed", "keyorix-trigger-def " + fn + " v2", fn, 0, true, facts, false, "malformed"},
		{"trailing text", next.marker() + " ", fn, 0, true, facts, false, "malformed"},
		{"own version", n.marker(), fn, 0, true, installedFacts(n), false, "not this release's v1"},
		{"too far ahead", far.marker(), fn, 0, true, installedFacts(&far), false, "more than 1 ahead"},
		{"another function's marker", strings.Replace(next.marker(), fn, "other_fn", 1), fn, 0, true, facts, false, "does not name"},
		{"function in another schema", next.marker(), fn, 0, false, facts, false, "does not name"},
		{"body changed", next.marker(), fn, 0, true, func() triggerDefFacts { f := facts; f.body += " "; return f }(), false, "digest"},
		{"settings changed", next.marker(), fn, 0, true, func() triggerDefFacts { f := facts; f.config = `{search_path=public}`; return f }(), false, "digest"},
		{"security definer", next.marker(), fn, 0, true, func() triggerDefFacts { f := facts; f.secdef = true; return f }(), false, "digest"},
		{"trigger shape changed", next.marker(), fn, 0, true, func() triggerDefFacts {
			f := facts
			f.triggers = append([]triggerShapeFacts(nil), f.triggers...)
			f.triggers[0].tgtype = 4 | 1 // AFTER INSERT, FOR EACH ROW
			return f
		}(), false, "digest"},
		{"trigger order does not matter", next.marker(), fn, 0, true, func() triggerDefFacts {
			f := facts
			f.triggers = []triggerShapeFacts{facts.triggers[1], facts.triggers[0]}
			return f
		}(), true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why, ok := n.newerThan(tc.marker, tc.proname, tc.pronargs, tc.sameNS, tc.facts)
			require.Equal(t, tc.ok, ok, why)
			if !tc.ok {
				require.Contains(t, why, tc.why)
			}
		})
	}
}

// TestRolePermGenerationTarget_FenceAllowedOnlyInSingleWriterMode: the
// single_writer fence's triggers on system_metadata are allowed by the check
// and its repair only in single_writer mode (PR #3841 review F1), and that
// mode comes from SetSingleWriter.
func TestRolePermGenerationTarget_FenceAllowedOnlyInSingleWriterMode(t *testing.T) {
	ls := &LocalStorage{}
	require.Same(t, rolePermGenerationIntegrityTarget, ls.rolePermGenerationTarget())
	require.NotContains(t, rolePermGenerationIntegrityTarget.def.sql, SoleWriterGuardFunc)
	require.NotContains(t, systemMetadataAllowedTriggerOK(false), SoleWriterGuardFunc)
	ls.SetSingleWriter(true)
	require.Same(t, rolePermGenerationSingleWriterIntegrityTarget, ls.rolePermGenerationTarget())
	require.Contains(t, rolePermGenerationSingleWriterIntegrityTarget.def.sql, SoleWriterGuardFunc)
	require.Contains(t, systemMetadataAllowedTriggerOK(true), SoleWriterGuardFunc)
	// Both read the same definition: only the write-target check differs.
	require.Equal(t, rolePermGenerationDef.marker(), rolePermGenerationSingleWriterIntegrityTarget.def.marker())
}
