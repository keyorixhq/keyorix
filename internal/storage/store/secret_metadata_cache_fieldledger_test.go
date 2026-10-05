// secret_metadata_cache_fieldledger_test.go — coordinator review of #2764,
// 2026-10-05, item 2: `(updated_at, read_count)` is a CLOCK-derived stamp and
// cannot be proven tie-free. `updated_at` is computed in Go by the writer and
// stored at microsecond precision on PostgreSQL, so two UpdateSecret calls to
// the same row from two replicas inside one microsecond produce the same value;
// a warm entry then validates and the pre-write row is served. Clock skew makes
// the second write's timestamp differ (safe) more often than not, but "usually
// differs" is a probability argument, and the review correctly refused one.
//
// The non-clock component added instead is the row's own CONTENT: the stamp
// covers every persisted column except the ones listed below. A tie therefore
// requires the cached row and the committed row to agree on every covered
// column — so a tie cannot produce a wrong answer, rather than merely being
// unlikely to.
//
// These tests are what keeps that claim true as the models change: a new
// persisted field on models.SecretNode (or models.SecretAccessSchedule) must
// either be in the stamp or be listed here with a reason. Deriving the field
// set from the model by reflection rather than hand-listing it is the point —
// a hand list is exactly the enumeration that goes stale.
package store

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// nodeGenerationExcludedFields are the models.SecretNode fields deliberately
// NOT part of the node stamp, one justification each.
//
// The first three are the whole reason the cache is worth having: they are the
// large columns a full row fetch pays for, and no authorization or read-gate
// decision reads them. The rest are structural.
var nodeGenerationExcludedFields = map[string]string{
	"Description": "free-text operator note (models.go: \"Metadata only; never the value\"). Read for display and audit text only — no authorization or read-gate decision consults it. Excluded on purpose: together with Metadata it is the cost a stamp read avoids.",
	"Metadata":    "caller-supplied JSON blob, display/integration only, never a decision input. Same cost reason as Description.",
	"ID":          "the cache KEY itself — an entry is looked up by it, so it cannot differ between the stamp and the cached row.",
	"DeletedAt":   "handled structurally, not by comparison: liveNodeGeneration queries through Model(&SecretNode{}), which auto-scopes deleted_at IS NULL, so a soft-deleted row returns not-found and the caller treats that as a miss (TestGetSecret_CacheReflectsDeleteSecret, and the \"GetSecret / node soft-delete\" race row).",
	"ValueStored": "not persisted (`gorm:\"-\"`) — a transient in-process signal (#499) that no read ever loads from the database.",
}

// scheduleGenerationExcludedFields is the same ledger for
// models.SecretAccessSchedule. The schedule row is small and every policy
// column IS in the stamp, so the exclusions are purely structural — which is
// what makes the schedule stamp complete rather than merely cheap.
var scheduleGenerationExcludedFields = map[string]string{
	"ID":           "surrogate key; nothing authorizes on it, and a schedule is addressed by SecretNodeID.",
	"SecretNodeID": "the cache KEY itself.",
	"CreatedAt":    "immutable after insert, so it cannot differ between two writes that tie on updated_at.",
}

func TestNodeGeneration_CoversEveryPersistedSecretNodeField(t *testing.T) {
	t.Parallel()
	assertGenerationCoversModel(t,
		reflect.TypeOf(models.SecretNode{}),
		reflect.TypeOf(nodeGeneration{}),
		nodeGenerationExcludedFields,
		"nodeGeneration / nodeGenerationOf (secret_metadata_cache.go)",
	)

	// The SQL column list must match the struct coverage, or the stamp read
	// would scan columns the comparison ignores (wasted I/O) or — far worse —
	// leave a covered field zero-valued on every read, which would make the
	// stamp compare equal when the row had actually changed.
	require.Len(t, nodeGenerationColumns, coveredFieldCount(
		reflect.TypeOf(models.SecretNode{}), nodeGenerationExcludedFields),
		"nodeGenerationColumns must name exactly the covered fields; a covered field missing from the SELECT reads back as zero on every stamp read, which makes two different rows compare equal")
}

func TestScheduleGeneration_CoversEveryPersistedScheduleField(t *testing.T) {
	t.Parallel()
	assertGenerationCoversModel(t,
		reflect.TypeOf(models.SecretAccessSchedule{}),
		reflect.TypeOf(scheduleGeneration{}),
		scheduleGenerationExcludedFields,
		"scheduleGeneration / scheduleGenerationOf (secret_metadata_cache.go)",
	)
}

// assertGenerationCoversModel checks that every persisted field of modelType is
// either represented in genType or listed in excluded with a non-empty reason.
//
// Matching is by normalised name: a model field Foo is covered when genType has
// a field whose name, lowercased and stripped of the suffixes this package uses
// for normalising non-comparable values (UnixNano) or optionality (the `has`
// prefix), equals the model field's lowercased name. Stated explicitly because
// a name-based match is the recognised shape here, and a covered field that
// does not follow the convention will read as uncovered — which fails loudly
// rather than silently passing.
func assertGenerationCoversModel(t *testing.T, modelType, genType reflect.Type, excluded map[string]string, what string) {
	t.Helper()

	genNames := map[string]bool{}
	for i := 0; i < genType.NumField(); i++ {
		n := strings.ToLower(genType.Field(i).Name)
		n = strings.TrimSuffix(n, "unixnano")
		n = strings.TrimPrefix(n, "has")
		genNames[n] = true
	}
	// "typ" stands in for the model's `Type` field, which collides with nothing
	// but cannot be spelled `type` in Go.
	if genNames["typ"] {
		genNames["type"] = true
	}

	var uncovered, staleExclusions []string
	seen := map[string]bool{}
	for i := 0; i < modelType.NumField(); i++ {
		f := modelType.Field(i)
		if f.Tag.Get("gorm") == "-" && excluded[f.Name] == "" {
			uncovered = append(uncovered, f.Name+" (not persisted, but list it in the exclusion ledger with that reason)")
			continue
		}
		seen[f.Name] = true
		if reason, ok := excluded[f.Name]; ok {
			require.NotEmpty(t, reason, "exclusion ledger entry for %s must carry a reason", f.Name)
			continue
		}
		if !genNames[strings.ToLower(f.Name)] {
			uncovered = append(uncovered, f.Name)
		}
	}
	for name := range excluded {
		if !seen[name] {
			staleExclusions = append(staleExclusions, name)
		}
	}

	sort.Strings(uncovered)
	sort.Strings(staleExclusions)
	require.Empty(t, uncovered,
		"%s does not cover these %s fields, and they are not in its exclusion ledger:\n  %s\n\n"+
			"A field outside the stamp can change without changing the generation, so a warm cache entry keeps serving the pre-change value. "+
			"Either add it to the stamp (and to the SELECT column list), or add it to the ledger in this file with the reason its staleness cannot matter.",
		what, modelType.Name(), strings.Join(uncovered, "\n  "))
	require.Empty(t, staleExclusions,
		"the exclusion ledger for %s names fields that no longer exist on %s: %s",
		what, modelType.Name(), strings.Join(staleExclusions, ", "))
}

func coveredFieldCount(modelType reflect.Type, excluded map[string]string) int {
	n := 0
	for i := 0; i < modelType.NumField(); i++ {
		f := modelType.Field(i)
		if f.Tag.Get("gorm") == "-" {
			continue
		}
		if _, ok := excluded[f.Name]; ok {
			continue
		}
		n++
	}
	return n
}

// TestNodeGeneration_StampIsStableAcrossTwoReadsOfOneRow is the green-direction
// calibration the stamp needs: a stamp built from ~25 columns, several of them
// normalised pointers and times, must compare EQUAL for two reads of an
// unchanged row. A stamp that never compares equal is a cache that never hits —
// a pure performance failure no correctness test would notice.
func TestNodeGeneration_StampIsStableAcrossTwoReadsOfOneRow(t *testing.T) {
	t.Parallel()
	ls := newCacheTestStorage(t)
	ctx := context.Background()
	maxReads := 3
	expiry := time.Now().Add(24 * time.Hour)
	created, err := ls.CreateSecret(ctx, &models.SecretNode{
		Name: "x", ProjectID: 1, EnvironmentID: 1, Status: "active",
		MaxReads: &maxReads, Expiration: &expiry, Classification: "restricted",
		RotationBackend: "aws-iam", RotationRef: "role/app",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	first, found, err := liveNodeGeneration(ctx, ls.db, created.ID)
	require.NoError(t, err)
	require.True(t, found)
	second, found, err := liveNodeGeneration(ctx, ls.db, created.ID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, first, second, "two stamp reads of an unchanged row must compare equal, or the cache never hits")

	// And the same row loaded in FULL must stamp identically to the stamp-only
	// read — otherwise GetSecret (which stamps from the full row) and a later
	// hit check (which stamps from the column subset) would never agree.
	full, err := ls.GetSecret(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, first, nodeGenerationOf(full),
		"the stamp derived from a full row must equal the stamp read from the column subset, or GetSecret's entry can never be validated")
}
