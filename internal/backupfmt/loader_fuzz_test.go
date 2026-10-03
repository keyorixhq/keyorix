package backupfmt

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// fuzzSchemaDeltaCurrentColumns is a fixed stand-in "current model" for
// FuzzCheckSchemaDelta -- the fuzzer mutates the ARCHIVED side (what an
// untrusted manifest declares a table's columns were), never this side,
// matching checkSchemaDelta's real signature (currentColumns always comes
// from the live, compiled-in binary's own schema.Parse result, never from
// archive content).
var fuzzSchemaDeltaCurrentColumns = []string{"id", "name", "project_id", "created_at", "updated_at"}

// FuzzCheckSchemaDelta is SESSION-BV target 3's "preflight-accept implies
// load succeeds" half, applied to loader.go's own detection layer (design
// §3.5): checkSchemaDelta must accept a table's declared columns if and only
// if every one of them is either a column the current model still has, or
// explicitly listed in knownRemovedColumns for that model -- never silently
// accept a column that is neither (which is exactly the renamed/type-changed
// hazard this check exists to catch before a single row is loaded). Pure
// function, no DB -- fuzzing the declared column list directly rather than
// indirectly through a built archive keeps this fast and makes a counter-
// example's exact violating column immediately visible in the failure.
func FuzzCheckSchemaDelta(f *testing.F) {
	f.Add("id,name,project_id,created_at,updated_at") // every column known -- must accept
	f.Add("")                                         // no columns declared -- vacuously must accept
	f.Add("id,a_column_that_was_renamed")             // design §3.5's own regression case -- must refuse
	f.Add("id,id,id")                                 // duplicates of a known column -- must still accept
	f.Add(",,,")                                      // empty-string "columns" -- must refuse unless "" is itself a known column (it isn't)
	f.Add("ID,Name")                                  // case-mismatched -- column names are case-sensitive DB names, must refuse

	f.Fuzz(func(t *testing.T, columnsCSV string) {
		var columns []string
		if columnsCSV != "" {
			columns = strings.Split(columnsCSV, ",")
		}

		err := checkSchemaDelta("FuzzModel", fuzzSchemaDeltaCurrentColumns, TableEntry{Name: "fuzz_table", Columns: columns})

		current := make(map[string]bool, len(fuzzSchemaDeltaCurrentColumns))
		for _, c := range fuzzSchemaDeltaCurrentColumns {
			current[c] = true
		}
		allKnown := true
		for _, c := range columns {
			if !current[c] { // knownRemovedColumns is empty today (see loader.go) -- "known" reduces to "current" for this model
				allKnown = false
				break
			}
		}

		if allKnown && err != nil {
			t.Fatalf("checkSchemaDelta refused columns %v, which are all known to the current model: %v", columns, err)
		}
		if !allKnown && err == nil {
			t.Fatalf("checkSchemaDelta accepted columns %v, which include at least one column neither current nor "+
				"on the known-removed allowlist -- design §3.5's whole point is to refuse exactly this", columns)
		}
	})
}

// FuzzLoadArchiveIgnoresManifestTableOrder is SESSION-BV target 3's "table
// order is a valid FK topological order for any accepted manifest" half:
// LoadArchive derives its own insert order from RestoreOrder() (order.go),
// never from the order manifest.Tables happens to list entries in -- the
// manifest field is informational/for hashing (manifest.go's own doc
// comment), not something restore trusts for sequencing. This fuzzes the
// one bit that actually varies here (Project-before-Environment or
// Environment-before-Project in the manifest's own Tables slice, and
// therefore in the staged archive's physical tar layout) and directly
// observes the real INSERT sequence via a GORM callback -- not merely
// whether the load reports success.
//
// Observing the outcome alone is NOT a sound oracle here: this schema has no
// real SQL-level FOREIGN KEY constraints (confirmed by inspection -- no
// model declares a `Project Project` association field GORM would turn into
// one; loader.go's own doc comment on CheckDanglingReferences calls this out
// explicitly as "the deferred-FK-constraint safety net a schema with real FK
// constraints would have had"), so SQLite never rejects an out-of-order
// insert regardless of PRAGMA foreign_keys, and CheckDanglingReferences only
// runs once, after every table has already loaded -- an outcome-only
// assertion would pass identically whether or not LoadArchive actually
// respected manifest order, i.e. it would prove nothing. Capturing the
// callback-observed table sequence and asserting "projects" precedes
// "environments" in it is the only part of this test that can actually fail.
func FuzzLoadArchiveIgnoresManifestTableOrder(f *testing.F) {
	f.Add(false)
	f.Add(true)

	f.Fuzz(func(t *testing.T, listEnvironmentFirst bool) {
		src := openTestDB(t)
		proj := models.Project{Name: "proj-1"}
		require.NoError(t, src.Create(&proj).Error)
		env := models.Environment{Name: "prod", ProjectID: proj.ID}
		require.NoError(t, src.Create(&env).Error)

		testModels := []any{&models.Project{}, &models.Environment{}}
		var archive bytes.Buffer
		writtenManifest, err := writeBackupModels(src, testModels, 1, "", testManifestKey(), nil, nil, &archive)
		require.NoError(t, err)
		require.Empty(t, writtenManifest.DanglingReferences)
		require.Len(t, writtenManifest.Tables, 2, "fuzz input assumes exactly Project and Environment were written")

		stagingDir := t.TempDir()
		extractedManifest, err := ExtractArchive(bytes.NewReader(archive.Bytes()), stagingDir, 0, 0)
		require.NoError(t, err)

		// writeBackupModels always writes Project before Environment in the
		// manifest (it follows RestoreOrder() itself); reorder the PARSED,
		// already-extracted manifest's Tables slice to the fuzzed order
		// before loading -- LoadArchive must not care, since it re-derives
		// insert order from the live model registry, not from this field.
		if listEnvironmentFirst {
			extractedManifest.Tables[0], extractedManifest.Tables[1] = extractedManifest.Tables[1], extractedManifest.Tables[0]
		}

		dst := openTestDB(t)
		var insertSequence []string
		require.NoError(t, dst.Callback().Create().Before("gorm:create").
			Register("fuzz-record-insert-order", func(tx *gorm.DB) {
				tbl := tx.Statement.Table
				if len(insertSequence) == 0 || insertSequence[len(insertSequence)-1] != tbl {
					insertSequence = append(insertSequence, tbl)
				}
			}))

		loadErr := dst.Transaction(func(tx *gorm.DB) error {
			return LoadArchive(tx, extractedManifest, stagingDir)
		})
		require.NoError(t, loadErr, "LoadArchive must succeed regardless of manifest.Tables declaration order "+
			"(listEnvironmentFirst=%v)", listEnvironmentFirst)

		projIdx, envIdx := -1, -1
		for i, tbl := range insertSequence {
			switch tbl {
			case "projects":
				projIdx = i
			case "environments":
				envIdx = i
			}
		}
		require.GreaterOrEqual(t, projIdx, 0, "projects was never inserted into -- sequence: %v", insertSequence)
		require.GreaterOrEqual(t, envIdx, 0, "environments was never inserted into -- sequence: %v", insertSequence)
		require.Less(t, projIdx, envIdx,
			"LoadArchive inserted environments (position %d) before projects (position %d) -- insert order %v "+
				"followed manifest.Tables declaration order (listEnvironmentFirst=%v) instead of RestoreOrder()'s "+
				"FK-respecting order", envIdx, projIdx, insertSequence, listEnvironmentFirst)

		var envCount int64
		require.NoError(t, dst.Model(&models.Environment{}).Count(&envCount).Error)
		require.Equal(t, int64(1), envCount)
	})
}
