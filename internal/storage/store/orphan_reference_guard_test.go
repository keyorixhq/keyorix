// orphan_reference_guard_test.go — SESSION-AT AT4: a CI-enforced guard
// against the DeleteRole class of bug (SESSION-AT AT1 row 2, PR #2357): a
// storage Delete* hard-deleting a row while another table still holds a
// row referencing its ID, because the referencing column is a plain uint
// scalar (not a GORM association), so AutoMigrate creates no FK constraint
// on either backend to catch it.
//
// The reference map (which model's field points at which other model) is
// DERIVED from the models via reflection over kxstorage.AllModels() --
// internal/storage/all_models.go's own machine-checked SSOT for "every
// table this binary migrates" (TestAllModels_MatchesLiveMigratedTables
// keeps IT honest) -- not a hand-maintained list here. A field named
// "XxxID" (uint or *uint, not the struct's own "ID") whose name ends with
// another model's struct name is treated as a reference to that model. This
// catches both exact matches (RoleID -> Role) and role-qualified prefixes
// (OwnerMachineIdentityID -> MachineIdentity), since any uppercase letter in
// a Go PascalCase identifier marks a new word boundary, making a trailing
// exact-case substring match structurally safe.
//
// Scope: only SINGLE-ID hard deletes are auto-verified -- a Delete<Model>
// method on *LocalStorage shaped (ctx context.Context, id uint) -> (..., error).
// A model with no DeletedAt field is soft-delete-safe by this codebase's own
// established pattern (query-time filtering on the parent's own deleted_at)
// and is skipped. A Delete method that doesn't match the single-ID shape
// (a bulk-by-time purge, a bulk-by-parent-ID sweep, a compound-key delete)
// is logged as out of this guard's scope, not silently treated as safe --
// see TestLogOrphanGuardSkips's own output for the full list each run.
//
// orphanGuardAllowlist is the explicit, human-maintained exception list for
// a referencing pair confirmed safe to leave unguarded, each with a
// one-line reason -- required for BreakGlassActivation/AccessReviewItem
// (history/compliance records that must survive a Role delete, PR #2357)
// and extend-as-needed for any future confirmed-safe pair.
//
// package store_test (not store): needs kxstorage.MigrateExisting for the
// FULL production schema, which would be an import cycle from inside
// package store itself (internal/storage imports internal/storage/store
// via factory.go) -- same reason local_rbac_deleterole_cascade_test.go is
// external.
package store_test

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// orphanGuardAllowlist[TargetModel][ReferencingModel] = reason.
var orphanGuardAllowlist = map[string]map[string]string{
	"Role": {
		"BreakGlassActivation": "history: the audit trail of a past emergency-access activation; must survive the role being deleted (PR #2357 review)",
		"AccessReviewItem":     "compliance: an explicit frozen snapshot of a grant at campaign-open time -- its own doc comment says the live grant may diverge after capture (PR #2357 review)",
	},
}

// deleteMethodNameOverrides maps a model's struct name to its actual
// DeleteXxx method name on *store.LocalStorage, for the one case found
// where the "Delete"+StructName convention doesn't hold.
var deleteMethodNameOverrides = map[string]string{
	"SecretNode": "DeleteSecret",
}

type orphanRefCandidate struct {
	sourceModel string
	sourceType  reflect.Type
	fieldName   string
	targetModel string
}

// deriveOrphanReferenceCandidates reflects over every model in
// kxstorage.AllModels() and returns every (source, field, target) triple
// where source has a field named "<suffix>ID" (uint/*uint, not the
// struct's own primary-key "ID") whose suffix matches -- exactly, or as a
// trailing PascalCase-word-boundary-safe substring -- another model's
// struct name. When more than one model name matches, the LONGEST wins
// (e.g. "OwnerMachineIdentityID" matches "MachineIdentity", not a shorter
// coincidental match).
func deriveOrphanReferenceCandidates(t *testing.T) []orphanRefCandidate {
	t.Helper()
	models := kxstorage.AllModels()
	typeByName := make(map[string]reflect.Type, len(models))
	names := make([]string, 0, len(models))
	for _, m := range models {
		typ := reflect.TypeOf(m).Elem()
		typeByName[typ.Name()] = typ
		names = append(names, typ.Name())
	}
	// Longest name first, so the suffix-match below prefers the longest
	// (most specific) candidate.
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })

	var out []orphanRefCandidate
	for sourceName, sourceType := range typeByName {
		for i := 0; i < sourceType.NumField(); i++ {
			f := sourceType.Field(i)
			if f.Name == "ID" || !strings.HasSuffix(f.Name, "ID") {
				continue
			}
			kind := f.Type.Kind()
			if kind == reflect.Pointer {
				kind = f.Type.Elem().Kind()
			}
			if kind != reflect.Uint && kind != reflect.Uint64 && kind != reflect.Uint32 {
				continue
			}
			base := strings.TrimSuffix(f.Name, "ID")
			if base == "" {
				continue
			}
			for _, targetName := range names {
				if targetName == sourceName {
					continue // self-reference (e.g. ParentID on SecretNode) -- not this guard's concern
				}
				if base == targetName || strings.HasSuffix(base, targetName) {
					out = append(out, orphanRefCandidate{
						sourceModel: sourceName, sourceType: sourceType,
						fieldName: f.Name, targetModel: targetName,
					})
					break // longest match wins; names is sorted longest-first
				}
			}
		}
	}
	return out
}

// ctxType/uintType are reused by the method-shape check below.
var ctxType = reflect.TypeOf((*context.Context)(nil)).Elem()

// singleIDDeleteMethod returns the reflect.Value of targetType's
// DeleteXxx(ctx, id uint) method on ls, and "", only if that method exists
// AND matches the single-ID shape this guard can auto-invoke: exactly
// (context.Context, uint-kind) in, with the LAST return value being error.
// Otherwise returns a zero Value and a human-readable reason (no such
// method at all -- e.g. MachineIdentity's lifecycle is revoke-only, never a
// hard delete -- vs. a method that exists but doesn't match the shape, e.g.
// a bulk-by-time purge or a compound-key delete) -- the caller logs this
// reason, never silently treats a non-match as a pass.
func singleIDDeleteMethod(ls *store.LocalStorage, targetModel string) (reflect.Value, string) {
	methodName := deleteMethodNameOverrides[targetModel]
	if methodName == "" {
		methodName = "Delete" + targetModel
	}
	m := reflect.ValueOf(ls).MethodByName(methodName)
	if !m.IsValid() {
		return reflect.Value{}, fmt.Sprintf("no %s method on *LocalStorage -- %s is never hard-deleted by a single ID", methodName, targetModel)
	}
	mt := m.Type()
	if mt.NumIn() != 2 || mt.In(0) != ctxType {
		return reflect.Value{}, fmt.Sprintf("%s has %d arg(s), not (context.Context, uint) -- a compound-key or differently-shaped delete, out of this guard's scope", methodName, mt.NumIn())
	}
	argKind := mt.In(1).Kind()
	if argKind != reflect.Uint && argKind != reflect.Uint64 && argKind != reflect.Uint32 {
		return reflect.Value{}, fmt.Sprintf("%s's second arg is %s, not a uint-kind id -- out of this guard's scope", methodName, argKind)
	}
	if mt.NumOut() == 0 {
		return reflect.Value{}, fmt.Sprintf("%s returns no values -- out of this guard's scope", methodName)
	}
	if !mt.Out(mt.NumOut() - 1).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
		return reflect.Value{}, fmt.Sprintf("%s's last return value is not an error -- out of this guard's scope", methodName)
	}
	return m, ""
}

func hasDeletedAtField(t reflect.Type) bool {
	_, ok := t.FieldByName("DeletedAt")
	return ok
}

// TestOrphanReferenceGuard_EveryHardDeleteCascadesOrIsAllowlisted is the
// AT4 guard itself.
func TestOrphanReferenceGuard_EveryHardDeleteCascadesOrIsAllowlisted(t *testing.T) {
	candidates := deriveOrphanReferenceCandidates(t)
	require.NotEmpty(t, candidates, "the reflection-derived reference map must not be empty -- if this fires, deriveOrphanReferenceCandidates itself is broken, not that there are genuinely zero cross-model references")

	namer := schema.NamingStrategy{}
	var verified, skippedSoftDelete, skippedAllowlisted int

	for _, c := range candidates {
		targetType, ok := func() (reflect.Type, bool) {
			for _, m := range kxstorage.AllModels() {
				typ := reflect.TypeOf(m).Elem()
				if typ.Name() == c.targetModel {
					return typ, true
				}
			}
			return nil, false
		}()
		require.True(t, ok, "target model %q from the reference map must be in AllModels()", c.targetModel)

		if hasDeletedAtField(targetType) {
			skippedSoftDelete++
			continue
		}

		if reason, ok := orphanGuardAllowlist[c.targetModel][c.sourceModel]; ok {
			t.Logf("allowlisted: %s.%s -> %s: %s", c.sourceModel, c.fieldName, c.targetModel, reason)
			skippedAllowlisted++
			continue
		}

		name := fmt.Sprintf("%s.%s_references_%s", c.sourceModel, c.fieldName, c.targetModel)
		t.Run(name, func(t *testing.T) {
			dsn := "file::memory:?cache=shared"
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			require.NoError(t, err)
			require.NoError(t, kxstorage.MigrateExisting(db))
			ls := store.NewLocalStorage(db)

			method, skipReason := singleIDDeleteMethod(ls, c.targetModel)
			if skipReason != "" {
				t.Skipf("%s", skipReason)
				return
			}

			// Seed one target row, read back its ID.
			targetPtr := reflect.New(targetType)
			require.NoError(t, db.Create(targetPtr.Interface()).Error)
			idField := targetPtr.Elem().FieldByName("ID")
			require.True(t, idField.IsValid(), "%s has no ID field -- cannot seed/verify by primary key", c.targetModel)
			targetID := idField.Uint()
			require.NotZero(t, targetID, "seeded %s row got a zero ID", c.targetModel)

			// Seed one source row referencing it.
			sourcePtr := reflect.New(c.sourceType)
			refField := sourcePtr.Elem().FieldByName(c.fieldName)
			refField.SetUint(targetID)
			require.NoError(t, db.Create(sourcePtr.Interface()).Error,
				"seed a %s row with %s=%d", c.sourceModel, c.fieldName, targetID)

			// Delete the target via its real Delete<Model> method.
			ctx := context.Background()
			results := method.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(uint(targetID))})
			errVal := results[len(results)-1]
			if !errVal.IsNil() {
				t.Fatalf("Delete%s(ctx, %d) on a freshly-seeded row failed: %v", c.targetModel, targetID, errVal.Interface())
			}

			// Check: does the referencing row still exist?
			column := namer.ColumnName("", c.fieldName)
			var n int64
			require.NoError(t, db.Model(sourcePtr.Interface()).Unscoped().
				Where(column+" = ?", targetID).Count(&n).Error)
			if n > 0 {
				t.Errorf("ORPHAN: deleting %s (id=%d) left %d live %s row(s) referencing it via %s -- "+
					"either cascade-delete them in the same transaction as the %s delete, or add "+
					"orphanGuardAllowlist[%q][%q] with a one-line reason if this is intentional "+
					"(a history/compliance record, e.g.)",
					c.targetModel, targetID, n, c.sourceModel, c.fieldName, c.targetModel, c.targetModel, c.sourceModel)
			}
		})
		verified++
	}

	t.Logf("orphan-reference guard: %d candidate pair(s) derived, %d verified (sub-tests above -- "+
		"some may report SKIP there if the target's Delete method isn't single-ID shaped), "+
		"%d skipped (target is soft-deletable), %d skipped (allowlisted)",
		len(candidates), verified, skippedSoftDelete, skippedAllowlisted)
}
