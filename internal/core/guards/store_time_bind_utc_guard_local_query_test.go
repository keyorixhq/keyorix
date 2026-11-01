// store_time_bind_utc_guard_local_query_test.go -- calibration of TestEveryStoreTimeBindIsUTC for
// query strings held in a function-local variable (REVIEW-3921-DEEP-4 F1). The real shape is the
// retention purges in local_purge.go (DeleteClosedAccessReviewsBefore,
// DeleteResolvedAccessRequestsBefore): `eligible := "... closed_at < ?"`, bound inside a
// transaction closure.

package guards

import "testing"

func TestStoreTimeBindScanner_LocalQueryVariable(t *testing.T) {
	for name, src := range map[string]string{
		"local query var":      "package s\nfunc f(before time.Time) {\n\tq := \"closed_at < ?\"\n\tdb.Where(q, before)\n}",
		"var declaration":      "package s\nfunc f(before time.Time) {\n\tvar q = \"closed_at < ?\"\n\tdb.Where(q, before)\n}",
		"local in a closure":   "package s\nfunc f(before time.Time) {\n\teligible := \"state = ? AND closed_at IS NOT NULL AND closed_at < ?\"\n\tdb.Transaction(func(tx *gorm.DB) error {\n\t\ttx.Where(eligible, \"closed\", before).Delete(&M{})\n\t\treturn nil\n\t})\n}",
		"local built on const": "package s\nconst live = \"deleted_at IS NOT NULL\"\nfunc f(b time.Time) {\n\tq := live + \" AND deleted_at < ?\"\n\tdb.Where(q, b)\n}",
	} {
		got := scanStoreTimeBindsInSource(t, src)
		if len(got) == 0 {
			t.Errorf("%s: want a bind, got none", name)
			continue
		}
		for _, b := range got {
			if b.UTC || !b.Mapped {
				t.Errorf("%s: want a mapped non-UTC bind, got %+v", name, b)
			}
		}
	}

	for name, src := range map[string]string{
		"local query var":    "package s\nfunc f(before time.Time) {\n\tq := \"closed_at < ?\"\n\tdb.Where(q, before.UTC())\n}",
		"local in a closure": "package s\nfunc f(before time.Time) {\n\tbefore = before.UTC()\n\teligible := \"resolved_at IS NOT NULL AND resolved_at < ?\"\n\tdb.Transaction(func(tx *gorm.DB) error {\n\t\ttx.Where(eligible, before).Delete(&M{})\n\t\treturn nil\n\t})\n}",
	} {
		got := scanStoreTimeBindsInSource(t, src)
		if len(got) == 0 {
			t.Errorf("%s: want a bind, got none", name)
		}
		for _, b := range got {
			if !b.UTC || !b.Mapped {
				t.Errorf("%s: want only UTC-traced binds, got %+v", name, b)
			}
		}
	}

	// A local that shadows a package const holds whatever the function put in it, not the const.
	if got := scanStoreTimeBindsInSource(t, "package s\nconst q = \"closed_at < ?\"\nfunc f(t time.Time, s string) {\n\tq := s\n\tdb.Where(q, t)\n}"); len(got) != 0 {
		t.Errorf("shadowed const: want no bind (the query is unresolved), got %+v", got)
	}
}
