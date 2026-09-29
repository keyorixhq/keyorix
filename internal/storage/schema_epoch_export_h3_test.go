package storage

import "testing"

// TestCurrentSchemaEpoch_MatchesInternalConstant and
// TestSchemaEpochTooNew_MatchesCheckSchemaEpochComparison guard the
// design-b3-backup-v2.md §3.5 export surface restore uses to apply
// checkSchemaEpoch's exact refusal decision to an archive's manifest-
// declared schema_epoch instead of a live database row.
func TestCurrentSchemaEpoch_MatchesInternalConstant(t *testing.T) {
	if CurrentSchemaEpoch() != currentSchemaEpoch {
		t.Fatalf("CurrentSchemaEpoch() = %d, want %d", CurrentSchemaEpoch(), currentSchemaEpoch)
	}
}

func TestSchemaEpochTooNew_MatchesCheckSchemaEpochComparison(t *testing.T) {
	cases := []struct {
		epoch int
		want  bool
	}{
		{currentSchemaEpoch - 1, false},
		{currentSchemaEpoch, false},
		{currentSchemaEpoch + 1, true},
	}
	for _, c := range cases {
		if got := SchemaEpochTooNew(c.epoch); got != c.want {
			t.Errorf("SchemaEpochTooNew(%d) = %v, want %v", c.epoch, got, c.want)
		}
	}
}
