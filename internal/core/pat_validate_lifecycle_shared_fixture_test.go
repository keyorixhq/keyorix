package core

import (
	"context"
	"testing"
)

// TestPATLifecycleSharedFixture_Guard pins the guard that makes sharing the
// FuzzPATValidateLifecycle fixture across inputs sound. Green: validating every
// issued token (the expired one writes a notification) leaves only notification
// rows changed, and begin() makes the next input start from an empty table so
// the expired-token notification is written again. Red: each way a fixture row
// could be changed behind the harness's back (update, delete, insert elsewhere,
// a second write to one notification) is reported.
func TestPATLifecycleSharedFixture_Guard(t *testing.T) {
	shared := newPATLifecycleShared(t)
	ctx := t.Context()

	validateAll := func(c *KeyorixCore) {
		for _, e := range shared.entries {
			_, _, _, _, _ = c.ValidatePATToken(ctx, e.plain)
		}
	}
	notifCount := func() (n int64) {
		shared.db.Raw("SELECT count(*) FROM notifications").Scan(&n)
		return n
	}

	t.Run("green/validation writes only notifications and is re-armed per input", func(t *testing.T) {
		for i := range 3 {
			c, base := shared.begin(t)
			validateAll(c)
			if err := shared.untouchedErr(t, base); err != nil {
				t.Fatalf("input %d: %v", i, err)
			}
			if notifCount() == 0 {
				t.Fatalf("input %d: the expired token wrote no notification: the path the reset exists for is not being exercised", i)
			}
		}
	})

	for _, tc := range []struct {
		name string
		stmt string
	}{
		{"update of a token row", "UPDATE personal_access_tokens SET name = 'x' WHERE id = (SELECT min(id) FROM personal_access_tokens)"},
		{"update of a user row", "UPDATE users SET is_active = 1"},
		{"delete of a token row", "DELETE FROM personal_access_tokens WHERE id = (SELECT max(id) FROM personal_access_tokens)"},
		{"insert into another table", "INSERT INTO roles (id, name, name_folded) VALUES (901, 'extra', 'extra')"},
		{"update of a notification row", "UPDATE notifications SET title = title"},
	} {
		t.Run("red/"+tc.name, func(t *testing.T) {
			// Fresh fixture: this case damages it.
			s := newPATLifecycleShared(t)
			c, base := s.begin(t)
			for _, e := range s.entries {
				_, _, _, _, _ = c.ValidatePATToken(context.Background(), e.plain)
			}
			if err := s.untouchedErr(t, base); err != nil {
				t.Fatalf("precondition: %v", err)
			}
			if tc.name == "update of a notification row" && notifCountOf(s) == 0 {
				t.Fatal("precondition: no notification to update")
			}
			if err := s.db.Exec(tc.stmt).Error; err != nil {
				t.Fatalf("plant: %v", err)
			}
			if s.untouchedErr(t, base) == nil {
				t.Fatalf("%s went undetected", tc.name)
			}
		})
	}
}

func notifCountOf(s *patLifecycleShared) (n int64) {
	s.db.Raw("SELECT count(*) FROM notifications").Scan(&n)
	return n
}
