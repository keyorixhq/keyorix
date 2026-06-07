package rbac

import "testing"

func TestSplitPermissionName(t *testing.T) {
	ok := map[string][2]string{
		"secrets.read": {"secrets", "read"},
		"system.admin": {"system", "admin"},
		"roles.assign": {"roles", "assign"},
	}
	for name, want := range ok {
		res, act, err := splitPermissionName(name)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", name, err)
		}
		if res != want[0] || act != want[1] {
			t.Errorf("%q: got (%q,%q), want (%q,%q)", name, res, act, want[0], want[1])
		}
	}

	for _, bad := range []string{"", "noaction", ".read", "secrets.", "secrets"} {
		if _, _, err := splitPermissionName(bad); err == nil {
			t.Errorf("%q: expected an error, got nil", bad)
		}
	}
}
