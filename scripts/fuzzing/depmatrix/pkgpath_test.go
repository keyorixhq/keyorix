package main

import "testing"

func TestPkgPathNamesDep(t *testing.T) {
	const dep = "golang.org/x/sync"
	cases := []struct {
		pkgPath string
		want    bool
	}{
		{"golang.org/x/sync", true},
		{"golang.org/x/sync/singleflight", true},
		{"github.com/keyorixhq/keyorix/fuzz/thirdparty/x-sync", true},
		{"github.com/keyorixhq/keyorix/fuzz/thirdparty/foo-x-sync-bar", false},
		{"github.com/keyorixhq/keyorix/fuzz/thirdparty/x-syncer", false},
		{"golang.org/x/syncx", false},
	}
	for _, c := range cases {
		if got := pkgPathNamesDep(c.pkgPath, dep); got != c.want {
			t.Errorf("pkgPathNamesDep(%q, %q) = %v, want %v", c.pkgPath, dep, got, c.want)
		}
	}
}
