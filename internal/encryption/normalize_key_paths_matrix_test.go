package encryption

// normalize_key_paths_matrix_test.go — #4396: normalizeKeyPaths returned an
// absolute dek_path unchanged when salt_path was empty (every non-password
// provider), so the DEK lock path failed with
//
//	open DEK lock file: access denied: path "/app/keys/dek.lock" must be relative
//
// The matrix is {dek abs/rel} x {salt empty/abs/rel} x {same dir/different dir}.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeKeyPaths_Matrix(t *testing.T) {
	const base = "."
	for _, tc := range []struct {
		name                      string
		dek, salt                 string
		wantBase, wantDEK, wantSl string
		wantErr                   string // substring; "" = no error
	}{
		// dek relative: returned unchanged whatever the salt is, except a
		// relative/absolute mix, which is refused (unchanged behaviour).
		{name: "rel dek, empty salt", dek: "keys/dek.key", salt: "",
			wantBase: base, wantDEK: "keys/dek.key", wantSl: ""},
		{name: "rel dek, rel salt (same dir)", dek: "keys/dek.key", salt: "keys/kek.salt",
			wantBase: base, wantDEK: "keys/dek.key", wantSl: "keys/kek.salt"},
		{name: "rel dek, rel salt (different dir)", dek: "keys/dek.key", salt: "other/kek.salt",
			wantBase: base, wantDEK: "keys/dek.key", wantSl: "other/kek.salt"},
		{name: "rel dek, abs salt", dek: "keys/dek.key", salt: "/app/keys/kek.salt",
			wantBase: base, wantDEK: "keys/dek.key", wantSl: "/app/keys/kek.salt",
			wantErr: "both be absolute or both be relative"},

		// dek absolute, salt empty: the #4396 rows. Collapsed like the both-set case.
		{name: "abs dek, empty salt", dek: "/app/keys/dek.key", salt: "",
			wantBase: "/app/keys", wantDEK: "dek.key", wantSl: ""},
		{name: "abs dek (unclean), empty salt", dek: "/app/keys/../keys/dek.key", salt: "",
			wantBase: "/app/keys", wantDEK: "dek.key", wantSl: ""},

		// both absolute, same directory: collapsed (unchanged behaviour).
		{name: "abs dek, abs salt (same dir)", dek: "/app/keys/dek.key", salt: "/app/keys/kek.salt",
			wantBase: "/app/keys", wantDEK: "dek.key", wantSl: "kek.salt"},

		// both absolute, different directories: refused, no base is picked
		// (unchanged behaviour, stated explicitly: the lock and .pending files have
		// no defined home when the two files live apart).
		{name: "abs dek, abs salt (different dir)", dek: "/app/keys/dek.key", salt: "/etc/keyorix/kek.salt",
			wantBase: base, wantDEK: "/app/keys/dek.key", wantSl: "/etc/keyorix/kek.salt",
			wantErr: "must live in the same directory"},

		// absolute dek, relative salt: refused (unchanged behaviour).
		{name: "abs dek, rel salt", dek: "/app/keys/dek.key", salt: "kek.salt",
			wantBase: base, wantDEK: "/app/keys/dek.key", wantSl: "kek.salt",
			wantErr: "both be absolute or both be relative"},

		// dek unset: nothing to place.
		{name: "empty dek, empty salt", dek: "", salt: "",
			wantBase: base, wantDEK: "", wantSl: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotBase, gotDEK, gotSalt, err := normalizeKeyPaths(base, tc.dek, tc.salt)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), tc.wantErr), err.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantBase, gotBase)
			require.Equal(t, tc.wantDEK, gotDEK)
			require.Equal(t, tc.wantSl, gotSalt)
		})
	}
}

// The #4396 failure end to end: an absolute dek_path with no salt (env provider)
// must take the DEK lock.
func TestAcquireExclusiveKeyLock_AbsoluteDEKNoSalt(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(".", dir+"/dek.key", "")
	require.NoError(t, km.configErr)
	f, err := acquireExclusiveKeyLock(km.baseDir, km.dekPath)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
