package keyfiles

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// #4105: StaleSaltPendingCandidate names the salt staging file only in the
// states a successful boot leaves it in (nothing staged, or a rotate-kek
// abandoned before it changed the active set), and never with a DEK staging
// file present. Each state is the one commitNewKEKFiles leaves at that step
// (kekRotationFixture).
func TestStaleSaltPendingCandidate_States(t *testing.T) {
	cases := []struct {
		name string
		// setup builds the state from a provisioned generation.
		setup func(f *kekRotationFixture)
		// want: true when the salt staging file is the candidate.
		want bool
		// refusal: a substring of the refusal, "" when none is expected.
		refusal string
	}{
		{"no staging file", func(*kekRotationFixture) {}, false, ""},
		{"rotate-kek abandoned before any rename, only the salt left", func(f *kekRotationFixture) {
			f.stageAndWritePending()
			if err := os.Remove(f.dek + ".pending"); err != nil {
				f.t.Fatal(err)
			}
		}, true, ""},
		{"stray salt staging file, nothing staged", func(f *kekRotationFixture) {
			f.write(f.salt+".pending", []byte("leftover"))
		}, true, ""},
		{"a DEK staging file beside it", func(f *kekRotationFixture) { f.stageAndWritePending() }, false, "dek.key.pending is present"},
		{"a DEK staging file alone", func(f *kekRotationFixture) {
			f.write(f.dek+".pending", []byte("the only copy of the new DEK"))
		}, false, "dek.key.pending is present"},
		{"hazard window: boot still needs the salt", func(f *kekRotationFixture) {
			f.stageAndWritePending()
			f.renameDEK()
		}, false, "may be the salt it needs"},
		{"completed rotation not yet committed, stray salt staging file", func(f *kekRotationFixture) {
			f.stageAndWritePending()
			f.renameDEK()
			if err := os.Rename(f.salt+".pending", f.salt); err != nil {
				f.t.Fatal(err)
			}
			f.write(f.salt+".pending", []byte("stray"))
		}, false, "may be the salt it needs"},
		{"active salt replaced from another generation", func(f *kekRotationFixture) {
			f.write(f.salt+".pending", readFile(f.t, f.salt))
			f.write(f.salt, []byte("a salt from another generation"))
		}, false, "the key set is refused"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newKEKRotationFixture(t)
			c.setup(f)
			before := snapshotDir(t, f.dir)

			got, err := StaleSaltPendingCandidate(passwordSetConfig(), f.dir)

			switch {
			case c.refusal != "":
				if err == nil || !strings.Contains(err.Error(), c.refusal) {
					t.Fatalf("want a refusal containing %q, got path %q, err %v", c.refusal, got, err)
				}
				if got != "" {
					t.Fatalf("a refusal must name no candidate, got %q", got)
				}
			case err != nil:
				t.Fatalf("unexpected refusal: %v", err)
			case c.want && got != f.salt+".pending":
				t.Fatalf("candidate = %q, want %q", got, f.salt+".pending")
			case !c.want && got != "":
				t.Fatalf("candidate = %q, want none", got)
			}
			requireDirUnchanged(t, f.dir, before)
		})
	}
}

// snapshotDir reads every regular file in dir.
func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			out[e.Name()] = readFile(t, dir+string(os.PathSeparator)+e.Name())
		}
	}
	return out
}

// requireDirUnchanged: the decision writes, moves and removes nothing.
func requireDirUnchanged(t *testing.T, dir string, before map[string][]byte) {
	t.Helper()
	after := snapshotDir(t, dir)
	if len(after) != len(before) {
		t.Fatalf("files changed: before %d, after %d", len(before), len(after))
	}
	for name, data := range before {
		if !bytes.Equal(after[name], data) {
			t.Fatalf("%s changed", name)
		}
	}
}
