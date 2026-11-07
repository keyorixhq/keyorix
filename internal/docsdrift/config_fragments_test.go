package docsdrift

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// DOCS-FRAGMENTS-1: the reader side of docs/configuration.d/ and docs/upgrading.d/.
//
// TestEveryConfigKeyIsDocumented, TestDocsConfigKeysExist, TestInsecureRegistryEntriesAreDocumented
// and the env/command checks read docs/CONFIGURATION.md PLUS every fragment (dual-read, the
// pattern of docs/check-then-act-lock-exempt.d/). The tests here pin the new branch:
// a key documented only in a fragment passes, an undocumented key still fails, an empty
// fragment documents nothing, and a key documented in both places is reported (as the ledger
// readers report a key that appears twice when one copy is a fragment).

var fragLeaves = []string{"storage.database.fdatasync", "storage.database.audit_durability", "server.http.port"}

func fragFlat() []string {
	return []string{"The key `storage.database.audit_durability` sets the audit level.\n"}
}

func TestConfigFragment_DocumentsAKeyAloneInTheFragment(t *testing.T) {
	frags := map[string]string{
		"docs/configuration.d/storage__database__fdatasync.md": "### `storage.database.fdatasync`\n\nSyncs the data file. Default false.\n",
	}
	if p := configFragmentProblems(frags, fragLeaves, fragFlat()); len(p) != 0 {
		t.Fatalf("a valid fragment was reported: %v", p)
	}
	docs := append(fragFlat(), frags["docs/configuration.d/storage__database__fdatasync.md"])
	got := documentedConfigLeaves(docs, fragLeaves)
	if !got["storage.database.fdatasync"] {
		t.Errorf("a key named only in a fragment must count as documented")
	}
	if got["server.http.port"] {
		t.Errorf("a key named nowhere must still be undocumented")
	}
	if documentedConfigLeaves(fragFlat(), fragLeaves)["storage.database.fdatasync"] {
		t.Errorf("without the fragment the key is undocumented (the red side of the proof)")
	}
}

func TestConfigFragment_EmptyOrKeylessFragmentDoesNotCount(t *testing.T) {
	for name, body := range map[string]string{
		"empty":      "",
		"whitespace": " \n\t\n",
		"no key":     "Syncs the data file. Default false.\n",
	} {
		frags := map[string]string{"docs/configuration.d/storage__database__fdatasync.md": body}
		if p := configFragmentProblems(frags, fragLeaves, fragFlat()); len(p) != 1 {
			t.Errorf("%s: want exactly one problem, got %v", name, p)
		}
		if documentedConfigLeaves(append(fragFlat(), body), fragLeaves)["storage.database.fdatasync"] {
			t.Errorf("%s: the fragment must not document the key", name)
		}
	}
}

func TestConfigFragment_DuplicateWithFlatDocIsReported(t *testing.T) {
	frags := map[string]string{
		"docs/configuration.d/storage__database__audit_durability.md": "`storage.database.audit_durability`: strict or standard.\n",
	}
	p := configFragmentProblems(frags, fragLeaves, fragFlat())
	if len(p) != 1 || !strings.Contains(p[0], "already documented in the flat documents") {
		t.Fatalf("want the duplicate reported, got %v", p)
	}
}

func TestConfigFragment_BadNamesAndUnknownKeysAreReported(t *testing.T) {
	body := "`storage.database.fdatasync` and `nope.not_a_key` are mentioned.\n"
	for _, name := range []string{
		"storage.database.fdatasync.md",   // dots instead of __
		"fdatasync.md",                    // no parent
		"Storage__Database__Fdatasync.md", // upper case
		"storage__database__fdatasync.txt",
		"storage___database__fdatasync.md", // triple underscore
		"nope__not_a_key.md",               // not a config key
	} {
		p := configFragmentProblems(map[string]string{"docs/configuration.d/" + name: body}, fragLeaves, fragFlat())
		if len(p) != 1 {
			t.Errorf("%s: want exactly one problem, got %v", name, p)
		}
	}
}

// TestConfigFragmentsOnDiskAreClean runs the fragment validation on the real directory,
// so a bad fragment fails this test by name even before the leaf check runs.
func TestConfigFragmentsOnDiskAreClean(t *testing.T) {
	leaves := readLeafList(t, configLeavesFile)
	for _, p := range configFragmentProblems(configFragmentDocs(t), leaves, configReferenceDocs(t)) {
		t.Error(p)
	}
}

var (
	upgradingFragmentName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.md$`)
	numberedHeading       = regexp.MustCompile(`(?m)^## \d+[a-z]*(?:\.\d+)?[. ]`)
)

// upgradingFragmentProblems validates docs/upgrading.d fragments (path -> text): a
// lower-case slug name, a non-empty body, and no numbered "## 6x" heading (section numbers
// are assigned when the fragment is folded into UPGRADING.md, so a fragment that
// claims one would collide with the numbering TestUpgradingSectionNumbersAreUnique protects).
func upgradingFragmentProblems(frags map[string]string) []string {
	paths := make([]string, 0, len(frags))
	for p := range frags {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []string
	for _, p := range paths {
		base := p[strings.LastIndex(p, "/")+1:]
		switch {
		case !upgradingFragmentName.MatchString(base):
			out = append(out, p+": name must be a lower-case slug ending in .md, e.g. fdatasync-default.md")
		case strings.TrimSpace(frags[p]) == "":
			out = append(out, p+": empty fragment; write the upgrade note or delete the file")
		case numberedHeading.MatchString(frags[p]):
			out = append(out, p+": do not number the heading; the section number is assigned when the fragment is folded into UPGRADING.md")
		}
	}
	return out
}

func TestUpgradingFragmentsAreWellFormed(t *testing.T) {
	frags := map[string]string{}
	for _, rel := range fragmentFiles(t, upgradingFragmentsDir) {
		frags[rel] = readDoc(t, rel)
	}
	for _, p := range upgradingFragmentProblems(frags) {
		t.Error(p)
	}
}

func TestUpgradingFragmentCheckCatchesPlantedError(t *testing.T) {
	good := map[string]string{"docs/upgrading.d/fdatasync-default.md": "## fdatasync default\n\nSet it before upgrading.\n"}
	if p := upgradingFragmentProblems(good); len(p) != 0 {
		t.Fatalf("a valid fragment was reported: %v", p)
	}
	for name, frags := range map[string]map[string]string{
		"empty":    {"docs/upgrading.d/a.md": "\n"},
		"numbered": {"docs/upgrading.d/a.md": "## 6ab. Something\n\nBody.\n"},
		"bad name": {"docs/upgrading.d/A B.md": "Body.\n"},
	} {
		if p := upgradingFragmentProblems(frags); len(p) != 1 {
			t.Errorf("%s: want exactly one problem, got %v", name, p)
		}
	}
}
