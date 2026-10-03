package deploy

import (
	"os"
	"regexp"
	"testing"
)

// TestComposeImagePinsMatchLatestRelease guards RELEASING.md's "bump the
// docker-compose.yml pins" step (#2601): the keyorix-server / keyorix-web image
// pins must equal the newest released version in CHANGELOG.md. Registry tags
// carry no leading "v" (release v0.95.3 -> image 0.95.3).
//
// It does NOT verify the image exists in the registry, and it takes the newest
// "## vX.Y.Z" heading of CHANGELOG.md as the source of truth for "latest
// release" (RELEASING.md requires the CHANGELOG entry before tagging). Only
// images under ghcr.io/keyorixhq/ are checked; third-party images are not.
func TestComposeImagePinsMatchLatestRelease(t *testing.T) {
	changelog := readRepoFile(t, "CHANGELOG.md")
	m := changelogHeadingRE.FindStringSubmatch(changelog)
	if m == nil {
		t.Fatal("no \"## vX.Y.Z\" release heading found in CHANGELOG.md; the check would be vacuous")
	}
	latest := m[1]

	pins := composePinRE.FindAllStringSubmatch(readRepoFile(t, "docker-compose.yml"), -1)
	if len(pins) < 2 {
		t.Fatalf("found %d ghcr.io/keyorixhq image pins in docker-compose.yml, want at least 2 (server, web)", len(pins))
	}
	for _, p := range pins {
		if p[2] != latest {
			t.Errorf("docker-compose.yml pins %s:%s but the latest release in CHANGELOG.md is v%s -- bump the pins (RELEASING.md step 3)", p[1], p[2], latest)
		}
	}
}

var (
	changelogHeadingRE = regexp.MustCompile(`(?m)^## v(\d+\.\d+\.\d+)\b`)
	composePinRE       = regexp.MustCompile(`(?m)^\s*image:\s*(ghcr\.io/keyorixhq/[\w.-]+):(\d+\.\d+\.\d+)\b`)
)

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../" + name) // #nosec G304 -- fixed repo-relative names from this file
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
