package docsdrift

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// INSTALL-AI-TAILS-1 item 3: INSTALL-WITH-AI.md pins a release (`V=vX.Y.Z` for the
// binary path, `git clone --branch vX.Y.Z` for the Compose path) and its Compose
// section states what is true at that tag (plaintext database connection). When a
// release lands in CHANGELOG.md the pins must move with it, and the "pinned tag"
// sentence must name the tag the page pins. The source of the latest release is the
// newest `## vX.Y.Z` heading of CHANGELOG.md (the one TestComposeImagePinsMatchLatestRelease
// reads): no network. A release tag whose CHANGELOG section lands only on its own tag
// (RELEASE-CHECKLIST.md) is not seen until then; scripts/release/check-docs-version.sh
// is the pre-tag check for that case.

var (
	iwpLatest    = regexp.MustCompile(`(?m)^## (v\d+\.\d+\.\d+)\b`)
	iwpPin       = regexp.MustCompile(`(?m)(?:^V=|--branch )(v\d+\.\d+\.\d+)\b`)
	iwpPinnedTag = regexp.MustCompile(`pinned tag (v\d+\.\d+\.\d+)`)
)

// iwpVersion parses vX.Y.Z.
func iwpVersion(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func iwpOlder(a, b string) bool {
	x, y := iwpVersion(a), iwpVersion(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// iwpFindings reports the pins of page older than latest and a "pinned tag"
// sentence that does not name the page's pin.
func iwpFindings(page, latest string) []string {
	var out []string
	pins := iwpPin.FindAllStringSubmatch(page, -1)
	for _, m := range pins {
		if iwpOlder(m[1], latest) {
			out = append(out, fmt.Sprintf("pin %s is older than the latest release %s", m[1], latest))
		}
	}
	for _, m := range iwpPinnedTag.FindAllStringSubmatch(page, -1) {
		match := false
		for _, p := range pins {
			if p[1] == m[1] {
				match = true
			}
		}
		if !match {
			out = append(out, fmt.Sprintf("\"pinned tag %s\" names a tag the page does not pin", m[1]))
		}
	}
	return out
}

func TestInstallWithAIPinsAreNotOlderThanLatestRelease(t *testing.T) {
	page := readDoc(t, iwaDoc)
	m := iwpLatest.FindStringSubmatch(readDoc(t, "CHANGELOG.md"))
	if m == nil {
		t.Fatal("CHANGELOG.md has no `## vX.Y.Z` heading to compare the page's pins with")
	}
	// Liveness: a regex that stopped seeing the pins would pass vacuously.
	if n := len(iwpPin.FindAllString(page, -1)); n < 2 {
		t.Fatalf("%s: found %d version pins (V= / --branch), want the binary and the Compose pin", iwaDoc, n)
	}
	if !iwpPinnedTag.MatchString(page) {
		t.Fatalf("%s: no \"pinned tag vX.Y.Z\" sentence in the Compose section", iwaDoc)
	}
	for _, f := range iwpFindings(page, m[1]) {
		t.Errorf("%s: %s: re-pin it (RELEASING.md, first release after v0.96.3)", iwaDoc, f)
	}
}

func TestInstallWithAIPinCheckCatchesPlantedErrors(t *testing.T) {
	page := readDoc(t, iwaDoc)
	pin := iwpPin.FindStringSubmatch(page)[1]
	newer := fmt.Sprintf("v%d.%d.%d", iwpVersion(pin)[0], iwpVersion(pin)[1], iwpVersion(pin)[2]+1)

	if f := iwpFindings(page, pin); len(f) != 0 {
		t.Errorf("page at its own pin reported: %v", f)
	}
	// a release newer than the pin makes both pins stale
	if f := iwpFindings(page, newer); len(f) < 2 {
		t.Errorf("a newer release %s must flag the page's pins: %v", newer, f)
	}
	// a re-pin that forgets the plaintext sentence is reported
	repinned := strings.ReplaceAll(page, pin, newer)
	if f := iwpFindings(repinned, newer); len(f) != 0 {
		t.Errorf("a consistent re-pin reported: %v", f)
	}
	stale := strings.Replace(repinned, "pinned tag "+newer, "pinned tag "+pin, 1)
	if f := iwpFindings(stale, newer); len(f) != 1 {
		t.Errorf("a stale \"pinned tag\" sentence: %d findings, want 1: %v", len(f), f)
	}
	// 0.96.10 is newer than 0.96.9: numeric, not lexical
	if !iwpOlder("v0.96.9", "v0.96.10") || iwpOlder("v0.96.10", "v0.96.9") || iwpOlder("v1.0.0", "v0.99.99") {
		t.Error("iwpOlder compares versions lexically")
	}
}
