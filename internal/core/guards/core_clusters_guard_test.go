package guards

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// R4 of ADR-116 (INV-CORE-package-boundaries): every non-test .go file directly
// in internal/core belongs to exactly one cluster of internal/core/CLUSTERS.d.
// The ownership map is what later extraction briefs and CI leg selection read;
// a file in no cluster or in two is an ownership question nobody answered.
//
// What this does not check: subpackages of internal/core (each is its own
// package) and test files (tests are not clustered; ADR-116 moves them by
// black-box analysis, not by cluster).

const kernelCluster = "kernel"

// readClusters parses every <cluster>.txt in dir: one filepath.Match pattern per
// line, '#' comment lines and blank lines ignored. kernel.txt takes exact names.
func readClusters(dir string) (map[string][]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	clusters := map[string][]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed repo-internal directory
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(filepath.Base(p), ".txt")
		var pats []string
		for line := range strings.SplitSeq(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, err := filepath.Match(line, ""); err != nil {
				return nil, fmt.Errorf("%s: bad pattern %q: %w", filepath.Base(p), line, err)
			}
			if name == kernelCluster && strings.ContainsAny(line, `*?[\`) {
				return nil, fmt.Errorf("kernel.txt: %q is a glob; the kernel lists exact file names", line)
			}
			pats = append(pats, line)
		}
		clusters[name] = pats
	}
	if _, ok := clusters[kernelCluster]; !ok {
		return nil, fmt.Errorf("%s has no kernel.txt", dir)
	}
	return clusters, nil
}

// nearestCluster names the cluster whose pattern shares the longest prefix with
// file, as a hint in the failure message.
func nearestCluster(file string, clusters map[string][]string) string {
	best, bestLen := kernelCluster, 0
	for _, c := range slices.Sorted(maps.Keys(clusters)) {
		for _, p := range clusters[c] {
			n := 0
			for n < len(p) && n < len(file) && p[n] == file[n] && p[n] != '*' {
				n++
			}
			if n > bestLen {
				best, bestLen = c, n
			}
		}
	}
	return best
}

// clusterViolations returns one message per file in zero or several clusters
// and per pattern that matches no file.
func clusterViolations(files []string, clusters map[string][]string) []string {
	var msgs []string
	used := map[string]bool{}
	for _, f := range files {
		var owners []string
		for _, c := range slices.Sorted(maps.Keys(clusters)) {
			for _, p := range clusters[c] {
				if ok, _ := filepath.Match(p, f); ok {
					used[c+"/"+p] = true
					if !slices.Contains(owners, c) {
						owners = append(owners, c)
					}
				}
			}
		}
		switch len(owners) {
		case 0:
			msgs = append(msgs, fmt.Sprintf("internal/core/%s is in no cluster: add it to internal/core/CLUSTERS.d/%s.txt "+
				"(nearest by name) or to the cluster it belongs to (ADR-116 R4)", f, nearestCluster(f, clusters)))
		case 1:
		default:
			msgs = append(msgs, fmt.Sprintf("internal/core/%s is in %d clusters (%s): narrow the patterns so it has one owner",
				f, len(owners), strings.Join(owners, ", ")))
		}
	}
	for c, pats := range clusters {
		for _, p := range pats {
			if !used[c+"/"+p] {
				msgs = append(msgs, fmt.Sprintf("CLUSTERS.d/%s.txt: %q matches no file in internal/core: remove the stale line", c, p))
			}
		}
	}
	slices.Sort(msgs)
	return msgs
}

func TestEveryCoreFileHasOneCluster(t *testing.T) {
	coreDir := filepath.Join(srcpath.RepoRoot(), filepath.FromSlash(srcpath.CoreDir))
	clusters, err := readClusters(filepath.Join(coreDir, "CLUSTERS.d"))
	if err != nil {
		t.Fatal(err)
	}
	// Package core only, not the family: R4 is about who owns a file while it is
	// still in internal/core.
	entries, err := os.ReadDir(coreDir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			files = append(files, n)
		}
	}
	if len(files) < 50 || len(clusters) < 2 {
		t.Fatalf("scan root is wrong: %d files, %d clusters", len(files), len(clusters))
	}
	for _, msg := range clusterViolations(files, clusters) {
		t.Error(msg)
	}
}

func TestClusterViolations_SelfTest(t *testing.T) {
	clusters := map[string][]string{
		kernelCluster: {"service.go", "auth.go"},
		"reports":     {"secret_access_*.go", "dashboard.go"},
		"sharing":     {"share_*.go"},
	}
	good := []string{"service.go", "auth.go", "secret_access_list.go", "dashboard.go", "share_authz.go"}
	if msgs := clusterViolations(good, clusters); len(msgs) != 0 {
		t.Fatalf("every file has one owner, want green: %v", msgs)
	}

	msgs := clusterViolations(append(slices.Clone(good), "secret_access_new.go", "share_brand_new.go", "unowned.go"), clusters)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "unowned.go is in no cluster") {
		t.Fatalf("a new file matching a glob is owned; an unmatched one is red: %v", msgs)
	}
	if got := nearestCluster("share_x.go", clusters); got != "sharing" {
		t.Errorf("nearest cluster of share_x.go = %s, want sharing", got)
	}

	clusters["reports"] = append(clusters["reports"], "share_authz.go")
	msgs = clusterViolations(good, clusters)
	if len(msgs) != 1 || !strings.Contains(msgs[0], "share_authz.go is in 2 clusters (reports, sharing)") {
		t.Fatalf("a file in two clusters must be red: %v", msgs)
	}

	msgs = clusterViolations([]string{"service.go", "auth.go", "secret_access_list.go", "share_authz.go"}, map[string][]string{
		kernelCluster: {"service.go", "auth.go"}, "reports": {"secret_access_*.go", "dashboard.go"}, "sharing": {"share_*.go"},
	})
	if len(msgs) != 1 || !strings.Contains(msgs[0], `reports.txt: "dashboard.go" matches no file`) {
		t.Fatalf("a stale pattern must be red: %v", msgs)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kernel.txt"), []byte("# c\nservice*.go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readClusters(dir); err == nil || !strings.Contains(err.Error(), "exact file names") {
		t.Errorf("a glob in kernel.txt must be refused, got %v", err)
	}
}
