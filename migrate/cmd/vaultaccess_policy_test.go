package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// The token policy the docs tell an operator to attach (migrate/healthscan-policy.hcl, see
// docs/vault-health-scan.md) must grant exactly what plan-access / apply-access / audit-access
// call. These tests parse that file with the same parser the commands use, run the shared Vault
// read (readAccessInputs) against a fake Vault that enforces it, and compare the capabilities
// the commands actually used with the capabilities the file grants.
//
// The fake models Vault's documented ACL path rules (exact path, "+" for one segment, a trailing
// "*" for a prefix). It is a model: that real Vault and OpenBao agree is the demo run
// (scripts/demo/vault-migration-demo.sh), pending e2e VM.

const documentedPolicyFile = "../healthscan-policy.hcl"

func loadDocumentedPolicy(t *testing.T) []healthscan.PolicyPathBlock {
	t.Helper()
	raw, err := os.ReadFile(documentedPolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	blocks := healthscan.ParsePolicyHCL(string(raw))
	if len(blocks) == 0 {
		t.Fatalf("%s parsed to zero stanzas", documentedPolicyFile)
	}
	return blocks
}

// vaultPathMatches reports whether a policy stanza path matches an API path, by Vault's rules.
func vaultPathMatches(pattern, path string) bool {
	pat, segs := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, p := range pat {
		if i >= len(segs) {
			return false
		}
		if i == len(pat)-1 && strings.HasSuffix(p, "*") {
			return strings.HasPrefix(segs[i], strings.TrimSuffix(p, "*")) // the rest of the path is free.
		}
		if p == "+" && segs[i] != "" {
			continue
		}
		if p != segs[i] {
			return false
		}
	}
	return len(pat) == len(segs)
}

// policyGrants reports whether the stanzas grant capability on path. A LIST is checked with and
// without the trailing slash Vault's HTTP layer adds, so both an exact "sys/policies/acl" and a
// glob "kv1/*" stanza count.
func policyGrants(blocks []healthscan.PolicyPathBlock, capability, path string) bool {
	paths := []string{path}
	if capability == "list" {
		paths = []string{strings.TrimSuffix(path, "/") + "/", strings.TrimSuffix(path, "/")}
	}
	for _, b := range blocks {
		if !slices.Contains(b.Capabilities, capability) {
			continue
		}
		for _, p := range paths {
			if vaultPathMatches(b.Path, p) {
				return true
			}
		}
	}
	return false
}

func TestVaultPathMatches(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"sys/mounts", "sys/mounts", true},
		{"sys/mounts", "sys/mounts/x", false},
		{"kv1/*", "kv1/", true},
		{"kv1/*", "kv1/team-a/", true},
		{"kv1/*", "kv10/team-a/", false},
		{"+/metadata/*", "secret/metadata/", true},
		{"+/metadata/*", "secret/data/x", false},
		{"auth/+/role", "auth/approle/role", true},
		{"auth/+/role", "auth/approle/role/ci", false},
		{"auth/+/role/+", "auth/approle/role/ci", true},
		{"auth/+/role/+", "auth/approle/role/", false},
	}
	for _, c := range cases {
		if got := vaultPathMatches(c.pattern, c.path); got != c.want {
			t.Errorf("vaultPathMatches(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

type vaultCall struct{ Capability, Path string }

// enforcingVault records every request, answers 403 when the policy does not grant it, and
// otherwise serves it from next.
type enforcingVault struct {
	next   http.Handler
	blocks []healthscan.PolicyPathBlock

	mu      sync.Mutex
	allowed []vaultCall
	denied  []vaultCall
}

func (e *enforcingVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	capability := "read"
	if r.Method != http.MethodGet {
		capability = r.Method // never granted by the file: shows up as denied.
	} else if r.URL.Query().Get("list") == "true" {
		capability = "list"
	}
	call := vaultCall{capability, strings.TrimPrefix(r.URL.Path, "/v1/")}
	e.mu.Lock()
	ok := policyGrants(e.blocks, call.Capability, call.Path)
	if ok {
		e.allowed = append(e.allowed, call)
	} else {
		e.denied = append(e.denied, call)
	}
	e.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	e.next.ServeHTTP(w, r)
}

// policyTestVault is a Vault with every surface the access commands read: a KV v2 mount and a KV
// v1 mount that both hold team-a/prod/, AppRole, Kubernetes and userpass auth.
func policyTestVault() *fakeAccessVault {
	return &fakeAccessVault{
		kv1HoldsTeamAProd: true,
		extra: map[string]string{
			"/v1/sys/auth": `{"data":{"approle/":{"type":"approle"},"kubernetes/":{"type":"kubernetes"},"userpass/":{"type":"userpass"}}}`,

			"LIST /v1/auth/kubernetes/role": `{"data":{"keys":["deploy"]}}`,
			"/v1/auth/kubernetes/role/deploy": `{"data":{"bound_service_account_names":["app"],` +
				`"bound_service_account_namespaces":["team-a"],"token_policies":["team-a-prod-ro"]}}`,
			"LIST /v1/auth/userpass/users":  `{"data":{"keys":["alice"]}}`,
			"/v1/auth/userpass/users/alice": `{"data":{"token_policies":["team-a-prod-ro"]}}`,
		},
	}
}

type policyRun struct {
	vault      *enforcingVault
	unreadable []string
	treeWarns  []string
}

// runAccessReadsUnder runs the Vault reads shared by plan-access, apply-access and audit-access
// against vault, enforcing blocks.
func runAccessReadsUnder(t *testing.T, vault *fakeAccessVault, blocks []healthscan.PolicyPathBlock) policyRun {
	t.Helper()
	enforcing := &enforcingVault{next: vault, blocks: blocks}
	vsrv := httptest.NewServer(enforcing)
	defer vsrv.Close()
	ksrv := httptest.NewServer(&fakeAccessKeyorix{})
	defer ksrv.Close()

	ctx := context.Background()
	vc, err := healthscan.New(ctx, healthscan.Config{Addr: vsrv.URL, Token: "vault-token"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	apiClient, err := newAPIClient(ksrv.URL, "pat")
	if err != nil {
		t.Fatal(err)
	}
	_, _, unreadable, treeWarns, err := readAccessInputs(ctx, vc, accesstarget.New(apiClient), nil)
	if err != nil {
		t.Fatal(err)
	}
	return policyRun{vault: enforcing, unreadable: unreadable, treeWarns: treeWarns}
}

// withoutPath drops every stanza whose path is exactly p.
func withoutPath(blocks []healthscan.PolicyPathBlock, p string) []healthscan.PolicyPathBlock {
	var out []healthscan.PolicyPathBlock
	for _, b := range blocks {
		if b.Path != p {
			out = append(out, b)
		}
	}
	return out
}

func TestDocumentedPolicy_GrantsEveryCallTheAccessCommandsMake(t *testing.T) {
	run := runAccessReadsUnder(t, policyTestVault(), loadDocumentedPolicy(t))

	if len(run.vault.denied) != 0 {
		t.Errorf("the documented policy does not grant %d call(s) the access commands make: %v", len(run.vault.denied), run.vault.denied)
	}
	if len(run.unreadable) != 0 || len(run.treeWarns) != 0 {
		t.Errorf("reads were refused under the documented policy: unreadable=%v tree=%v", run.unreadable, run.treeWarns)
	}

	// The test is only meaningful if it saw every surface: pin what was called.
	for _, want := range []vaultCall{
		{"read", "sys/mounts"},
		{"list", "sys/policies/acl"}, {"read", "sys/policies/acl/team-a-prod-ro"},
		{"read", "sys/auth"},
		{"list", "auth/approle/role"}, {"read", "auth/approle/role/ci"},
		{"list", "auth/kubernetes/role"}, {"read", "auth/kubernetes/role/deploy"},
		{"list", "auth/userpass/users"}, {"read", "auth/userpass/users/alice"},
		{"list", "secret/metadata"}, {"list", "secret/metadata/team-a"}, // KV v2 tree
		{"list", "kv1"}, {"list", "kv1/team-a"}, // KV v1 tree
	} {
		if !slices.Contains(run.vault.allowed, want) {
			t.Errorf("the access commands never made the call %v: the fake Vault no longer exercises that surface (calls: %v)", want, run.vault.allowed)
		}
	}
	// Read-only by construction: only GET and LIST reach Vault.
	for _, c := range run.vault.allowed {
		if c.Capability != "read" && c.Capability != "list" {
			t.Errorf("call %v is neither a read nor a list", c)
		}
	}
}

// The file grants nothing beyond what the commands call on the KV mounts: names on a KV v1
// mount (list, no read), names and metadata on KV v2 (never the data/ twin), no value anywhere.
func TestDocumentedPolicy_GrantsNoMoreThanTheKVTreeReadNeeds(t *testing.T) {
	blocks := loadDocumentedPolicy(t)
	all := []string{"create", "read", "update", "patch", "delete", "list", "sudo", "deny"}
	grantedOn := func(path string) []string {
		var got []string
		for _, c := range all {
			if policyGrants(blocks, c, path) {
				got = append(got, c)
			}
		}
		return got
	}

	// plan-access lists these KV v1 paths; list is all the file may grant there.
	for _, p := range []string{"kv1/", "kv1/team-a/"} {
		if got := grantedOn(p); !slices.Equal(got, []string{"list"}) {
			t.Errorf("capabilities granted on KV v1 path %q = %v, want exactly [list]", p, got)
		}
	}
	// A KV v1 value and a KV v2 value are never readable with this token.
	for _, p := range []string{"kv1/team-a/prod/db-password", "secret/data/team-a/prod/db-password"} {
		if policyGrants(blocks, "read", p) {
			t.Errorf("the documented policy grants read on the secret value path %q", p)
		}
	}
	// The file's header promise: only read and list, anywhere.
	for _, b := range blocks {
		for _, c := range b.Capabilities {
			if c != "read" && c != "list" {
				t.Errorf("stanza %q grants %q: the documented policy must be read/list only", b.Path, c)
			}
		}
	}
}

// Red/green for the v1 stanza without editing production code: the same run with the stanza
// removed (the policy as shipped before) cannot list the v1 mount, and says so.
func TestDocumentedPolicy_KV1StanzaIsWhatLetsPlanAccessListAV1Mount(t *testing.T) {
	blocks := loadDocumentedPolicy(t)
	if !slices.ContainsFunc(blocks, func(b healthscan.PolicyPathBlock) bool { return b.Path == "kv1/*" }) {
		t.Fatal("the documented policy has no kv1/* stanza")
	}

	without := runAccessReadsUnder(t, policyTestVault(), withoutPath(blocks, "kv1/*"))
	if !slices.Contains(without.vault.denied, vaultCall{"list", "kv1"}) {
		t.Errorf("without the stanza, listing kv1/ should be denied; denied=%v", without.vault.denied)
	}
	if len(without.treeWarns) != 1 || !strings.Contains(without.treeWarns[0], "could not list KV mount kv1/") {
		t.Errorf("without the stanza, plan-access should warn it could not list kv1/; got %v", without.treeWarns)
	}

	with := runAccessReadsUnder(t, policyTestVault(), blocks)
	if len(with.treeWarns) != 0 || len(with.vault.denied) != 0 {
		t.Errorf("with the stanza, the v1 mount must list cleanly; warnings=%v denied=%v", with.treeWarns, with.vault.denied)
	}
}

// The shipped stanza names the example mount kv1/. Any other KV v1 mount needs its own stanza,
// and until it has one plan-access fails closed with a warning that says what to grant.
func TestDocumentedPolicy_AnotherV1MountNeedsItsOwnStanzaAndTheWarningSaysSo(t *testing.T) {
	vault := policyTestVault()
	vault.extra["/v1/sys/mounts"] = `{"data":{"secret/":{"type":"kv","options":{"version":"2"}},"legacy/":{"type":"kv"}}}`
	vault.extra["LIST /v1/legacy"] = `{"data":{"keys":["team-a/"]}}`

	run := runAccessReadsUnder(t, vault, loadDocumentedPolicy(t))
	if len(run.treeWarns) != 1 {
		t.Fatalf("want one warning for the unlisted legacy/ mount, got %v", run.treeWarns)
	}
	for _, want := range []string{"could not list KV mount legacy/", "KV v1: <mount>/*", "KV v2: <mount>/metadata/*"} {
		if !strings.Contains(run.treeWarns[0], want) {
			t.Errorf("warning %q does not contain %q", run.treeWarns[0], want)
		}
	}
}
