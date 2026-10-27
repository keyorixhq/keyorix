package cmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/accessreport"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// listKVScopeTree against a fake Vault: KV v2 lists through metadata/, KV v1 directly; only
// root keys naming a Keyorix project are descended into; a refused LIST is recorded as not
// listed (so the mapper fails closed) and warned about. It only ever issues LIST.
func TestListKVScopeTree_FakeVault(t *testing.T) {
	lists := map[string]string{
		"/v1/secret/metadata":        `{"data":{"keys":["team-a/","unrelated/"]}}`,
		"/v1/secret/metadata/team-a": `{"data":{"keys":["prod/","dev"]}}`,
		"/v1/kv1":                    `{"data":{"keys":["team-a/","team-b"]}}`,
	}
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Query().Get("list") != "true" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		seen = append(seen, r.URL.Path)
		if r.URL.Path == "/v1/kv1/team-a" || r.URL.Path == "/v1/locked/metadata" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, ok := lists[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	vc, err := healthscan.New(context.Background(), healthscan.Config{Addr: srv.URL, Token: "t"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	mounts := []healthscan.KVMount{{Path: "kv1/", KVVersion: 1}, {Path: "locked/", KVVersion: 2}, {Path: "secret/", KVVersion: 2}, {Path: "empty/", KVVersion: 2}}
	projects := []accessplan.ProjectRef{{ID: 1, Name: "team-a"}, {ID: 2, Name: "team-b"}}
	tree, warnings, err := listKVScopeTree(context.Background(), vc, mounts, projects)
	if err != nil {
		t.Fatal(err)
	}

	secret := tree["secret/"]
	if !secret.RootListed || len(secret.Projects) != 1 || !secret.Projects["team-a"].Listed || !slices.Equal(secret.Projects["team-a"].Envs, []string{"prod", "dev"}) {
		t.Fatalf("secret/ = %+v, want team-a listed with envs [prod dev] and nothing for the non-project key", secret)
	}
	kv1 := tree["kv1/"]
	if !kv1.RootListed || kv1.Projects["team-a"].Listed || !kv1.Projects["team-b"].Listed || len(kv1.Projects["team-b"].Envs) != 0 {
		t.Fatalf("kv1/ = %+v, want team-a not listed (403) and team-b a listed leaf", kv1)
	}
	if tree["locked/"].RootListed {
		t.Fatalf("locked/ = %+v, want RootListed=false after a 403", tree["locked/"])
	}
	if e := tree["empty/"]; !e.RootListed || len(e.Projects) != 0 {
		t.Fatalf("empty/ = %+v, want listed and empty (Vault answers 404 for an empty mount)", e)
	}
	if len(warnings) != 2 || !strings.Contains(strings.Join(warnings, "\n"), "kv1/team-a/") || !strings.Contains(strings.Join(warnings, "\n"), "locked/") {
		t.Fatalf("warnings = %v, want one for kv1/team-a/ and one for locked/", warnings)
	}
	if slices.Contains(seen, "/v1/secret/metadata/unrelated") {
		t.Fatalf("listed a directory that names no Keyorix project: %v", seen)
	}
}

func TestRefuseCrossMountDrift(t *testing.T) {
	reviewed := []accessplan.Item{{Kind: accessplan.KindRole, Outcome: accessplan.Create, SourceRef: "policy:p path:secret/data/team-a/prod/*",
		CrossMountEvidence: []string{"kv1/team-a/prod/: absent", "secret/team-a/prod/: policy mount"}}}
	fresh := []accessplan.Item{{Kind: accessplan.KindRole, Outcome: accessplan.Unmappable, Category: accessplan.CategoryCrossMountScope, SourceRef: "policy:p path:secret/data/team-a/prod/*",
		CrossMountEvidence: []string{"kv1/team-a/prod/: present", "secret/team-a/prod/: policy mount"}}}
	var stderr bytes.Buffer
	err := refuseCrossMountDrift(&stderr, reviewed, fresh)
	if err == nil || !strings.Contains(err.Error(), "nothing was applied") || !strings.Contains(stderr.String(), "kv1/team-a/prod/: present") {
		t.Fatalf("err=%v stderr=%q, want a refusal naming the changed kv1 paths", err, stderr.String())
	}
	if err := refuseCrossMountDrift(io.Discard, reviewed, reviewed); err != nil {
		t.Fatalf("unchanged tree: %v", err)
	}
}

// plan-access with a --path-map entry: the policy covers the whole mapped subtree, so it maps to
// team-a/prod; kv1/team-a/prod/ lands in the same scope by name. The report says it is not
// equivalent and prints that path (the control run, with kv1 empty, maps).
func TestBuildFreshAccessPlan_PathMapScopeSharedByNameWithAnotherMount(t *testing.T) {
	for _, kv1Holds := range []bool{true, false} {
		vault := &fakeAccessVault{kv1HoldsTeamAProd: kv1Holds}
		vsrv := httptest.NewServer(vault)
		ksrv := httptest.NewServer(&fakeAccessKeyorix{})
		ctx := context.Background()
		vc, err := healthscan.New(ctx, healthscan.Config{Addr: vsrv.URL, Token: "vault-token"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		api, err := newAPIClient(ksrv.URL, "pat")
		if err != nil {
			t.Fatal(err)
		}
		plan, _, err := buildFreshAccessPlan(ctx, vc, accesstarget.New(api), "", []string{"secret/data/team-a/prod=1:11"})
		vsrv.Close()
		ksrv.Close()
		if err != nil {
			t.Fatal(err)
		}
		var md bytes.Buffer
		if err := accessreport.WriteMarkdown(&md, plan, vsrv.URL); err != nil {
			t.Fatal(err)
		}
		creates, unmappable := 0, 0
		for _, it := range plan.Items {
			if it.Kind != accessplan.KindRole || !strings.HasPrefix(it.SourceRef, "policy:team-a-prod-ro") {
				continue
			}
			switch it.Outcome {
			case accessplan.Create:
				creates++
			case accessplan.Unmappable:
				unmappable++
				if it.Category != accessplan.CategoryCrossMountScope {
					t.Errorf("category = %q, want %q", it.Category, accessplan.CategoryCrossMountScope)
				}
			}
		}
		if kv1Holds {
			if creates != 0 || unmappable == 0 || !strings.Contains(md.String(), "kv1/team-a/prod/: present") {
				t.Fatalf("kv1 holds team-a/prod/: creates=%d unmappable=%d, want 0 / >0 with the kv1 path printed in the report:\n%s", creates, unmappable, md.String())
			}
			continue
		}
		if creates == 0 || unmappable != 0 {
			t.Fatalf("kv1 empty (control): creates=%d unmappable=%d, want the grant to map", creates, unmappable)
		}
	}
}
