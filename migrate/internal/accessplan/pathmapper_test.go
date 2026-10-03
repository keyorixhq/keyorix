package accessplan

import "testing"

func testMapper(t *testing.T, overrides ...string) *PathMapper {
	t.Helper()
	projects := []ProjectRef{{ID: 1, Name: "team-a"}, {ID: 2, Name: "team-b"}}
	envs := map[int][]EnvironmentRef{
		1: {{ID: 10, Name: "dev"}, {ID: 11, Name: "prod"}},
		2: {{ID: 20, Name: "prod"}},
	}
	kvMounts := []KVMountInfo{{Path: "secret/", KVVersion: 2}, {Path: "kv1/", KVVersion: 1}}
	m, err := NewPathMapper(projects, envs, kvMounts, overrides)
	if err != nil {
		t.Fatalf("NewPathMapper: %v", err)
	}
	return m
}

func TestPathMapper_ExactProjectAndEnvironment(t *testing.T) {
	m := testMapper(t)
	res, _, _, ok := m.Resolve("secret/data/team-a/prod/db-password")
	if !ok {
		t.Fatal("expected ok")
	}
	if res.ProjectID != 1 || res.EnvironmentID != 11 {
		t.Fatalf("res = %+v, want project 1 / env 11", res)
	}
}

func TestPathMapper_TrailingWildcardOnLiteralScope(t *testing.T) {
	m := testMapper(t)
	res, _, _, ok := m.Resolve("secret/data/team-a/dev/*")
	if !ok {
		t.Fatal("expected ok")
	}
	if res.ProjectID != 1 || res.EnvironmentID != 10 {
		t.Fatalf("res = %+v, want project 1 / env 10", res)
	}
}

func TestPathMapper_ProjectOnlyWildcard_GlobalWithinProject(t *testing.T) {
	m := testMapper(t)
	res, _, _, ok := m.Resolve("secret/data/team-a/*")
	if !ok {
		t.Fatal("expected ok (ADR-114's documented env=0 case)")
	}
	if res.ProjectID != 1 || res.EnvironmentID != 0 {
		t.Fatalf("res = %+v, want project 1 / env 0 (global)", res)
	}
}

func TestPathMapper_EntireMountWildcard_Unmappable(t *testing.T) {
	m := testMapper(t)
	_, category, reason, ok := m.Resolve("secret/data/*")
	if ok {
		t.Fatal("expected Unmappable — a bare mount-wide wildcard must never resolve to a grant")
	}
	if category != CategoryUnresolvedPathScope || reason == "" {
		t.Fatalf("category=%q reason=%q, want CategoryUnresolvedPathScope with a reason", category, reason)
	}
}

func TestPathMapper_UnknownProject_Unmappable(t *testing.T) {
	m := testMapper(t)
	_, category, _, ok := m.Resolve("secret/data/no-such-team/prod/x")
	if ok || category != CategoryUnresolvedPathScope {
		t.Fatalf("expected Unmappable/unresolved-path-scope, got ok=%v category=%q", ok, category)
	}
}

func TestPathMapper_UnknownEnvironment_Unmappable(t *testing.T) {
	m := testMapper(t)
	_, category, _, ok := m.Resolve("secret/data/team-a/staging/x")
	if ok || category != CategoryUnresolvedPathScope {
		t.Fatalf("expected Unmappable/unresolved-path-scope, got ok=%v category=%q", ok, category)
	}
}

func TestPathMapper_OutsideAnyKVMount_MountManagement(t *testing.T) {
	m := testMapper(t)
	_, category, _, ok := m.Resolve("sys/policies/acl/*")
	if ok || category != CategoryMountManagement {
		t.Fatalf("expected Unmappable/mount-management, got ok=%v category=%q", ok, category)
	}
}

func TestPathMapper_KVv1Mount_NoInfixStripped(t *testing.T) {
	m := testMapper(t)
	res, _, _, ok := m.Resolve("kv1/team-b/prod/x")
	if !ok {
		t.Fatal("expected ok")
	}
	if res.ProjectID != 2 || res.EnvironmentID != 20 {
		t.Fatalf("res = %+v, want project 2 / env 20", res)
	}
}

func TestPathMapper_Override_LongestPrefixWins(t *testing.T) {
	m := testMapper(t, "secret/data/team-a=2:20", "secret/data/team-a/dev=1:10")
	res, _, _, ok := m.Resolve("secret/data/team-a/dev/x")
	if !ok {
		t.Fatal("expected ok")
	}
	if res.ProjectID != 1 || res.EnvironmentID != 10 {
		t.Fatalf("res = %+v, want the longer, more specific override (project 1 / env 10) to win", res)
	}
	res2, _, _, ok := m.Resolve("secret/data/team-a/staging/x")
	if !ok {
		t.Fatal("expected ok via the shorter override")
	}
	if res2.ProjectID != 2 || res2.EnvironmentID != 20 {
		t.Fatalf("res2 = %+v, want the shorter override (project 2 / env 20)", res2)
	}
}

func TestNewPathMapper_RejectsMalformedOverride(t *testing.T) {
	_, err := NewPathMapper(nil, nil, nil, []string{"not-a-valid-override"})
	if err == nil {
		t.Fatal("expected an error for a malformed --path-map value")
	}
}
