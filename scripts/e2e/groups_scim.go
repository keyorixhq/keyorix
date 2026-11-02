//go:build e2e

package e2e

import (
	"encoding/json"
	"net/url"
	"testing"
)

// scimResource is the part of a SCIM User or Group resource (RFC 7643) this driver reads.
type scimResource struct {
	ID          string `json:"id"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

// scimList is a SCIM ListResponse.
type scimList struct {
	TotalResults int            `json:"totalResults"`
	Resources    []scimResource `json:"Resources"`
}

func (r scimResource) memberIDs() []string {
	ids := make([]string, 0, len(r.Members))
	for _, m := range r.Members {
		ids = append(ids, m.Value)
	}
	return ids
}

// groupSCIM drives every /scim/v2 route with the SCIM bearer token the harness generated and
// handed to the server (harness.DBBackend.EnableSCIM). SCIM has no token-issuance flow: the
// token is a static operator-supplied value, so there is nothing to mint through the API.
//
// The walk is one IdP lifecycle: provision a user, read it, replace it, find it by userName,
// deactivate it, provision a group around it, replace and patch the members, then deprovision
// both. It ends by reading the audit rows back as the admin: every SCIM write must have left
// its scim.* row, attributed to the SCIM principal (no user, no machine identity).
//
// The deeper behaviour (a deactivated user's PATs stop working, #3419) is
// journeys/journey_scim_provisioning_test.go; this group is the route walk both backends and
// the upgrade path share, so a SCIM route that stops answering fails coverage.go's guard.
func groupSCIM(ctx *smokeCtx) {
	t, c := ctx.t, ctx.c
	if ctx.scimToken == "" {
		t.Fatal("groupSCIM: the server under test was started without a SCIM token (harness.DBBackend.EnableSCIM)")
	}
	adminToken := c.token
	defer func() { c.token = adminToken }()

	// Authentication: the SCIM surface takes the SCIM token and nothing else. The admin's
	// session token and a missing header are refused; so is a wrong token. One wrong attempt
	// only: the middleware rate-limits repeated invalid tokens.
	c.token = ""
	c.callExpect("GET", "GET /scim/v2/ServiceProviderConfig", "/scim/v2/ServiceProviderConfig", nil, 401)
	c.token = adminToken
	c.callExpect("GET", "GET /scim/v2/ServiceProviderConfig", "/scim/v2/ServiceProviderConfig", nil, 401)

	c.token = ctx.scimToken
	spc := c.callExpect("GET", "GET /scim/v2/ServiceProviderConfig", "/scim/v2/ServiceProviderConfig", nil, 200)
	var cfg struct {
		Patch struct {
			Supported bool `json:"supported"`
		} `json:"patch"`
		Filter struct {
			Supported bool `json:"supported"`
		} `json:"filter"`
	}
	scimDecode(t, spc, &cfg, "ServiceProviderConfig")
	if !cfg.Patch.Supported || !cfg.Filter.Supported {
		t.Errorf("ServiceProviderConfig must advertise patch and filter support, got %s", spc.Body)
	}

	// ── Users ────────────────────────────────────────────────────────────────
	const (
		userName = "scim-smoke-user@example.invalid"
		extID    = "idp|scim-smoke-user"
	)
	created := c.callExpect("POST", "POST /scim/v2/Users", "/scim/v2/Users", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    userName,
		"externalId":  extID,
		"displayName": "SCIM Smoke User",
		"active":      true,
		"emails":      []map[string]any{{"value": userName, "primary": true}},
	}, 201)
	var user scimResource
	scimDecode(t, created, &user, "create SCIM user")
	if user.ID == "" || user.UserName != userName || !user.Active {
		t.Fatalf("created SCIM user: want an id, userName %q and active=true, got %s", userName, created.Body)
	}
	u := "/scim/v2/Users/" + user.ID

	// The same user again is refused, not duplicated.
	c.callExpect("POST", "POST /scim/v2/Users", "/scim/v2/Users", map[string]any{
		"userName": userName, "externalId": extID, "active": true,
	}, 409)

	got := c.callExpect("GET", "GET /scim/v2/Users/{id}", u, nil, 200)
	var read scimResource
	scimDecode(t, got, &read, "get SCIM user")
	if read.ID != user.ID || read.UserName != userName || read.DisplayName != "SCIM Smoke User" {
		t.Errorf("GET SCIM user: want the created user back, got %s", got.Body)
	}

	replaced := c.callExpect("PUT", "PUT /scim/v2/Users/{id}", u, map[string]any{
		"userName": userName, "displayName": "SCIM Smoke User (renamed)", "active": true,
		"emails": []map[string]any{{"value": userName, "primary": true}},
	}, 200)
	var afterPut scimResource
	scimDecode(t, replaced, &afterPut, "replace SCIM user")
	if afterPut.DisplayName != "SCIM Smoke User (renamed)" || !afterPut.Active {
		t.Errorf("PUT SCIM user: want the new displayName and active=true, got %s", replaced.Body)
	}

	// The reconciliation lookup an IdP runs before it creates anything.
	found := scimUserList(ctx, `userName eq "`+userName+`"`)
	if found.TotalResults != 1 || len(found.Resources) != 1 || found.Resources[0].ID != user.ID {
		t.Errorf("filter userName eq %q: want exactly the created user %s, got %+v", userName, user.ID, found)
	}
	none := scimUserList(ctx, `userName eq "nobody-here@example.invalid"`)
	if none.TotalResults != 0 || len(none.Resources) != 0 {
		t.Errorf("filter on an unknown userName: want no resources, got %+v", none)
	}
	c.callExpect("GET", "GET /scim/v2/Users", "/scim/v2/Users?filter="+url.QueryEscape(`emails co "x"`), nil, 400)
	all := scimUserList(ctx, "")
	if !scimListHas(all, user.ID) {
		t.Errorf("unfiltered user list must contain %s, got %+v", user.ID, all)
	}

	deact := c.callExpect("PATCH", "PATCH /scim/v2/Users/{id}", u, scimPatchBody(map[string]any{
		"op": "replace", "path": "active", "value": false,
	}), 200)
	var afterPatch scimResource
	scimDecode(t, deact, &afterPatch, "deactivate SCIM user")
	if afterPatch.Active {
		t.Errorf("PATCH active=false: the user must read back inactive, got %s", deact.Body)
	}
	reread := c.callExpect("GET", "GET /scim/v2/Users/{id}", u, nil, 200)
	var stillInactive scimResource
	scimDecode(t, reread, &stillInactive, "re-read deactivated SCIM user")
	if stillInactive.Active {
		t.Errorf("a deactivated user must stay inactive on a fresh GET, got %s", reread.Body)
	}

	// ── Groups ───────────────────────────────────────────────────────────────
	const groupName = "scim-smoke-group"
	gcreated := c.callExpect("POST", "POST /scim/v2/Groups", "/scim/v2/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": groupName,
		"members":     []map[string]any{{"value": user.ID}},
	}, 201)
	var group scimResource
	scimDecode(t, gcreated, &group, "create SCIM group")
	if group.ID == "" || group.DisplayName != groupName || !equalStrings(group.memberIDs(), []string{user.ID}) {
		t.Fatalf("created SCIM group: want an id, name %q and member %s, got %s", groupName, user.ID, gcreated.Body)
	}
	g := "/scim/v2/Groups/" + group.ID

	ggot := c.callExpect("GET", "GET /scim/v2/Groups/{id}", g, nil, 200)
	var gread scimResource
	scimDecode(t, ggot, &gread, "get SCIM group")
	if gread.ID != group.ID || !equalStrings(gread.memberIDs(), []string{user.ID}) {
		t.Errorf("GET SCIM group: want the created group with its member, got %s", ggot.Body)
	}
	gall := scimGroupList(ctx, "")
	if !scimListHas(gall, group.ID) {
		t.Errorf("unfiltered group list must contain %s, got %+v", group.ID, gall)
	}
	gfound := scimGroupList(ctx, `displayName eq "`+groupName+`"`)
	if gfound.TotalResults != 1 || len(gfound.Resources) != 1 || gfound.Resources[0].ID != group.ID {
		t.Errorf("filter displayName eq %q: want exactly the created group %s, got %+v", groupName, group.ID, gfound)
	}

	// PUT replaces the whole member set: an empty array empties the group.
	emptied := c.callExpect("PUT", "PUT /scim/v2/Groups/{id}", g, map[string]any{
		"displayName": groupName, "members": []map[string]any{},
	}, 200)
	var afterEmpty scimResource
	scimDecode(t, emptied, &afterEmpty, "replace SCIM group members")
	if len(afterEmpty.Members) != 0 {
		t.Errorf("PUT with no members must empty the group, got %s", emptied.Body)
	}
	refilled := c.callExpect("PUT", "PUT /scim/v2/Groups/{id}", g, map[string]any{
		"displayName": groupName, "members": []map[string]any{{"value": user.ID}},
	}, 200)
	var afterRefill scimResource
	scimDecode(t, refilled, &afterRefill, "replace SCIM group members")
	if !equalStrings(afterRefill.memberIDs(), []string{user.ID}) {
		t.Errorf("PUT with one member: want exactly %s, got %s", user.ID, refilled.Body)
	}

	// PATCH removes then re-adds a member, the two operations IdPs send.
	removed := c.callExpect("PATCH", "PATCH /scim/v2/Groups/{id}", g, scimPatchBody(map[string]any{
		"op": "remove", "path": `members[value eq "` + user.ID + `"]`,
	}), 200, 204)
	if removed.StatusCode == 200 {
		var afterRemove scimResource
		scimDecode(t, removed, &afterRemove, "patch SCIM group (remove)")
		if len(afterRemove.Members) != 0 {
			t.Errorf("PATCH remove member: the group must be empty, got %s", removed.Body)
		}
	}
	added := c.callExpect("PATCH", "PATCH /scim/v2/Groups/{id}", g, scimPatchBody(map[string]any{
		"op": "add", "path": "members", "value": []map[string]any{{"value": user.ID}},
	}), 200)
	var afterAdd scimResource
	scimDecode(t, added, &afterAdd, "patch SCIM group (add)")
	if !equalStrings(afterAdd.memberIDs(), []string{user.ID}) {
		t.Errorf("PATCH add member: want exactly %s, got %s", user.ID, added.Body)
	}

	// ── Deprovision ──────────────────────────────────────────────────────────
	c.callExpect("DELETE", "DELETE /scim/v2/Groups/{id}", g, nil, 204)
	c.callExpect("GET", "GET /scim/v2/Groups/{id}", g, nil, 404)
	c.callExpect("DELETE", "DELETE /scim/v2/Users/{id}", u, nil, 204)
	c.callExpect("GET", "GET /scim/v2/Users/{id}", u, nil, 404)

	// ── Audit: every SCIM write left its row, attributed to the SCIM principal ──
	c.token = adminToken
	scimAuditRows(ctx, "scim.user_provisioned", 1)
	scimAuditRows(ctx, "scim.user_updated", 2) // the PUT and the deactivating PATCH
	scimAuditRows(ctx, "scim.user_deprovisioned", 1)
	scimAuditRows(ctx, "scim.group_provisioned", 1)
	scimAuditRows(ctx, "scim.group_updated", 4) // two PUTs, a PATCH remove and a PATCH add
	scimAuditRows(ctx, "scim.group_deprovisioned", 1)
}

func scimPatchBody(ops ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": ops,
	}
}

func scimDecode(t *testing.T, env envelope, v any, what string) {
	if err := json.Unmarshal(env.Body, v); err != nil {
		t.Fatalf("%s: decode SCIM response: %v\nraw: %s", what, err, env.Body)
	}
}

func scimUserList(ctx *smokeCtx, filter string) scimList {
	path := "/scim/v2/Users"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	env := ctx.c.callExpect("GET", "GET /scim/v2/Users", path, nil, 200)
	var list scimList
	scimDecode(ctx.t, env, &list, "list SCIM users")
	return list
}

func scimGroupList(ctx *smokeCtx, filter string) scimList {
	path := "/scim/v2/Groups"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	env := ctx.c.callExpect("GET", "GET /scim/v2/Groups", path, nil, 200)
	var list scimList
	scimDecode(ctx.t, env, &list, "list SCIM groups")
	return list
}

func scimListHas(l scimList, id string) bool {
	for _, r := range l.Resources {
		if r.ID == id {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// scimAuditRows asserts the admin-readable audit log holds exactly want rows of eventType and
// that each is attributed to the SCIM principal. The provisioning token is no account, so the
// row carries no user or machine identity: the API reports it as the "system" actor.
func scimAuditRows(ctx *smokeCtx, eventType string, want int) {
	t, c := ctx.t, ctx.c
	env := c.callExpect("GET", "GET /api/v1/audit/search", "/api/v1/audit/search?limit=100&action="+url.QueryEscape(eventType), nil, 200)
	var data struct {
		Events []struct {
			EventType string `json:"event_type"`
			Actor     string `json:"actor"`
			ActorType string `json:"actor_type"`
		} `json:"events"`
	}
	c.unmarshalData(env, &data, "audit search "+eventType)
	if len(data.Events) != want {
		t.Errorf("audit rows %s: want exactly %d, got %d", eventType, want, len(data.Events))
	}
	for i, e := range data.Events {
		if e.EventType != eventType {
			t.Errorf("audit row %d of %s has event_type %q", i, eventType, e.EventType)
		}
		if e.ActorType != "system" || e.Actor != "system" {
			t.Errorf("audit row %d of %s: want the SCIM principal (actor_type and actor both \"system\"), got actor_type %q actor %q",
				i, eventType, e.ActorType, e.Actor)
		}
	}
}
