// scim_groups.go — SCIM 2.0 Groups endpoints (RFC 7644), the companion to scim.go.
// Maps a SCIM Group to a native Keyorix group (displayName → name) and its members
// to user↔group links. PUT replaces the full member set; PATCH adds/removes members
// (the common Okta/Entra ops) and may rename.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

// SCIM group-mutation bounds: a single request may not carry more than these many
// member entries or patch operations, so a multi-MiB members[] / Operations[] array
// can't fan out into hundreds of thousands of per-member DB writes (the body is already
// capped at 10 MiB, but that still permits a very large small-object array).
const (
	scimMaxMembersPerRequest = 5000
	scimMaxPatchOps          = 1000
)

func toSCIMGroup(g *models.Group, members []*models.User) map[string]any {
	mem := make([]map[string]any, 0, len(members))
	for _, u := range members {
		mem = append(mem, map[string]any{
			"value":   strconv.FormatUint(uint64(u.ID), 10),
			"display": u.Email,
		})
	}
	return map[string]any{
		"schemas":     []string{scimGroupSchema},
		"id":          strconv.FormatUint(uint64(g.ID), 10),
		"displayName": g.Name,
		"members":     mem,
		"meta": map[string]any{
			"resourceType": "Group",
			"location":     fmt.Sprintf("/scim/v2/Groups/%d", g.ID),
		},
	}
}

type scimGroupPayload struct {
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (p *scimGroupPayload) memberIDs() []uint {
	out := make([]uint, 0, len(p.Members))
	for _, m := range p.Members {
		if id, err := strconv.ParseUint(m.Value, 10, 32); err == nil {
			out = append(out, uint(id))
		}
	}
	return out
}

// renderGroup writes a group with its current members at the given status. A failed
// member read answers the SCIM error instead: rendering the group with an empty member
// list would tell the IdP the group has no members, and it would remove them all.
func (h *SCIMHandler) renderGroup(w http.ResponseWriter, r *http.Request, g *models.Group, status int) {
	members, err := h.coreService.GetGroupMembers(r.Context(), g.ID)
	if err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("reading members of SCIM group %d", g.ID), err)
		return
	}
	writeSCIM(w, status, toSCIMGroup(g, members))
}

var scimGroupNameFilter = regexp.MustCompile(`(?i)displayName\s+eq\s+"([^"]+)"`)

// ListGroups handles GET /scim/v2/Groups — optionally filtered by displayName.
//
// The unfiltered (common, directory-sync) path is backed by a bounded,
// offset-limited storage query (ListSCIMGroupsPage) so an IdP paging through
// startIndex/count never loads the whole groups table into memory. The filtered
// (displayName eq) path still does a full scan — there is no indexed
// group-by-name lookup today (unlike users, which have FindSCIMUser) — but that
// path is a narrow, bounded "does this one group exist" check during
// provisioning, not a directory-wide sync, so it's out of scope for this fix.
func (h *SCIMHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	var wantName string
	if filter := r.URL.Query().Get("filter"); filter != "" {
		m := scimGroupNameFilter.FindStringSubmatch(filter)
		if m == nil {
			scimError(w, http.StatusBadRequest, "only 'displayName eq' filtering is supported")
			return
		}
		wantName = m[1]
	}

	startIndex, count := scimPaging(r)

	var page []*models.Group
	var total int
	if wantName != "" {
		groups, err := h.coreService.ListGroups(r.Context())
		if err != nil {
			log.Printf("Error listing SCIM groups: %v", err)
			scimError(w, http.StatusInternalServerError, clientSafe(err))
			return
		}
		matched := groups[:0]
		for _, g := range groups {
			if g.Name == wantName {
				matched = append(matched, g)
			}
		}
		total = len(matched)
		page = pageSlice(matched, startIndex, count)
	} else {
		var err error
		page, total, err = h.coreService.ListSCIMGroupsPage(r.Context(), startIndex, count)
		if err != nil {
			log.Printf("Error listing SCIM groups (page): %v", err)
			scimError(w, http.StatusInternalServerError, clientSafe(err))
			return
		}
	}

	// Members are fetched ONLY for the groups on the returned page, so the
	// per-group GetGroupMembers query (an N+1) is capped at the page size instead
	// of running across the whole directory.
	resources := make([]map[string]any, 0, len(page))
	for _, g := range page {
		members, err := h.coreService.GetGroupMembers(r.Context(), g.ID)
		if err != nil {
			writeSCIMWriteError(w, r, fmt.Sprintf("listing members of SCIM group %d", g.ID), err)
			return
		}
		resources = append(resources, toSCIMGroup(g, members))
	}
	writeSCIM(w, http.StatusOK, listResponsePaged(resources, total, startIndex))
}

// pageSlice returns the [startIndex, startIndex+count) window of items (startIndex is
// 1-based), clamped to the slice bounds.
func pageSlice[T any](items []T, startIndex, count int) []T {
	lo := max(startIndex-1, 0)
	if lo >= len(items) || count <= 0 {
		return nil
	}
	hi := min(lo+count, len(items))
	return items[lo:hi]
}

// GetGroup handles GET /scim/v2/Groups/{id}.
func (h *SCIMHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	g, err := h.coreService.GetGroup(r.Context(), id)
	if err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("reading SCIM group %d", id), err)
		return
	}
	h.renderGroup(w, r, g, http.StatusOK)
}

// CreateGroup handles POST /scim/v2/Groups — provision a group with initial members.
func (h *SCIMHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var p scimGroupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM payload")
		return
	}
	if p.DisplayName == "" {
		scimError(w, http.StatusBadRequest, "displayName is required")
		return
	}
	if len(p.Members) > scimMaxMembersPerRequest {
		scimError(w, http.StatusRequestEntityTooLarge, errTooManyMembers)
		return
	}
	st, err := h.coreService.ProvisionSCIMGroup(r.Context(), 0, p.DisplayName, p.memberIDs())
	if err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("provisioning SCIM group %q", p.DisplayName), err)
		return
	}
	// Read in the create's own transaction, like PUT/PATCH: a member read after the
	// commit that failed would answer 500 for a group that exists, and the IdP's retry
	// of the POST would then hit 409 on the duplicate name.
	writeSCIM(w, http.StatusCreated, toSCIMGroup(st.Group, st.Members))
}

// ReplaceGroup handles PUT /scim/v2/Groups/{id} — rename + full member replace.
func (h *SCIMHandler) ReplaceGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var p scimGroupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM payload")
		return
	}
	if len(p.Members) > scimMaxMembersPerRequest {
		scimError(w, http.StatusRequestEntityTooLarge, errTooManyMembers)
		return
	}
	st, err := h.coreService.ReplaceSCIMGroup(r.Context(), 0, id, p.DisplayName, p.memberIDs())
	if err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("replacing SCIM group %d", id), err)
		return
	}
	// The committed state comes from the write's own transaction: a member read after
	// the commit that failed would answer 500 for a write that was applied.
	writeSCIM(w, http.StatusOK, toSCIMGroup(st.Group, st.Members))
}

var scimMemberFilterPath = regexp.MustCompile(`(?i)members\[\s*value\s+eq\s+"([^"]+)"\s*\]`)

// PatchGroup handles PATCH /scim/v2/Groups/{id} — add/remove members (the common
// IdP operations) and optional rename. A replace of the whole `members` array is
// routed through the full-replace path.
func (h *SCIMHandler) PatchGroup(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 34, suppress go:S3776
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	var patch scimPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		scimError(w, http.StatusBadRequest, "invalid SCIM patch")
		return
	}
	if len(patch.Operations) > scimMaxPatchOps {
		scimError(w, http.StatusRequestEntityTooLarge, "too many patch operations in one request")
		return
	}

	var newName *string
	var addIDs, removeIDs []uint
	var replaceMembers []uint
	replaceAll := false

	parseValueMembers := func(raw json.RawMessage) []uint {
		var arr []struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(raw, &arr) != nil {
			return nil
		}
		var ids []uint
		for _, m := range arr {
			if v, err := strconv.ParseUint(m.Value, 10, 32); err == nil {
				ids = append(ids, uint(v))
			}
		}
		return ids
	}

	for _, op := range patch.Operations {
		path := strings.TrimSpace(op.Path)
		lower := strings.ToLower(path)
		// Filtered single-member path: members[value eq "X"]. The member id comes
		// from the filter expression itself, not from op.Value — but which side
		// (add vs. remove) it lands on MUST still be driven by op.Op (RFC 7644
		// §3.5.2): "remove" deletes that member, while "add"/"replace" ensure that
		// member is present, mirroring the non-filtered `members` handling below.
		// Ignoring op.Op here previously treated every filtered-path operation as a
		// removal regardless of what the client actually requested (#226).
		if m := scimMemberFilterPath.FindStringSubmatch(path); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				continue
			}
			switch {
			case strings.EqualFold(op.Op, "remove"):
				removeIDs = append(removeIDs, uint(v))
			case strings.EqualFold(op.Op, "add"), strings.EqualFold(op.Op, "replace"):
				addIDs = append(addIDs, uint(v))
			}
			continue
		}
		switch {
		case lower == "displayname" && strings.EqualFold(op.Op, "replace"):
			var s string
			if json.Unmarshal(op.Value, &s) == nil {
				newName = &s
			}
		case lower == "members" && strings.EqualFold(op.Op, "add"):
			addIDs = append(addIDs, parseValueMembers(op.Value)...)
		case lower == "members" && strings.EqualFold(op.Op, "remove"):
			removeIDs = append(removeIDs, parseValueMembers(op.Value)...)
		case lower == "members" && strings.EqualFold(op.Op, "replace"):
			replaceAll = true
			replaceMembers = parseValueMembers(op.Value)
		}
	}

	if len(addIDs)+len(removeIDs)+len(replaceMembers) > scimMaxMembersPerRequest {
		scimError(w, http.StatusRequestEntityTooLarge, errTooManyMembers)
		return
	}

	var st *core.SCIMGroupState
	var err error
	if replaceAll {
		name := ""
		if newName != nil {
			name = *newName
		}
		st, err = h.coreService.ReplaceSCIMGroup(r.Context(), 0, id, name, replaceMembers)
	} else {
		st, err = h.coreService.PatchSCIMGroup(r.Context(), 0, id, newName, addIDs, removeIDs)
	}
	if err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("patching SCIM group %d", id), err)
		return
	}
	writeSCIM(w, http.StatusOK, toSCIMGroup(st.Group, st.Members))
}

// DeleteGroup handles DELETE /scim/v2/Groups/{id}.
func (h *SCIMHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := scimID(w, r)
	if !ok {
		return
	}
	if err := h.coreService.DeprovisionSCIMGroup(r.Context(), 0, id); err != nil {
		writeSCIMWriteError(w, r, fmt.Sprintf("deprovisioning SCIM group %d", id), err)
		return
	}
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(http.StatusNoContent)
}
