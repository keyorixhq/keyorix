// secret_listing_query.go — ListSecretsWithSharingInfo and helpers.
//
// For sharing status and UI indicators see secret_listing_sharing.go.
package core

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsInScope lists every secret in the filter's project/environment
// scope, with no per-user ownership or sharing resolution. It backs machine
// principals (ADR-030), which have no user identity and whose authorization to
// the scope is already enforced by the route's scoped-permission gate. The
// response shape matches ListSecretsWithSharingInfo so the handler is uniform;
// the sharing fields are owner-agnostic (a machine does not "own" or have
// secrets "shared with" it).
func (c *KeyorixCore) ListSecretsInScope(ctx context.Context, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	storageFilter := c.convertToStorageFilter(filter)
	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	all := make([]*models.SecretWithSharingInfo, 0, len(secrets))
	for _, secret := range secrets {
		all = append(all, &models.SecretWithSharingInfo{SecretNode: secret})
	}
	all = c.applySecretFilters(ctx, all, filter)
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return &models.SecretListResponse{
		Secrets:    all[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ListSecretsWithSharingInfo lists secrets with sharing information for a specific user.
func (c *KeyorixCore) ListSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) { // NOSONAR -- cognitive complexity 19, suppress go:S3776
	if filter == nil {
		filter = &models.SecretListFilter{}
	}

	// Fetch owned secrets (skip when user only wants to see what's shared with them).
	var ownedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowSharedOnly {
		var err error
		ownedSecrets, err = c.getOwnedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Fetch shared secrets (only when not filtering by project — project view shows owned only).
	var sharedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowOwnedOnly && filter.ProjectID == nil {
		var err error
		sharedSecrets, err = c.getSharedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Fetch ACL-granted secrets — secrets the user holds a per-secret or per-folder
	// SecretACL grant for but neither owns nor has a legacy ShareRecord for.
	var aclGrantedSecrets []*models.SecretWithSharingInfo
	if !filter.ShowOwnedOnly {
		var err error
		aclGrantedSecrets, err = c.getACLGrantedSecretsWithSharingInfo(ctx, userID, filter)
		if err != nil {
			return nil, err
		}
	}

	// Merge owned + shared + acl-granted, deduplicating by secret ID.
	// aclDistinctCount tracks how many ACL-granted secrets were NOT already
	// covered by owned or shared, so ACLGrantedCount reflects only net-new grants.
	seen := make(map[uint]bool)
	var all []*models.SecretWithSharingInfo
	for _, s := range ownedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}
	for _, s := range sharedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
		}
	}
	aclDistinctCount := 0
	for _, s := range aclGrantedSecrets {
		if !seen[s.ID] {
			seen[s.ID] = true
			all = append(all, s)
			aclDistinctCount++
		}
	}

	// Apply post-fetch filters (search, type, shared-only)
	all = c.applySecretFilters(ctx, all, filter)

	// Sort
	c.sortSecrets(all, filter.SortBy, filter.SortOrder)

	total := int64(len(all))

	// Paginate
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	paged := all[start:end]

	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	return &models.SecretListResponse{
		Secrets:         paged,
		Total:           total,
		Page:            page,
		PageSize:        pageSize,
		TotalPages:      totalPages,
		OwnedCount:      len(ownedSecrets),
		SharedCount:     len(sharedSecrets),
		ACLGrantedCount: aclDistinctCount,
	}, nil
}

// getOwnedSecretsWithSharingInfo retrieves secrets owned by the user with sharing information.
func (c *KeyorixCore) getOwnedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	storageFilter := c.convertToStorageFilter(filter)

	// Resolve the user first — fail closed for an unknown/zero principal (e.g. a
	// machine identity has no owning user, so it owns no secrets).
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("failed to resolve user for secret listing: %w", err)
	}
	// "Owned" means owner_id == userID — the canonical ownership the permission
	// model uses (CheckSecretPermission), not the created_by username string. The
	// username proxy missed CLI-created secrets (created_by "cli-user") and could
	// mis-attribute ownership across a deleted-then-reused username.
	storageFilter.OwnerID = &userID

	secrets, _, err := c.storage.ListSecrets(ctx, storageFilter)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, secret := range secrets {
		shares, err := c.storage.ListSharesBySecret(ctx, secret.ID)
		if err != nil {
			continue
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          len(shares) > 0,
			IsOwnedByUser:     true,
			UserPermission:    "",
			ShareCount:        len(shares),
			SharingIndicators: c.buildSharingIndicators(secret, shares, true, ""),
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *KeyorixCore) getSharedSecretsWithSharingInfo(ctx context.Context, userID uint, _ *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	shares, err := c.storage.ListSharesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	var result []*models.SecretWithSharingInfo
	for _, share := range shares {
		secret, err := c.storage.GetSecret(ctx, share.SecretID)
		if err != nil || secret == nil {
			continue
		}
		ownerUsername := ""
		if owner, err := c.storage.GetUser(ctx, secret.OwnerID); err == nil && owner != nil {
			ownerUsername = owner.Username
		}
		s := &models.SecretWithSharingInfo{
			SecretNode:        secret,
			IsShared:          true,
			IsOwnedByUser:     false,
			OwnerUsername:     ownerUsername,
			UserPermission:    string(share.Permission),
			ShareCount:        0,
			SharingIndicators: c.buildSharingIndicators(secret, nil, false, string(share.Permission)),
		}
		result = append(result, s)
	}
	return result, nil
}

func (c *KeyorixCore) applySecretFilters(ctx context.Context, secrets []*models.SecretWithSharingInfo, filter *models.SecretListFilter) []*models.SecretWithSharingInfo {
	// Tag filter: require every requested tag (AND). Resolved per secret only when a
	// tag filter is present, so the common no-tag list path does no extra queries.
	want := normalizeTagFilter(filter.Tags)
	var out []*models.SecretWithSharingInfo
	for _, s := range secrets {
		if c.secretPassesFilters(ctx, s, filter, want) {
			out = append(out, s)
		}
	}
	return out
}

// secretPassesFilters reports whether a secret satisfies all active list filters.
func (c *KeyorixCore) secretPassesFilters(ctx context.Context, s *models.SecretWithSharingInfo, filter *models.SecretListFilter, want []string) bool {
	if filter.ShowSharedOnly && !s.IsShared {
		return false
	}
	if len(want) > 0 && !c.secretHasAllTags(ctx, s.ID, want) {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		if !c.secretMatchesSearch(ctx, s, strings.ToLower(*filter.Search)) {
			return false
		}
	}
	if filter.Type != nil && *filter.Type != "" && s.Type != *filter.Type {
		return false
	}
	if !secretMatchesClassification(s, filter) {
		return false
	}
	return secretMatchesExpiration(s, filter)
}

func secretMatchesClassification(s *models.SecretWithSharingInfo, filter *models.SecretListFilter) bool {
	if filter.Classification == nil || *filter.Classification == "" {
		return true
	}
	if *filter.Classification == "unclassified" {
		return s.Classification == ""
	}
	return s.Classification == *filter.Classification
}

func secretMatchesExpiration(s *models.SecretWithSharingInfo, filter *models.SecretListFilter) bool {
	if filter.ExpiresBefore == nil {
		return true
	}
	return s.Expiration != nil && s.Expiration.Before(*filter.ExpiresBefore)
}

// normalizeTagFilter trims/lowercases/de-duplicates requested tag filters (matching
// how tags are stored), dropping empties.
func normalizeTagFilter(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// secretHasAllTags reports whether the secret carries every tag in want. A storage
// error is treated as "no match" (fail closed — the secret is excluded).
func (c *KeyorixCore) secretHasAllTags(ctx context.Context, secretID uint, want []string) bool {
	have, err := c.storage.GetSecretTags(ctx, secretID)
	if err != nil {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, t := range have {
		set[t] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// secretMatchesSearch reports whether the secret matches the (lower-cased) search
// query by name, description, or any tag. Name/description are in-memory; tags are
// looked up only when neither already matched (so the common name-hit costs nothing
// extra). A tag-lookup error just means tags don't contribute to the match.
func (c *KeyorixCore) secretMatchesSearch(ctx context.Context, s *models.SecretWithSharingInfo, q string) bool {
	if strings.Contains(strings.ToLower(s.Name), q) {
		return true
	}
	if s.Description != "" && strings.Contains(strings.ToLower(s.Description), q) {
		return true
	}
	tags, err := c.storage.GetSecretTags(ctx, s.ID)
	if err != nil {
		return false
	}
	for _, t := range tags { // stored tags are already lower-cased
		if strings.Contains(t, q) {
			return true
		}
	}
	return false
}

// sortSecrets sorts the secret list by name, created_at, updated_at, or owner.
// Uses strict comparators (Before/After, <, >) so equal elements return false in
// both directions, letting sort.SliceStable preserve insertion order as a tie-break.
func (c *KeyorixCore) sortSecrets(secrets []*models.SecretWithSharingInfo, sortBy, sortOrder string) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	if sortBy == "" {
		sortBy = "updated_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	desc := sortOrder == "desc"
	sort.SliceStable(secrets, func(i, j int) bool {
		a, b := secrets[i], secrets[j]
		switch sortBy {
		case "name":
			if desc {
				return a.Name > b.Name
			}
			return a.Name < b.Name
		case "created_at":
			if desc {
				return a.CreatedAt.After(b.CreatedAt)
			}
			return a.CreatedAt.Before(b.CreatedAt)
		case "owner":
			if desc {
				return a.OwnerUsername > b.OwnerUsername
			}
			return a.OwnerUsername < b.OwnerUsername
		default: // updated_at / recently modified
			if desc {
				return a.UpdatedAt.After(b.UpdatedAt)
			}
			return a.UpdatedAt.Before(b.UpdatedAt)
		}
	})
}

// secretListingMaxRows bounds the single unpaginated storage fetch backing
// ListSecretsInScope / ListSecretsWithSharingInfo (mirrors secretInventoryMaxRows
// in secret_inventory.go). Both callers apply post-fetch filters in Go — tag
// AND-matching and cross-field search need a per-secret storage lookup, and
// ShowSharedOnly only makes sense after owned+shared results are merged — none of
// which can be expressed as a single SQL predicate the storage layer could apply
// before its own LIMIT/OFFSET. If the DB paginated to the caller's requested page
// FIRST and the post-fetch filter ran second, the filter would silently operate on
// (and the code below would re-paginate) an already-sliced page: page >= 2 could
// come back empty even when more genuinely-matching secrets exist beyond page 1,
// and Total/TotalPages would reflect the pre-filter page count rather than the
// true post-filter match count (#251). So the storage fetch always pulls every
// matching row (up to this bound) and pagination is applied once, in Go, after
// filtering the full set.
const secretListingMaxRows = 10000

// convertToStorageFilter converts SecretListFilter to storage.SecretFilter. It
// deliberately ignores the caller's Page/PageSize — see secretListingMaxRows.
func (c *KeyorixCore) convertToStorageFilter(filter *models.SecretListFilter) *storage.SecretFilter {
	return &storage.SecretFilter{
		Page:           1,
		PageSize:       secretListingMaxRows,
		Type:           filter.Type,
		Classification: filter.Classification,
		CreatedBy:      filter.CreatedBy,
		ProjectID:      filter.ProjectID,
		EnvironmentID:  filter.EnvironmentID,
		IncludeDeleted: filter.IncludeDeleted,
		ParentID:       filter.ParentID,
		FolderOnly:     filter.FolderOnly,
		Search:         filter.Search,
	}
}

// aclFolderMaxDepth caps the BFS depth when expanding folder-level ACL grants to
// their descendant leaf secrets. Mirrors the ancestor-walk cap in GetSecretAncestors.
const aclFolderMaxDepth = 20

// getACLGrantedSecretsWithSharingInfo returns secrets the user holds a per-secret or
// per-folder SecretACL grant for but neither owns nor has a legacy ShareRecord for.
// It expands folder grants by collecting all descendant leaf secrets via BFS.
func (c *KeyorixCore) getACLGrantedSecretsWithSharingInfo(ctx context.Context, userID uint, filter *models.SecretListFilter) ([]*models.SecretWithSharingInfo, error) {
	acls, err := c.storage.ListSecretACLsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(acls) == 0 {
		return nil, nil
	}

	seen := make(map[uint]bool)
	var result []*models.SecretWithSharingInfo

	for _, acl := range acls {
		c.applyACLGrant(ctx, acl, filter, seen, &result)
	}

	return result, nil
}

// collectFolderDescendants does a BFS from folderID and returns all leaf
// (IsSecret=true) descendant SecretNodes. Sub-folders are expanded up to
// aclFolderMaxDepth levels to match the ancestor-walk cap in HasSecretACL.
// Project/environment filters are honoured so that a folder grant in project A
// does not bleed into project B when the caller is listing project B only.
func (c *KeyorixCore) collectFolderDescendants(ctx context.Context, folderID uint, filter *models.SecretListFilter, depth int) []*models.SecretNode {
	if depth >= aclFolderMaxDepth {
		return nil
	}
	sf := &storage.SecretFilter{
		Page:          1,
		PageSize:      secretListingMaxRows,
		ParentID:      &folderID,
		ProjectID:     filter.ProjectID,
		EnvironmentID: filter.EnvironmentID,
	}
	children, _, err := c.storage.ListSecrets(ctx, sf)
	if err != nil {
		return nil
	}
	var result []*models.SecretNode
	for _, child := range children {
		if child.IsSecret {
			result = append(result, child)
		} else {
			result = append(result, c.collectFolderDescendants(ctx, child.ID, filter, depth+1)...)
		}
	}
	return result
}

// applyACLGrant processes a single ACL grant, expanding folder nodes to leaf
// secrets and appending any un-seen entries to result.
func (c *KeyorixCore) applyACLGrant(ctx context.Context, acl *models.SecretACL, filter *models.SecretListFilter, seen map[uint]bool, result *[]*models.SecretWithSharingInfo) {
	perm := ""
	if perms := DecodeSecretACLPerms(acl.Permissions); len(perms) > 0 {
		perm = normaliseACLPerm(perms[0])
	}

	node, err := c.storage.GetSecret(ctx, acl.SecretID)
	if err != nil || node == nil {
		return
	}
	if filter.ProjectID != nil && node.ProjectID != *filter.ProjectID {
		return
	}
	if filter.EnvironmentID != nil && node.EnvironmentID != *filter.EnvironmentID {
		return
	}

	var leaves []*models.SecretNode
	if node.IsSecret {
		leaves = []*models.SecretNode{node}
	} else {
		leaves = c.collectFolderDescendants(ctx, node.ID, filter, 0)
	}

	for _, leaf := range leaves {
		if seen[leaf.ID] {
			continue
		}
		seen[leaf.ID] = true
		*result = append(*result, &models.SecretWithSharingInfo{
			SecretNode:        leaf,
			IsShared:          false,
			IsOwnedByUser:     false,
			UserPermission:    perm,
			SharingIndicators: c.buildSharingIndicators(leaf, nil, false, perm),
		})
	}
}

// normaliseACLPerm maps an RBAC-style ACL permission name ("secrets.read",
// "secrets.write") to the sharing-style short form ("read", "write") used by
// the SharingIndicators builder and the UserPermission field. Unknown values
// are returned unchanged.
func normaliseACLPerm(p string) string {
	switch p {
	case "secrets.read":
		return "read"
	case "secrets.write":
		return "write"
	default:
		return p
	}
}
