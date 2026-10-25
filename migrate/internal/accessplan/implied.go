package accessplan

import (
	"slices"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// impliedAccess returns the access a secrets.read grant for the Create-mapped stanza at path
// adds beyond what the role/user's own Vault policies grant: Keyorix's secrets.read also lists
// secret names and reads version metadata in the scope. Vault grants those separately: on KV v2
// "list" and "read" on the metadata/ twin of the data/ subtree, on KV v1 "list" on the same
// subtree (KV v1 keeps no version metadata, so that part is always implied). granting is every
// non-deny stanza of the same role/user and denyPaths every deny stanza; a deny anywhere in the
// subtree, a "+" segment or a path this cannot place on a KV mount counts as not granted, so
// the report errs towards listing a policy.
func impliedAccess(path string, mapper *PathMapper, granting []healthscan.PolicyPathBlock, denyPaths []string) []string {
	literal, _ := wildcardSplit(path)
	var namesDir, metadataDir string
	if km, ok := mapper.kvMountFor(path); ok {
		switch {
		case km.KVVersion == 2 && strings.HasPrefix(literal, km.Path+"data/"):
			namesDir = km.Path + "metadata/" + strings.TrimPrefix(literal, km.Path+"data/")
			metadataDir = namesDir
		case km.KVVersion == 1:
			namesDir = literal
		}
	}
	var out []string
	if !grantsWholeDir(granting, denyPaths, namesDir, "list") {
		out = append(out, ImpliedListNames)
	}
	if !grantsWholeDir(granting, denyPaths, metadataDir, "read") {
		out = append(out, ImpliedReadVersionMetadata)
	}
	return out
}

// grantsWholeDir reports whether some stanza grants capability on every path under dir and no
// deny stanza touches any of them. dir "" means there is no Vault equivalent at all.
func grantsWholeDir(granting []healthscan.PolicyPathBlock, denyPaths []string, dir, capability string) bool {
	if dir == "" || overlapsAnyDeny(dir+"*", denyPaths) {
		return false
	}
	for _, b := range granting {
		if containsCapability(b.Capabilities, capability) && globCovers(b.Path, dir) {
			return true
		}
	}
	return false
}

// ImpliedAccessPolicy is one Vault policy whose migrated secrets.read grants add access the
// policy never granted (see Item.ImpliedAccess): Paths are its stanzas that do, Access the
// union of what they add.
type ImpliedAccessPolicy struct {
	Policy string
	Paths  []string
	Access []string
}

// ImpliedAccessPolicies lists, per Vault policy and sorted by name, the Create role items that
// carry ImpliedAccess: the plan report's machine-readable list of policies migrated with
// names/version-metadata access their Vault policy did not grant.
func ImpliedAccessPolicies(items []Item) []ImpliedAccessPolicy {
	byPolicy := map[string]*ImpliedAccessPolicy{}
	for _, it := range items {
		if it.Kind != KindRole || it.Outcome != Create || len(it.ImpliedAccess) == 0 {
			continue
		}
		name := it.SourcePolicy
		path := strings.TrimPrefix(it.SourceRef, "policy:"+name+" path:")
		if name == "" {
			name, path = it.SourceRef, ""
		}
		p := byPolicy[name]
		if p == nil {
			p = &ImpliedAccessPolicy{Policy: name}
			byPolicy[name] = p
		}
		if path != "" && !slices.Contains(p.Paths, path) {
			p.Paths = append(p.Paths, path)
		}
		for _, a := range it.ImpliedAccess {
			if !slices.Contains(p.Access, a) {
				p.Access = append(p.Access, a)
			}
		}
	}
	out := make([]ImpliedAccessPolicy, 0, len(byPolicy))
	for _, p := range byPolicy {
		sort.Strings(p.Paths)
		sort.Strings(p.Access) // "list-names" < "read-version-metadata"
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Policy < out[j].Policy })
	return out
}
