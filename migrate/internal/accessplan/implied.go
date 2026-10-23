package accessplan

// ImpliedAccessPolicy is one Vault policy whose migrated secrets.read grants add access the
// policy never granted (see Item.ImpliedAccess).
type ImpliedAccessPolicy struct {
	Policy string
	Paths  []string
	Access []string
}

// ImpliedAccessPolicies lists, per Vault policy, the Create role items carrying ImpliedAccess.
func ImpliedAccessPolicies(items []Item) []ImpliedAccessPolicy {
	return nil
}
