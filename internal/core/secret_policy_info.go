// secret_policy_info.go — a read-only view of the active secret-name and secret-value
// policies, so clients (the web create form, the CLI) can show the conventions and
// pre-validate input instead of surprising the user with a server-side rejection.
// Exposes only the non-sensitive rule flags — never the extra-denylist values.
package core

// SecretNamePolicyInfo is the client-facing view of the naming policy.
type SecretNamePolicyInfo struct {
	Enabled   bool   `json:"enabled"`
	Pattern   string `json:"pattern,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
}

// SecretValuePolicyInfo is the client-facing view of the value policy (flags only —
// the extra denylist is intentionally not exposed).
type SecretValuePolicyInfo struct {
	Enabled      bool `json:"enabled"`
	MinLength    int  `json:"min_length,omitempty"`
	RejectCommon bool `json:"reject_common"`
}

// SecretPolicyInfo bundles the active create-time policies for clients.
type SecretPolicyInfo struct {
	Name  SecretNamePolicyInfo  `json:"name"`
	Value SecretValuePolicyInfo `json:"value"`
}

// SecretPolicies returns the active secret-name and secret-value policies as a
// non-sensitive, client-facing view.
func (c *KeyorixCore) SecretPolicies() SecretPolicyInfo {
	return SecretPolicyInfo{
		Name: SecretNamePolicyInfo{
			Enabled:   c.secretNamePolicy.Enabled,
			Pattern:   c.secretNamePolicy.Pattern,
			MaxLength: c.secretNamePolicy.MaxLength,
		},
		Value: SecretValuePolicyInfo{
			Enabled:      c.secretValuePolicy.Enabled,
			MinLength:    c.secretValuePolicy.MinLength,
			RejectCommon: c.secretValuePolicy.RejectCommon,
		},
	}
}
