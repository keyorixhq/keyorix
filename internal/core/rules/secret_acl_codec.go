package rules

import "encoding/json"

// DecodeSecretACLPerms parses a stored permissions column back into a slice.
// An empty or invalid column yields nil.
func DecodeSecretACLPerms(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
