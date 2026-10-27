package encryption

import "strings"

// DEKEpochIsRotating reports whether a stored DEK epoch value is the fence of an
// in-flight rotation ("rotating:<old fingerprint>") rather than a settled DEK
// fingerprint. The crypto inventory uses it to decide whether the epoch row's
// timestamp dates the current DEK (RD-CBOM-TAILS-1).
func DEKEpochIsRotating(value string) bool {
	return strings.HasPrefix(value, dekEpochRotatingPrefix)
}
