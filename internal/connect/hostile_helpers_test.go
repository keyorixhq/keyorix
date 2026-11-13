package connect

import "encoding/json"

// normUTF8 applies encoding/json's treatment of invalid UTF-8 in a string (each
// bad byte becomes U+FFFD) so a decoder that passes raw bytes through is
// compared on content, not on that known difference. Shared by the AWS and
// Azure hostile fuzz targets, so it carries no build tag.
func normUTF8(s string) string {
	b, _ := json.Marshal(s)
	var out string
	_ = json.Unmarshal(b, &out)
	return out
}
