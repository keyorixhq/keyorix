package verifierflip_test

import "slices"

// Reviewed ACCEPT-EQUIVALENT classes (PREREG "Verdicts"), as path.Match
// patterns over "region|mutation kind". A class missing here fails
// TestVerifierBitFlip until someone reviews it and adds it with a reason.
var (
	// encoding/json matches member names case-insensitively, so flipping a
	// letter's case bit in a name changes nothing.
	jsonMemberNames = []string{"key:*|bitflip"}
	// Insignificant whitespace around a JSON document.
	jsonTrailingNewline = []string{"|extend+0x0a"}
	jsonWhitespace      = []string{"|extend+0x20", "|prepend+space"}
	// Metadata outside the GCM tag by design, and block moves that stay inside
	// it (see aead-envelope-metadata-informational).
	aeadUnsignedMetadata = []string{
		"aad_version|bitflip", "aad_version|del", "key:aad_version|del",
		"encrypted_at|bitflip", "encrypted_at|del", "key:encrypted_at|del",
		"key_version|bitflip", "key_version|del", "key:key_version|del",
		"|dup8", "|swap8",
	}
	// anchor_token/anchor_provider are outside the checkpoint signature by
	// design (see the -unsigned-fields-informational sibling target).
	anchorUnsignedFields = []string{
		"anchor_token|bitflip", "key:anchor_token|del",
		"anchor_provider|bitflip", "anchor_provider|del", "key:anchor_provider|del",
		"|dup8", "|swap8",
	}
)

var reviewedEquivalents = map[string][]string{
	// |dup8 lands in unknown or repeated JSON members; every signed field
	// still decodes to the original value.
	"backup-manifest-hmac":         slices.Concat(jsonMemberNames, jsonTrailingNewline, jsonWhitespace, []string{"|dup8"}),
	"audit-external-anchor-bundle": slices.Concat(jsonMemberNames, jsonTrailingNewline, jsonWhitespace, anchorUnsignedFields),
	"aead-envelope-plaintext":      slices.Concat(jsonMemberNames, jsonTrailingNewline, jsonWhitespace, aeadUnsignedMetadata),
	// A trailing newline is rejected here because it starts an empty chunk.
	// DecryptChunked documents that chunks may arrive out of order; the
	// fieldswap keeps every chunk and only changes arrival order.
	"aead-chunked-stream": slices.Concat(jsonMemberNames, jsonWhitespace, aeadUnsignedMetadata, []string{`|fieldswap\[0\]`}),
	// Unused trailing bits of the last base64url character of the payload.
	"audit-seal-records":    {"line1/payload|bitflip"},
	"audit-key-transitions": {"line1/payload|bitflip"},
	// Normalize folds case and separators and trims surrounding whitespace.
	"recoverykey-entered-key": {"|bitflip", "|del", "|extend+0x0a", "|extend+0x20", "|prepend+space"},
	// The MAC is compared after hex decoding, so hex case is free.
	"evidence-pack-signature": {"mac|bitflip"},
	// Unused trailing base64url bits; the token is trimmed before parsing.
	"license-ed25519-token": {"payload|bitflip", "signature|bitflip", "|extend+0x0a", "|extend+0x20", "|prepend+space"},
	// Unused trailing base64url bits; encoding/base64 skips newlines.
	"oidc-jwt-rs256": {"signature|bitflip", "|extend+0x0a"},
	// Gzip framing the verifier never reaches or that is not content: reserved
	// flag bits, MTIME, XFL, OS, and everything after the tar end-of-archive
	// (final deflate bytes, CRC, length, trailing data). The signed manifest
	// pins every component by sha256, and Canon includes manifest and signature.
	"update-bundle-ed25519-manifest": {"gzip-header|bitflip", "deflate|*", "gzip-trailer|*", "|dup8", "|truncate", "|extend+*"},
}
