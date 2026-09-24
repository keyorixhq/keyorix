package auditverify

// Version identifies this package's verification algorithm/encoding
// awareness, surfaced on every Result so a compliance evidence pack records
// which verifier produced it. Bump when the algorithm this package
// implements changes (a new hash encoding, a new anchor format) — not on
// every unrelated code change.
const Version = "auditverify/v1"
