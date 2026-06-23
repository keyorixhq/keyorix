package trust

// Build-time-embedded trusted public keys (ADR-062). These are set via -ldflags at
// release time, each a comma-separated list of "keyID=base64publickey":
//
//	go build -ldflags "\
//	  -X github.com/keyorixhq/keyorix/internal/trust.updateKeysB64=upd-2026=<base64> \
//	  -X github.com/keyorixhq/keyorix/internal/trust.licenseKeysB64=lic-2026=<base64>"
//
// They default to empty, so a plain `go build` trusts no keys and every Verify fails
// closed. `keyorix trust keygen` prints the exact -ldflags snippet for a generated key.
// The Makefile wires these from the TRUST_UPDATE_KEYS / TRUST_LICENSE_KEYS variables.
var (
	updateKeysB64  string
	licenseKeysB64 string
)

// DefaultRegistry builds the registry from the embedded keys. It errors only if an
// embedded spec is malformed (a build/release misconfiguration), not if it is empty.
func DefaultRegistry() (*KeyRegistry, error) {
	r := NewRegistry()
	for purpose, spec := range map[Purpose]string{
		PurposeUpdate:  updateKeysB64,
		PurposeLicense: licenseKeysB64,
	} {
		parsed, err := parseKeySpec(spec)
		if err != nil {
			return nil, err
		}
		for keyID, pub := range parsed {
			if err := r.Add(purpose, keyID, pub); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}
