package faultops

import "strings"

// opVariantSep separates a live route key from a variant name in an opCatalog key:
// "REST POST /auth/setup/consume#invitation_accept" is a second op on the live route
// "REST POST /auth/setup/consume", for a route whose request selects one of several
// distinct write paths (here the setup token's purpose). Catalog keys stay unique (the
// fuzzer, the tolerance tables and the oracles key on them); only the check against
// the live inventory uses the route part (TestOperationCatalogKeysAreRegistered). A
// variant needs its own StatusFuzzed override row; it is not counted in the
// inventory coverage report, which counts live routes.
const opVariantSep = "#"

// opRouteKey is key without its variant suffix: the live inventory key it drives.
func opRouteKey(key string) string {
	route, _, _ := strings.Cut(key, opVariantSep)
	return route
}
