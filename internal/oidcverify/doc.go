// Package oidcverify verifies federated JWTs for machine-identity federation
// (ADR-031): signature against the issuer's JWKS, iss/aud/azp/exp/iat and a
// per-issuer max token age. It is a pure leaf extracted from internal/core
// (ADR-109 Step 7, ADR-121 decision 3): no *KeyorixCore, no storage, and it
// must never import internal/core (ADR-121 R1, TestCoreFamilyNeverImportsCore).
// Package core keeps its names as aliases (internal/core/oidc_aliases.go).
//
// Its fuzz targets (FuzzOIDCVerifierVerify, FuzzOIDCVerifierClaims) live here
// so their coverage map is this package's, not core's.
package oidcverify
