// Package libconformance holds fuzz targets that pin the behaviour keyorix
// relies on in third-party parsing and crypto libraries (etree, crewjam/saml's
// xmlenc, digitorus/pkcs7, golang-jwt). The targets call only the libraries,
// never keyorix code, so they live here instead of in internal/core: a fuzz
// binary's coverage map covers every package it links, and core links every
// connector SDK (~480 KB of map versus a few tens of KB here), which made each
// input several times more expensive and stalled minimization (Keyorix project
// doc claude/2026-09-23-coverage-map-leaf-package-ab-results.md).
//
// The package has no non-test code; this file only carries the documentation.
package libconformance
