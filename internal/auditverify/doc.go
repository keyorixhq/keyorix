// Package auditverify offline-verifies the audit tamper-evidence hash chain
// (ADR-029) directly against a database artifact — a SQLite file or a
// Postgres DSN — without trusting or needing a running Keyorix server.
//
// # Independence
//
// This package deliberately duplicates rather than imports the server's own
// audit-chain code (internal/storage/store, internal/core): a verifier that
// reuses the code that WROTE the chain proves nothing about a bug or backdoor
// in that code. Everything here — the DB access (plain database/sql, no
// GORM), the entry-hash derivation (both the current and the frozen
// pre-#1452 encodings), and the checkpoint/high-water/retention-anchor HMAC
// logic — is an independent reimplementation. A differential test elsewhere
// in this module (not imported by this package) proves the two
// implementations agree over shared fixtures; a dependency-guard test in
// this package proves no file here imports internal/core or
// internal/storage/store. See docs/design-b4-offline-audit-verify.md for the
// full design and trust model this package implements, in particular what a
// bare re-walk cannot prove (tail-truncation, genesis re-seed) and what a
// host admin who controls both the DB and the checkpoint signing key can
// still fabricate undetectably — this package's own Result type surfaces
// that "not proven" state explicitly rather than reporting a bare VALID.
package auditverify
